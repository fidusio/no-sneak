package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.analysis.CipherProbeCallback;
import io.xlogistx.nosneak.v2.analysis.RevocationChecker;
import io.xlogistx.nosneak.v2.analysis.VersionProbeCallback;
import io.xlogistx.nosneak.v2.model.PatternRule;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.tls.PQCConnectionHelper.PQCHandshakeState;
import org.bouncycastle.tls.ProtocolVersion;
import io.xlogistx.nosneak.v2.tls.PQCHandshakeStateMachine;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import io.xlogistx.nosneak.v2.tls.PQCTlsClient;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.SharedBase64;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.regex.Matcher;

/**
 * Execution context for one probe run — the {@code StateMachine} config the
 * {@link ProbeEngine} drives. It owns the live NIO connection(s), the
 * {@link ProbeResult} builder, and the plaintext {@code expect} matcher, and it
 * bridges NIO events into engine transitions.
 * <p>
 * <b>Fully non-blocking.</b> Connections are opened on the shared {@link NIOSocket};
 * every asynchronous wait (connect / expect / overall) is bounded by a task on
 * the scheduler taken from that socket. All transitions run on the selector or
 * scheduler thread and are serialised through {@link #fire(String)} /
 * {@link #deliver(boolean, String)} (both synchronized). Each wait is guarded by a
 * single {@code armed} token plus an {@code armGen} epoch so an inbound event and
 * its timeout can never both resolve the same window. Terminal delivery is exactly-once.
 */
public class ProbeContext {

    public static final LogWrapper log = new LogWrapper(ProbeContext.class).setEnabled(false);

    /** How inbound bytes on the current channel are interpreted. */
    enum Mode { CONNECTING, EXPECT, TLS, IDLE, SECURE_CONNECTING, UDP }

    private final NIOSocket nioSocket;
    private final IPAddress target;
    private final ProbeDefinition definition;
    private final int timeoutSec;
    private final Consumer<ProbeResult> userCallback;
    /** Arms every wait guard; taken from the {@link NIOSocket} this probe rides on. */
    private final ScheduledExecutorService scheduler;
    /** Parallel dispatch for fan-out children; taken from the same {@link NIOSocket}. */
    private final Executor executor;

    private final ProbeEngine engine;
    private final ProbeResult.Builder result;
    private final long startTime = System.currentTimeMillis();

    // Terminal + per-wait guards
    private final AtomicBoolean terminated = new AtomicBoolean(false);
    private final AtomicBoolean armed = new AtomicBoolean(false);
    private final AtomicLong armGen = new AtomicLong();
    private volatile ScheduledFuture<?> waitTimeout;
    private volatile ScheduledFuture<?> overallDeadline;

    // Live connection state
    private volatile ProbeTCPCallback currentCallback;
    // SelectionKey of the current connection, captured so teardown can abort a still-connecting
    // socket (cancel its NIOSocket connect-timeout appointment) instead of letting it linger.
    private volatile SelectionKey currentKey;
    // Secure (JSSE) connection state — set only by openSecureConnection (tls-connect).
    // The raw/BC path never sees secure==true, so it stays unchanged.
    private volatile ProbeSecureCallback currentSecureCallback;
    private volatile boolean secure = false;
    // UDP datagram session state (set only by openUDPConnection for a udp-transport probe).
    private volatile ProbeUDPCallback currentUDPCallback;
    private volatile boolean udp = false;
    private volatile Mode mode = Mode.IDLE;
    private int connectionIndex = 0;
    private int currentPort;
    private boolean receivedData = false;

    // expect() accumulation + active patterns
    private final ByteArrayOutputStream accumulator = new ByteArrayOutputStream();
    private volatile List<PatternRule> expectPatterns;

    // Inner BC TLS/PQC handshake (trigger-StateMachine, no MonoStateMachine).
    private volatile PQCSessionConfig pqcConfig;
    private volatile PQCHandshakeStateMachine pqcSM;
    private volatile boolean tlsUpgrade = false; // true => reached TLS via STARTTLS (Phase 4)

    public ProbeContext(NIOSocket nioSocket, IPAddress target, ProbeDefinition definition,
                        int timeoutSec, Consumer<ProbeResult> userCallback) {
        this.nioSocket = nioSocket;
        // Every wait this probe arms runs on the pools the NIOSocket was constructed with, rather
        // than the process-wide defaults, so an embedder that supplied its own executor and
        // scheduler gets the whole probe — connect, expect, handshake and overall deadlines — on
        // them. Taking them from the socket also makes it impossible to arm a timeout on one pool
        // while the I/O it guards runs on another.
        this.scheduler = nioSocket.getScheduler();
        this.executor = nioSocket.getExecutor();
        this.target = target;
        this.definition = definition;
        this.timeoutSec = timeoutSec > 0 ? timeoutSec : 5;
        this.userCallback = userCallback;
        this.engine = new ProbeEngine(definition, this);
        this.result = ProbeResult.builder(target.getInetAddress(), target.getPort(), definition.getTransport())
                .probeName(definition.getName())
                .service(definition.getService())
                .observedAtMs(startTime);
    }

    // ==================== Lifecycle ====================

    /** Arm the overall watchdog and enter the start state. */
    public void start() {
        int overall = Math.max(timeoutSec * 4, 30);
        overallDeadline = scheduler
                .schedule(() -> deliver(false, "overall-timeout"), overall, TimeUnit.SECONDS);
        engine.start();
    }

    public boolean isTerminated() {
        return terminated.get();
    }

    /** Advance the engine. Serialised; ignored once terminated. */
    public synchronized void fire(String outcome) {
        engine.fire(outcome);
    }

    /** Deliver the {@link ProbeResult} exactly once and tear the context down. */
    public synchronized void deliver(boolean complete, String terminalNote) {
        if (!terminated.compareAndSet(false, true)) {
            return;
        }
        cancelWaitTimeout();
        cancelOverall();
        result.addConnection(connectionIndex, currentPort, terminalNote);
        result.complete(complete);
        result.note(terminalNote);
        result.durationMs(System.currentTimeMillis() - startTime);
        closeCurrent();
        engine.close();
        ProbeResult r = result.build();
        if (log.isEnabled()) log.getLogger().info("deliver " + r);
        try {
            userCallback.accept(r);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("userCallback error: " + e.getMessage());
        }
    }

    /**
     * Tear this context down WITHOUT delivering a result — used to supersede a losing/redundant
     * candidate in a parallel sweep once a higher-priority probe has already won. Idempotent; a
     * context that has already delivered (or been cancelled) is left untouched, so the winner's
     * result is never clobbered.
     */
    public synchronized void cancel() {
        if (!terminated.compareAndSet(false, true)) {
            return;
        }
        cancelWaitTimeout();
        cancelOverall();
        closeCurrent();
        engine.close();
    }

    // ==================== Async wait guard ====================

    /** Arm a single-shot wait: the first of (event, timeout) wins. */
    private void arm() {
        long gen = armGen.incrementAndGet();
        armed.set(true);
        cancelWaitTimeout();
        waitTimeout = scheduler
                .schedule(() -> fireArmedGen("timeout", gen), timeoutSec, TimeUnit.SECONDS);
    }

    /** Fire {@code outcome} for the current wait window (used by NIO events). */
    private void fireArmed(String outcome) {
        fireArmedGen(outcome, armGen.get());
    }

    private void fireArmedGen(String outcome, long gen) {
        if (gen == armGen.get() && armed.compareAndSet(true, false)) {
            cancelWaitTimeout();
            fire(outcome);
        }
    }

    private void cancelWaitTimeout() {
        ScheduledFuture<?> a = waitTimeout;
        if (a != null) {
            waitTimeout = null;
            try { a.cancel(false); } catch (Exception ignored) { }
        }
    }

    private void cancelOverall() {
        ScheduledFuture<?> a = overallDeadline;
        if (a != null) {
            overallDeadline = null;
            try { a.cancel(false); } catch (Exception ignored) { }
        }
    }

    // ==================== Action primitives ====================

    /** connect (and reconnect): open a fresh channel to {@code port} (UDP if the probe is udp). */
    public void openConnection(int port) {
        if ("udp".equalsIgnoreCase(definition.getTransport())) {
            openUDPConnection(port);
            return;
        }
        connectionIndex++;
        currentPort = port;
        mode = Mode.CONNECTING;
        secure = false;
        currentSecureCallback = null;
        udp = false;
        currentUDPCallback = null;
        receivedData = false;
        accumulator.reset();
        pqcConfig = null;
        pqcSM = null;
        arm();
        ProbeTCPCallback cb = new ProbeTCPCallback(this, new IPAddress(target.getInetAddress(), port), connectionIndex);
        currentCallback = cb;
        try {
            currentKey = nioSocket.addClientSocket(cb, timeoutSec);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("connect error: " + e.getMessage());
            fireArmed("error");
        }
    }

    /**
     * tls-connect: open a fresh channel to {@code port} and perform a JSSE TLS handshake
     * (RSA-capable, trust-all) via {@link ProbeSecureCallback}. On success the context is in
     * secure mode, so the ordinary {@code send}/{@code expect} exchange application data
     * <em>through</em> TLS. Fires {@code connected} only after the handshake completes; the
     * single {@link #arm()} window spans TCP-connect + handshake because
     * {@code connectedFinished} is deferred until after the handshake.
     */
    public void openSecureConnection(int port) {
        connectionIndex++;
        currentPort = port;
        mode = Mode.SECURE_CONNECTING;
        secure = true;
        udp = false;
        currentUDPCallback = null;
        receivedData = false;
        accumulator.reset();
        pqcConfig = null;
        pqcSM = null;
        arm();
        try {
            ProbeSecureCallback cb = new ProbeSecureCallback(
                    this, new IPAddress(target.getInetAddress(), port), connectionIndex, false);
            currentSecureCallback = cb;
            currentCallback = null; // raw ingress identity checks now reject stray events
            currentKey = nioSocket.addClientSocket(cb, timeoutSec);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("secure connect error: " + e);
            fireArmed("error");
        }
    }

    /**
     * connect over UDP: bind an ephemeral datagram socket and fire {@code connected}
     * immediately (UDP is connectionless — there is no handshake). The following
     * {@code send} emits a datagram to the target and {@code expect} matches the response.
     */
    public void openUDPConnection(int port) {
        connectionIndex++;
        currentPort = port;
        mode = Mode.UDP;
        udp = true;
        secure = false;
        currentSecureCallback = null;
        currentCallback = null;
        pqcConfig = null;
        pqcSM = null;
        receivedData = false;
        accumulator.reset();
        arm();
        try {
            ProbeUDPCallback cb = new ProbeUDPCallback(executor, this, port, connectionIndex);
            currentUDPCallback = cb;
            currentKey = nioSocket.addDatagramSocket(new InetSocketAddress(0), cb); // ephemeral local bind
            fireArmed("connected"); // ready immediately
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("udp connect error: " + e);
            fireArmed("error");
        }
    }

    /** reconnect: record the closing connection, then open a new one. */
    public void reconnect(int port) {
        result.addConnection(connectionIndex, currentPort, "reconnect");
        closeCurrent();
        openConnection(port);
    }

    public int effectivePort(Integer statePort) {
        return statePort != null ? statePort : target.getPort();
    }

    /**
     * send: resolve a state's payload to bytes and write them to the current channel.
     * Prefers the codec-prefixed {@code data} field ({@code hex:}/{@code base64:}/{@code text:},
     * or plain text if unprefixed); falls back to the templated {@code payload}.
     */
    public boolean send(ProbeState state) {
        byte[] bytes;
        try {
            bytes = resolveSendBytes(state);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("send decode error: " + e.getMessage());
            return false;
        }
        return writeBytes(bytes);
    }

    /** send (text): write templated plaintext bytes (used for protocol commands). */
    public boolean write(String payload) {
        return writeBytes(expandTemplate(payload).getBytes(StandardCharsets.UTF_8));
    }

    private byte[] resolveSendBytes(ProbeState state) {
        String data = state.getData();
        if (data != null) {
            if (data.startsWith("hex:")) {
                return SharedStringUtil.hexToBytes(data.substring(4));
            }
            if (data.startsWith("base64:")) {
                return SharedBase64.decode(data.substring(7));
            }
            if (data.startsWith("text:")) {
                return expandTemplate(data.substring(5)).getBytes(StandardCharsets.UTF_8);
            }
            return expandTemplate(data).getBytes(StandardCharsets.UTF_8); // default: text
        }
        return expandTemplate(state.getPayload()).getBytes(StandardCharsets.UTF_8);
    }

    private boolean writeBytes(byte[] data) {
        if (udp) {
            // Send a datagram to the target (host:currentPort).
            ProbeUDPCallback cb = currentUDPCallback;
            if (cb == null || data == null) {
                return false;
            }
            try {
                cb.send(ByteBuffer.wrap(data),
                        new InetSocketAddress(target.getInetAddress(), currentPort), false);
                return true;
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("udp send error: " + e.getMessage());
                return false;
            }
        }
        if (secure) {
            // Encrypt-and-send through the established TLS session.
            ProbeSecureCallback cb = currentSecureCallback;
            return cb != null && cb.writeApp(data);
        }
        ProbeTCPCallback cb = currentCallback;
        if (cb == null || cb.getChannel() == null || data == null) {
            return false;
        }
        try {
            ByteBufferUtil.write(cb.getChannel(), ByteBuffer.wrap(data), false);
            return true;
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("write error: " + e.getMessage());
            return false;
        }
    }

    /** expect: enter plaintext match mode against {@code patterns}. */
    public void beginExpect(List<PatternRule> patterns) {
        this.expectPatterns = patterns;
        this.mode = Mode.EXPECT;
        arm();
        matchExpect(); // a banner may already be buffered from just after connect
    }

    /** record: merge a note into the result. */
    public void recordNote(String note) {
        result.note(note);
    }

    // ==================== TLS / PQC handshake ====================

    /**
     * tls-handshake: start a Bouncy Castle handshake on the CURRENT already-open channel
     * (a mid-session upgrade if {@code upgrade}). When {@code classicalOnly} is true the
     * ClientHello advertises only classical groups; otherwise PQC hybrids are offered.
     * Driven by the trigger-{@link PQCHandshakeStateMachine} (no MonoStateMachine).
     */
    public void startTlsHandshake(boolean upgrade, boolean classicalOnly) {
        this.tlsUpgrade = upgrade;
        this.mode = Mode.TLS;
        arm();
        try {
            // SNI carries the target HOSTNAME (unresolved → no blocking DNS on the selector thread;
            // the channel is already connected).
            InetSocketAddress sni = InetSocketAddress.createUnresolved(hostname(), currentPort);
            pqcConfig = new PQCSessionConfig(sni, classicalOnly);
            pqcConfig.channel = currentCallback.getChannel();
            pqcSM = new PQCHandshakeStateMachine(pqcConfig);
            pqcSM.publish(PQCHandshakeState.START, this::onTlsTransition);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("tls start error: " + e.getMessage());
            fireArmed("error");
        }
    }

    private void onTlsTransition(PQCSessionConfig cfg) {
        if (cfg != null && cfg.handshakeComplete.get()) {
            fireArmed("handshaked");
        }
    }

    /** Flag set by the starttls action so the following tls-handshake records an upgrade. */
    public void markStartTls() {
        this.tlsUpgrade = true;
    }

    public boolean isUpgrade() {
        return tlsUpgrade;
    }

    /** pqc-check: record TLS facts AND classify the negotiated key exchange. */
    public void recordPQC() {
        recordTls(true);
    }

    /** tls-facts: record TLS facts WITHOUT any PQC classification. */
    public void recordTlsFacts() {
        recordTls(false);
    }

    private void recordTls(boolean classifyPqc) {
        PQCSessionConfig cfg = pqcConfig;
        if (cfg == null || cfg.tlsClient == null) {
            if (classifyPqc) {
                result.pqcStatus(ProbeResult.PqcStatus.UNKNOWN);
            }
            return;
        }
        PQCTlsClient client = cfg.tlsClient;
        result.tlsState(tlsUpgrade ? ProbeResult.TlsState.STARTTLS_UPGRADED
                : ProbeResult.TlsState.DIRECT_TLS);
        result.tlsVersion(client.getNegotiatedVersionString());
        result.cipherSuite(client.getNegotiatedCipherSuiteName());

        String kex = client.getNegotiatedKeyExchangeName();
        if (kex == null || "UNKNOWN".equals(kex)) {
            kex = client.getKeyExchangeAlgorithm();
        }
        result.keyExchangeGroup(kex);
        result.keyExchangeAlgorithm(kex);

        if (classifyPqc) {
            String cls = OPSecUtil.singleton().classifyKeyExchange(kex);
            if ("PQC_HYBRID".equals(cls)) {
                result.pqcStatus(ProbeResult.PqcStatus.PQC);
            } else if (cls == null || "UNKNOWN".equals(cls)) {
                result.pqcStatus(ProbeResult.PqcStatus.UNKNOWN);
            } else {
                result.pqcStatus(ProbeResult.PqcStatus.CLASSICAL);
            }
        }

        recordCertFacts(client);
    }

    private void recordCertFacts(PQCTlsClient client) {
        try {
            Certificate serverCert = client.getServerCertificate();
            if (serverCert != null && serverCert.getLength() > 0) {
                TlsCertificate[] list = serverCert.getCertificateList();
                if (list.length > 0) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate leaf = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(list[0].getEncoded()));
                    result.certSubject(leaf.getSubjectX500Principal().getName());
                    result.certIssuer(leaf.getIssuerX500Principal().getName());
                    // Validity window + explicit expired / not-yet-valid check (independent of the
                    // PKIX chain result, which also rejects expired certs but does not surface dates).
                    result.certNotBefore(leaf.getNotBefore().toInstant().toString());
                    result.certNotAfter(leaf.getNotAfter().toInstant().toString());
                    String validity;
                    try {
                        leaf.checkValidity();
                        validity = "VALID";
                    } catch (java.security.cert.CertificateExpiredException ex) {
                        validity = "EXPIRED";
                    } catch (java.security.cert.CertificateNotYetValidException ex) {
                        validity = "NOT_YET_VALID";
                    }
                    result.certValidity(validity);
                    recordLeafKeyFacts(leaf);
                    recordHostnameMatch(leaf);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("cert facts skipped: " + e.getMessage());
        }
    }

    /** Leaf signature/public-key classification, including PQC (ML-DSA) signature detection. */
    private void recordLeafKeyFacts(X509Certificate leaf) {
        try {
            // [signatureType, signatureAlgorithm, publicKeyType, publicKeySize]
            String[] a = OPSecUtil.singleton().analyzeCertificatePQC(leaf);
            if (a != null && a.length >= 4) {
                int keySize;
                try {
                    keySize = Integer.parseInt(a[3]);
                } catch (Exception e) {
                    keySize = 0;
                }
                result.certKeyAnalysis(a[0], a[1], a[2], keySize, "PQC_SIGNATURE".equals(a[0]));
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("cert key analysis skipped: " + e.getMessage());
        }
    }

    /**
     * RFC 6125 hostname match of the leaf against the scanned host. <b>Report-only</b> by
     * design: a mismatch is recorded and surfaced as a recommendation, but never on its own
     * downgrades the trust verdict (the grading layer treats it as advisory).
     */
    private void recordHostnameMatch(X509Certificate leaf) {
        try {
            OPSecUtil.HostnameResult hn = OPSecUtil.singleton().matchesHostname(leaf, hostname());
            if (hn != null) {
                String detail = hn.getMessage();
                if (!hn.isMatched() && hn.getPresentedNames() != null && !hn.getPresentedNames().isEmpty()) {
                    detail = (detail != null ? detail + " " : "") + "presented=" + hn.getPresentedNames();
                }
                result.certHostname(hn.isMatched(), detail);
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("hostname check skipped: " + e.getMessage());
        }
    }

    // ==================== Deep analysis (scanner-grade) ====================

    /**
     * cert-chain-validate: run PKIX chain-to-root validation on the handshake certificate
     * (via {@code opsec}'s {@code OPSecUtil.validateChain}) and record the trust verdict.
     * Requires a prior {@code tls-handshake}. Synchronous → the action fires {@code done}.
     */
    public void validateCertChain() {
        PQCSessionConfig cfg = pqcConfig;
        if (cfg == null || cfg.tlsClient == null) {
            return;
        }
        try {
            Certificate serverCert = cfg.tlsClient.getServerCertificate();
            if (serverCert == null || serverCert.getLength() == 0) {
                return;
            }
            TlsCertificate[] list = serverCert.getCertificateList();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate[] chain = new X509Certificate[list.length];
            for (int i = 0; i < list.length; i++) {
                chain[i] = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(list[i].getEncoded()));
            }
            OPSecUtil.ChainTrustResult ctr = OPSecUtil.singleton().validateChain(chain);
            if (ctr != null && ctr.getTrust() != null) {
                result.certChainTrust(ctr.getTrust().name(), ctr.getMessage());
            }
            recordChainBreakdown(chain, ctr);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("cert-chain validate skipped: " + e.getMessage());
        }
    }

    /**
     * Record the per-certificate breakdown and the chain-wide time validity.
     * <p>
     * Servers do not send the Root CA (the client is expected to have it), so on a
     * {@code TRUSTED} result the PKIX-matched trust anchor from the local store is appended as
     * the final {@code role:"root"} entry — skipped when the server already terminated the
     * chain with a self-signed root.
     */
    private void recordChainBreakdown(X509Certificate[] chain, OPSecUtil.ChainTrustResult ctr) {
        X509Certificate[] display = chain;
        X509Certificate anchor = ctr != null ? ctr.getTrustAnchor() : null;
        if (anchor != null && chain.length > 0) {
            X509Certificate last = chain[chain.length - 1];
            boolean selfSignedLast = last.getSubjectX500Principal().equals(last.getIssuerX500Principal());
            if (!selfSignedLast) {
                display = java.util.Arrays.copyOf(chain, chain.length + 1);
                display[chain.length] = anchor;
            }
        }
        long now = System.currentTimeMillis();
        boolean chainTimeValid = true;
        result.clearCertChain();
        for (int i = 0; i < display.length; i++) {
            X509Certificate c = display[i];
            long nb = c.getNotBefore().getTime();
            long na = c.getNotAfter().getTime();
            boolean timeValid = now >= nb && now <= na;
            if (!timeValid) {
                chainTimeValid = false;
            }
            boolean selfSigned = c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
            result.addCert(new ProbeResult.CertInfo(
                    i,
                    c.getSubjectX500Principal().getName(),
                    c.getIssuerX500Principal().getName(),
                    c.getNotBefore().toInstant().toString(),
                    c.getNotAfter().toInstant().toString(),
                    timeValid,
                    timeValid ? "VALID" : (now < nb ? "NOT_YET_VALID" : "EXPIRED"),
                    selfSigned,
                    c.getBasicConstraints() != -1,
                    i == 0 ? "leaf" : (selfSigned ? "root" : "intermediate")));
        }
        result.certChainTimeValid(chainTimeValid);
    }

    /**
     * enumerate-versions: probe each candidate TLS version <b>in parallel</b> (one
     * independent connection each) via the {@link Fanout} primitive, then record the
     * server-accepted set and fire {@code done}. Each child guarantees a terminal result
     * (success/failure/own timeout), so the join always resolves.
     */
    public void enumerateVersions() {
        final int port = currentPort > 0 ? currentPort : target.getPort();
        final ProtocolVersion[] candidates = {
                ProtocolVersion.TLSv13, ProtocolVersion.TLSv12,
                ProtocolVersion.TLSv11, ProtocolVersion.TLSv10,
                ProtocolVersion.SSLv3 // probe legacy SSLv3 too so an insecure server is flagged
        };
        final Map<String, Boolean> results = new ConcurrentHashMap<>();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (ProtocolVersion candidate : candidates) {
            final ProtocolVersion ver = candidate;
            children.add(join -> {
                try {
                    VersionProbeCallback probe = new VersionProbeCallback(
                            scheduler, new IPAddress(target.getInetAddress(), port), hostname(), ver,
                            (name, supported) -> {
                                results.put(name, supported);
                                join.childDone();
                            });
                    probe.timeoutInSec(Math.max(timeoutSec, 5));
                    nioSocket.addClientSocket(probe); // uses probe.timeoutInSec()
                } catch (Exception e) {
                    join.childDone();
                }
            });
        }
        Fanout.run(children, () -> onVersionsDone(results), executor);
    }

    private synchronized void onVersionsDone(Map<String, Boolean> results) {
        // Record best-first for a stable, readable order (weakest last).
        for (String name : new String[]{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"}) {
            if (Boolean.TRUE.equals(results.get(name))) {
                result.addProtocolVersion(name);
            }
        }
        fire("done");
    }

    private static final int[] TLS13_CIPHERS = {
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256
    };
    private static final int[] TLS12_CIPHERS = {
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    };

    /**
     * enumerate-ciphers: probe each candidate cipher suite <b>in parallel</b> (one connection
     * offering a single cipher at its version) via {@link Fanout}, then record the accepted set
     * and fire {@code done}.
     */
    public void enumerateCiphers() {
        final int port = currentPort > 0 ? currentPort : target.getPort();
        final Map<Integer, Boolean> accepted = new ConcurrentHashMap<>();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        cipherChildren(children, accepted, ProtocolVersion.TLSv13, TLS13_CIPHERS, port);
        cipherChildren(children, accepted, ProtocolVersion.TLSv12, TLS12_CIPHERS, port);
        final int[] ordered = new int[TLS13_CIPHERS.length + TLS12_CIPHERS.length];
        System.arraycopy(TLS13_CIPHERS, 0, ordered, 0, TLS13_CIPHERS.length);
        System.arraycopy(TLS12_CIPHERS, 0, ordered, TLS13_CIPHERS.length, TLS12_CIPHERS.length);
        Fanout.run(children, () -> onCiphersDone(accepted, ordered), executor);
    }

    private void cipherChildren(List<Consumer<ParallelJoin>> children, Map<Integer, Boolean> accepted,
                                ProtocolVersion ver, int[] ciphers, int port) {
        for (int c : ciphers) {
            final int cipher = c;
            children.add(join -> {
                try {
                    CipherProbeCallback probe = new CipherProbeCallback(
                            scheduler, new IPAddress(target.getInetAddress(), port), hostname(), ver,
                            new int[]{cipher},
                            (v, cipherId) -> {
                                if (cipherId != null && cipherId != 0) {
                                    accepted.put(cipherId, Boolean.TRUE);
                                }
                                join.childDone();
                            });
                    probe.timeoutInSec(Math.max(timeoutSec, 5));
                    nioSocket.addClientSocket(probe);
                } catch (Exception e) {
                    join.childDone();
                }
            });
        }
    }

    private synchronized void onCiphersDone(Map<Integer, Boolean> accepted, int[] ordered) {
        for (int c : ordered) {
            if (Boolean.TRUE.equals(accepted.get(c))) {
                result.addCipherSuite(PQCTlsClient.getCipherSuiteName(c));
            }
        }
        fire("done");
    }

    /**
     * revocation-check: report the certificate's revocation status from the handshake-stapled
     * OCSP response (RFC 6066) — instant, no network. When nothing was stapled the status is
     * UNKNOWN/NOT_CHECKED. Requires a prior {@code tls-handshake}. Synchronous → fires {@code done}.
     */
    public void checkRevocation() {
        PQCSessionConfig cfg = pqcConfig;
        if (cfg == null || cfg.tlsClient == null) {
            return;
        }
        try {
            RevocationResult r = RevocationChecker.fromStaple(cfg.tlsClient.getStapledOCSPResponse());
            if (r != null && r.getStatus() != null) {
                result.revocation(r.getStatus().name(), r.getMethod());
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("revocation check skipped: " + e.getMessage());
        }
    }

    // ==================== NIO event ingress (from ProbeTCPCallback) ====================

    synchronized void onConnected(ProbeTCPCallback cb) {
        if (cb != currentCallback) return;
        fireArmed("connected");
    }

    synchronized void onInbound(ProbeTCPCallback cb, byte[] bytes) {
        if (cb != currentCallback || bytes == null || bytes.length == 0) return;
        receivedData = true;
        if (mode == Mode.TLS) {
            PQCHandshakeStateMachine sm = pqcSM;
            if (sm != null) {
                sm.processIncomingData(ByteBuffer.wrap(bytes), this::onTlsTransition);
                // A failed handshake closes the config without invoking the callback, so a
                // stalled handshake would otherwise resolve only via the wait timeout.
                PQCSessionConfig cfg = pqcConfig;
                if (cfg != null && cfg.isClosed() && !cfg.handshakeComplete.get()) {
                    fireArmed("error");
                }
            }
            return;
        }
        accumulator.write(bytes, 0, bytes.length);
        if (mode == Mode.EXPECT) {
            matchExpect();
        }
    }

    synchronized void onException(ProbeTCPCallback cb, Throwable t) {
        if (cb != currentCallback) return;
        if (log.isEnabled()) log.getLogger().info("connection exception: " + t);
        switch (mode) {
            case EXPECT:
                fireArmed(receivedData ? "nomatch" : "error");
                break;
            default:
                fireArmed("error");
        }
    }

    // ==================== Secure (JSSE) NIO ingress (from ProbeSecureCallback) ====================

    /** TLS handshake completed on the secure channel. */
    synchronized void onSecureConnected(ProbeSecureCallback cb) {
        if (cb != currentSecureCallback) return;
        recordSecureTlsFacts(cb);
        fireArmed("connected");
    }

    /**
     * Record TLS facts negotiated over the JSSE (RSA-capable) secure channel used by
     * {@code tls-connect}. Unlike the Bouncy-Castle path this does not classify PQC
     * (JSSE does not surface the key-exchange group), but it must still mark the result
     * as an established TLS session so an HTTPS identification is not reported with
     * {@code tls-state=NONE}.
     */
    private void recordSecureTlsFacts(ProbeSecureCallback cb) {
        result.tlsState(tlsUpgrade ? ProbeResult.TlsState.STARTTLS_UPGRADED
                : ProbeResult.TlsState.DIRECT_TLS);
        try {
            javax.net.ssl.SSLSession session =
                    (cb.getConfig() != null) ? cb.getConfig().getSSLSession() : null;
            if (session != null) {
                String proto = session.getProtocol();
                String cipher = session.getCipherSuite();
                if (proto != null && !proto.isEmpty()) result.tlsVersion(proto);
                if (cipher != null && !cipher.isEmpty()) result.cipherSuite(cipher);
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("secure tls-facts unavailable: " + e);
        }
    }

    /** Decrypted application data — same accumulate + match path as plaintext. */
    synchronized void onSecureInbound(ProbeSecureCallback cb, byte[] bytes) {
        if (cb != currentSecureCallback || bytes == null || bytes.length == 0) return;
        receivedData = true;
        accumulator.write(bytes, 0, bytes.length);
        if (mode == Mode.EXPECT) {
            matchExpect();
        }
    }

    synchronized void onSecureException(ProbeSecureCallback cb, Throwable t) {
        if (cb != currentSecureCallback) return;
        if (log.isEnabled()) log.getLogger().info("secure connection exception: " + t);
        switch (mode) {
            case EXPECT:
                fireArmed(receivedData ? "nomatch" : "error");
                break;
            default:
                fireArmed("error");
        }
    }

    // ==================== UDP ingress (from ProbeUDPCallback) ====================

    /** A response datagram — accumulate and run the {@code expect} matcher. */
    synchronized void onUDPInbound(ProbeUDPCallback cb, byte[] bytes) {
        if (cb != currentUDPCallback || bytes == null || bytes.length == 0) return;
        receivedData = true;
        accumulator.write(bytes, 0, bytes.length);
        if (mode == Mode.EXPECT) {
            matchExpect();
        }
    }

    synchronized void onUDPException(ProbeUDPCallback cb, Throwable t) {
        if (cb != currentUDPCallback) return;
        if (log.isEnabled()) log.getLogger().info("udp exception: " + t);
        if (mode == Mode.EXPECT) {
            fireArmed(receivedData ? "nomatch" : "error");
        } else {
            fireArmed("error");
        }
    }

    private void matchExpect() {
        List<PatternRule> patterns = expectPatterns;
        if (patterns == null) return;
        // ISO-8859-1 is a byte-preserving decode of 0..255, so regexes on ASCII markers
        // match inside binary responses without UTF-8 mangling.
        String data = accumulator.toString(StandardCharsets.ISO_8859_1);
        for (PatternRule rule : patterns) {
            Matcher m = rule.pattern().matcher(data);
            if (m.find()) {
                captureFact(rule, m);
                accumulator.reset();
                fireArmed(rule.getOutcome());
                return;
            }
        }
        // no match yet: keep waiting for more bytes / timeout / close
    }

    /**
     * If the matched rule declares a {@code capture}, extract its capture group and
     * record it as a service fact. Any extraction failure is swallowed — version
     * detection is best-effort and must never derail the probe.
     */
    private void captureFact(PatternRule rule, Matcher m) {
        String name = rule.getCapture();
        if (name == null || name.isEmpty()) return;
        int g = rule.getCaptureGroup();
        if (g < 0 || g > m.groupCount()) return;
        try {
            String v = m.group(g);
            if (v != null) {
                result.fact(name, cleanFact(v));
            }
        } catch (Exception ignored) {
        }
    }

    /** Normalize a captured fact: drop CR/LF, trim, and bound the length. */
    private static String cleanFact(String v) {
        String s = v.replace('\r', ' ').replace('\n', ' ').trim();
        return s.length() > 256 ? s.substring(0, 256) : s;
    }

    // ==================== Helpers ====================

    public String hostname() {
        return target.getInetAddress();
    }

    public ProbeResult.Builder result() {
        return result;
    }

    private String expandTemplate(String s) {
        if (s == null) return "";
        return s.replace("{probe.hostname}", hostname())
                .replace("{probe.port}", Integer.toString(currentPort));
    }

    private void closeCurrent() {
        PQCHandshakeStateMachine sm = pqcSM;
        if (sm != null) {
            try { sm.close(); } catch (Exception ignored) { }
            pqcSM = null;
        }
        PQCSessionConfig cfg = pqcConfig;
        if (cfg != null) {
            SharedIOUtil.close(cfg); // closes channel + caches buffers
            pqcConfig = null;
        }
        ProbeTCPCallback cb = currentCallback;
        if (cb != null) {
            SharedIOUtil.close(cb);
        }
        ProbeSecureCallback scb = currentSecureCallback;
        if (scb != null) {
            SharedIOUtil.close(scb); // base delegate closes channel + SSL config (close-notify)
            currentSecureCallback = null;
        }
        ProbeUDPCallback ucb = currentUDPCallback;
        if (ucb != null) {
            SharedIOUtil.close(ucb);
            currentUDPCallback = null;
        }
        // Abort the connection at the NIOSocket level: if the socket was still connecting, this
        // cancels its pending connect-timeout appointment (otherwise orphaned in the scheduler for
        // the full timeout, keeping the processor "busy" long after this probe is torn down).
        SelectionKey key = currentKey;
        if (key != null) {
            currentKey = null;
            nioSocket.abortClientSocket(key);
        }
    }
}
