package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.analysis.CipherProbeCallback;
import io.xlogistx.nosneak.v2.analysis.GroupProbeCallback;
import io.xlogistx.nosneak.v2.analysis.NetworkRevocationChecker;
import io.xlogistx.nosneak.v2.analysis.RevocationChecker;
import org.zoxweb.server.http.HTTPNIOSocket;
import io.xlogistx.nosneak.v2.analysis.VersionProbeCallback;
import io.xlogistx.nosneak.v2.model.PatternRule;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import org.bouncycastle.tls.ProtocolVersion;
import io.xlogistx.nosneak.v2.tls.PQCHandshakeStateMachine;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import io.xlogistx.nosneak.v2.tls.PQCTlsClient;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.crypto.TlsCertificate;
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
 * <b>Fully non-blocking.</b> Connections are opened through a {@link ProbeTransport} (the
 * injected {@link NIOSocket} in production, a scripted stand-in under test); every
 * asynchronous wait (connect / expect / overall) is bounded by a task on the injected
 * scheduler. All transitions run on the selector or scheduler thread and are serialised
 * through the context monitor. Each wait is guarded by a single {@code armed} token plus an
 * {@code armGen} epoch so an inbound event and its timeout can never both resolve the same
 * window. Terminal delivery is exactly-once.
 * <p>
 * <b>The user's callback never runs under the monitor.</b> Every entry point — an engine
 * transition, an inbound byte, a timer, a cancel — takes the monitor through
 * {@link #guarded(Runnable)}, which tracks re-entrancy depth; a terminal {@code deliver}
 * only <em>parks</em> the built result, and the outermost frame hands it to the callback
 * after the monitor is released. So a {@code FirstSweep} election, and the {@code cancel()}
 * it issues to each losing context, never run while holding the winner's monitor
 * (PENDING-ISSUES P10).
 */
public class ProbeContext {

    public static final LogWrapper log = new LogWrapper(ProbeContext.class).setEnabled(false);

    /** How inbound bytes on the current channel are interpreted. */
    enum Mode { CONNECTING, EXPECT, TLS, IDLE, SECURE_CONNECTING, UDP }

    private final ProbeTransport transport;
    private final IPAddress target;
    private final ProbeDefinition definition;
    private final int timeoutSec;
    private final Consumer<ProbeResult> userCallback;
    /** Arms every wait guard; taken from the {@link NIOSocket} this probe rides on. */
    private final ScheduledExecutorService scheduler;
    /** Parallel dispatch for fan-out children; taken from the same {@link NIOSocket}. */
    private final Executor executor;
    /**
     * HTTP over the same {@link NIOSocket}, for the active OCSP/CRL fetch of
     * {@code revocation-check}. Null on the test seam: a scripted probe then reports revocation
     * as unknown/none rather than touching a network.
     */
    private final HTTPNIOSocket httpNio;

    private final ProbeEngine engine;
    private final ProbeResult.Builder result;
    private final long startTime = System.currentTimeMillis();

    // Terminal + per-wait guards
    private final AtomicBoolean terminated = new AtomicBoolean(false);
    private final AtomicBoolean armed = new AtomicBoolean(false);
    private final AtomicLong armGen = new AtomicLong();
    private volatile ScheduledFuture<?> waitTimeout;
    private volatile ScheduledFuture<?> overallDeadline;
    // Monitor re-entrancy depth and the result parked by deliver() until the outermost frame
    // leaves the monitor. Both guarded by `this`.
    private int depth;
    private ProbeResult pendingDelivery;

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
        // Every wait this probe arms runs on the pools the NIOSocket was constructed with, rather
        // than the process-wide defaults, so an embedder that supplied its own executor and
        // scheduler gets the whole probe — connect, expect, handshake and overall deadlines — on
        // them. Taking them from the socket also makes it impossible to arm a timeout on one pool
        // while the I/O it guards runs on another.
        this(new NioProbeTransport(nioSocket), nioSocket.getScheduler(), nioSocket.getExecutor(),
             new HTTPNIOSocket(nioSocket), target, definition, timeoutSec, userCallback);
    }

    /**
     * The seam constructor: a transport and the two executors, injected. Production goes
     * through the {@link NIOSocket} constructor above; tests hand in a scripted transport and a
     * manual scheduler so every branch of the state machine can be driven without a wire.
     */
    ProbeContext(ProbeTransport transport, ScheduledExecutorService scheduler, Executor executor,
                 IPAddress target, ProbeDefinition definition, int timeoutSec,
                 Consumer<ProbeResult> userCallback) {
        this(transport, scheduler, executor, null, target, definition, timeoutSec, userCallback);
    }

    ProbeContext(ProbeTransport transport, ScheduledExecutorService scheduler, Executor executor,
                 HTTPNIOSocket httpNio, IPAddress target, ProbeDefinition definition, int timeoutSec,
                 Consumer<ProbeResult> userCallback) {
        this.transport = transport;
        this.scheduler = scheduler;
        this.executor = executor;
        this.httpNio = httpNio;
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
        guarded(() -> {
            if (terminated.get()) {
                return;
            }
            int overall = Math.max(timeoutSec * 4, 30);
            overallDeadline = scheduler
                    .schedule(() -> deliver(false, "overall-timeout"), overall, TimeUnit.SECONDS);
            engine.start();
        });
    }

    public boolean isTerminated() {
        return terminated.get();
    }

    /** Advance the engine. Serialised; ignored once terminated. */
    public void fire(String outcome) {
        guarded(() -> engine.fire(outcome));
    }

    /**
     * Deliver the {@link ProbeResult} exactly once and tear the context down. The result is
     * built and the context torn down under the monitor; the user's callback runs after the
     * outermost frame has released it (see {@link #guarded(Runnable)}).
     */
    public void deliver(boolean complete, String terminalNote) {
        guarded(() -> {
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
            pendingDelivery = result.build();
            if (log.isEnabled()) log.getLogger().info("deliver " + pendingDelivery);
        });
    }

    /**
     * Tear this context down WITHOUT delivering a result — used to supersede a losing/redundant
     * candidate in a parallel sweep once a higher-priority probe has already won. Idempotent; a
     * context that has already delivered (or been cancelled) is left untouched, so the winner's
     * result is never clobbered.
     */
    public void cancel() {
        guarded(() -> {
            if (!terminated.compareAndSet(false, true)) {
                return;
            }
            cancelWaitTimeout();
            cancelOverall();
            closeCurrent();
            engine.close();
        });
    }

    /**
     * Run {@code body} under the monitor, then — only when this is the outermost frame — hand
     * any result parked by {@link #deliver} to the user's callback <em>outside</em> the monitor.
     * Re-entrant: an action that fires the next outcome synchronously nests one level deeper
     * and the parked result waits for the outermost frame. Exactly-once holds because
     * {@code terminated} is claimed under the monitor and the parked result is taken once.
     */
    private void guarded(Runnable body) {
        ProbeResult toDeliver = null;
        synchronized (this) {
            depth++;
            try {
                body.run();
            } finally {
                depth--;
            }
            if (depth == 0 && pendingDelivery != null) {
                toDeliver = pendingDelivery;
                pendingDelivery = null;
            }
        }
        if (toDeliver != null) {
            try {
                userCallback.accept(toDeliver);
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("userCallback error: " + e.getMessage());
            }
        }
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
            currentKey = transport.open(cb, timeoutSec);
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
            currentKey = transport.open(cb, timeoutSec);
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
            currentKey = transport.openDatagram(cb); // ephemeral local bind
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

    /** Package-private so {@code SendBytesTest} can pin the codec prefixes and the templating. */
    byte[] resolveSendBytes(ProbeState state) {
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
        if (cb == null || data == null) {
            return false;
        }
        try {
            transport.write(cb, data);
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
            ProbeTransport.TlsSession session =
                    transport.startTls(currentCallback, sni, classicalOnly, this::onTlsTransition);
            pqcConfig = session.config;
            pqcSM = session.machine;
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
                    transport.open(probe); // uses probe.timeoutInSec()
                } catch (Exception e) {
                    join.childDone();
                }
            });
        }
        Fanout.run(children, () -> onVersionsDone(results), executor);
    }

    private void onVersionsDone(Map<String, Boolean> results) {
        guarded(() -> {
            // Record best-first for a stable, readable order (weakest last).
            for (String name : new String[]{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"}) {
                if (Boolean.TRUE.equals(results.get(name))) {
                    result.addProtocolVersion(name);
                }
            }
            engine.fire("done");
        });
    }

    /**
     * Upper bound on the child connections one enumeration step may open at once. A deep probe
     * today costs at most 5 (versions) + 44 (ciphers) + 2 (cipher preference) + 10 (groups) = 61
     * connections, each bounded by its own handshake timeout; candidate lists longer than this
     * are truncated rather than allowed to grow silently.
     */
    public static final int MAX_ENUMERATION_CHILDREN = 64;

    /** TLS 1.3 suites (5) — every one AEAD; opsec's list. */
    private static final int[] TLS13_CIPHERS = OPSecUtil.ALL_TLS13_CIPHERS;

    /**
     * TLS 1.2 candidates: opsec's strong (9), weak (21) and insecure (9) sets, in that order, so
     * a server's <em>whole</em> accepted surface is observed and the weak-suite grading rule has
     * something to look at. Offering an old suite in a ClientHello is an ordinary handshake.
     */
    private static final int[] TLS12_CIPHERS = concat(OPSecUtil.ALL_TLS12_STRONG,
                                                      OPSecUtil.ALL_TLS12_WEAK,
                                                      OPSecUtil.ALL_TLS12_INSECURE);

    private static int[] concat(int[]... parts) {
        int n = 0;
        for (int[] p : parts) n += p.length;
        int[] out = new int[n];
        int at = 0;
        for (int[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    private static int[] bounded(int[] candidates, int limit) {
        return candidates.length <= limit ? candidates : java.util.Arrays.copyOf(candidates, limit);
    }

    private static boolean isTls13Suite(int cipher) {
        for (int c : TLS13_CIPHERS) {
            if (c == cipher) return true;
        }
        return false;
    }

    /**
     * enumerate-ciphers: probe each candidate cipher suite <b>in parallel</b> (one connection
     * offering a single cipher at its version) via {@link Fanout}; record the accepted set with
     * opsec's strength classification; then, when two or more suites were accepted at a version,
     * two more handshakes offering the whole accepted list in our order and in reverse decide
     * whether the server or the client picks ({@code server-cipher-preference}); then fire
     * {@code done}.
     */
    public void enumerateCiphers() {
        final int port = currentPort > 0 ? currentPort : target.getPort();
        final Map<Integer, Boolean> accepted = new ConcurrentHashMap<>();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        final int[] tls13 = bounded(TLS13_CIPHERS, MAX_ENUMERATION_CHILDREN);
        final int[] tls12 = bounded(TLS12_CIPHERS, Math.max(0, MAX_ENUMERATION_CHILDREN - tls13.length));
        cipherChildren(children, accepted, ProtocolVersion.TLSv13, tls13, port);
        cipherChildren(children, accepted, ProtocolVersion.TLSv12, tls12, port);
        final int[] ordered = concat(tls13, tls12);
        Fanout.run(children, () -> onCiphersDone(accepted, ordered, port), executor);
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
                    transport.open(probe);
                } catch (Exception e) {
                    join.childDone();
                }
            });
        }
    }

    private void onCiphersDone(Map<Integer, Boolean> accepted, int[] ordered, int port) {
        final List<Integer> accepted13 = new ArrayList<>();
        final List<Integer> accepted12 = new ArrayList<>();
        guarded(() -> {
            OPSecUtil ops = OPSecUtil.singleton();
            for (int c : ordered) {
                if (!Boolean.TRUE.equals(accepted.get(c))) {
                    continue;
                }
                boolean v13 = isTls13Suite(c);
                (v13 ? accepted13 : accepted12).add(c);
                String name = PQCTlsClient.getCipherSuiteName(c);
                OPSecUtil.CipherComponents parts = ops.parseCipherSuite(name);
                result.addCipherSuite(name, v13 ? "TLSv1.3" : "TLSv1.2",
                        parts.strength != null ? parts.strength.name() : null,
                        parts.keyExchange, parts.forwardSecrecy);
            }
        });
        // Preference is only meaningful where the server had a choice; TLS 1.2 first because
        // that is where weak suites live, TLS 1.3 otherwise.
        if (accepted12.size() >= 2) {
            probeCipherPreference(accepted12, ProtocolVersion.TLSv12, port);
        } else if (accepted13.size() >= 2) {
            probeCipherPreference(accepted13, ProtocolVersion.TLSv13, port);
        } else {
            guarded(() -> {
                List<Integer> only = accepted12.isEmpty() ? accepted13 : accepted12;
                if (only.size() == 1) {
                    result.serverCipherPreference(PQCTlsClient.getCipherSuiteName(only.get(0)),
                            "only-one-accepted");
                }
                engine.fire("done");
            });
        }
    }

    /**
     * Two handshakes offering every accepted suite at {@code ver}: in our order, then reversed.
     * A server that returns the same suite both times enforces its own preference; one that
     * follows the client's first choice does not. Two children, bounded like every other probe.
     */
    private void probeCipherPreference(List<Integer> acceptedSuites, ProtocolVersion ver, int port) {
        final int[] forward = new int[acceptedSuites.size()];
        final int[] reversed = new int[acceptedSuites.size()];
        for (int i = 0; i < forward.length; i++) {
            forward[i] = acceptedSuites.get(i);
            reversed[forward.length - 1 - i] = acceptedSuites.get(i);
        }
        final Map<String, Integer> picks = new ConcurrentHashMap<>();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        children.add(preferenceChild("forward", forward, ver, port, picks));
        children.add(preferenceChild("reversed", reversed, ver, port, picks));
        Fanout.run(children, () -> onPreferenceDone(picks, forward), executor);
    }

    private Consumer<ParallelJoin> preferenceChild(String label, int[] offer, ProtocolVersion ver, int port,
                                                   Map<String, Integer> picks) {
        return join -> {
            try {
                CipherProbeCallback probe = new CipherProbeCallback(
                        scheduler, new IPAddress(target.getInetAddress(), port), hostname(), ver, offer,
                        (v, cipherId) -> {
                            picks.put(label, cipherId == null ? 0 : cipherId);
                            join.childDone();
                        });
                probe.timeoutInSec(Math.max(timeoutSec, 5));
                transport.open(probe);
            } catch (Exception e) {
                picks.put(label, 0);
                join.childDone();
            }
        };
    }

    private void onPreferenceDone(Map<String, Integer> picks, int[] forward) {
        guarded(() -> {
            Integer f = picks.get("forward");
            Integer r = picks.get("reversed");
            if (f != null && f != 0 && r != null && r != 0) {
                if (f.equals(r)) {
                    result.serverCipherPreference(PQCTlsClient.getCipherSuiteName(f), "server");
                } else {
                    // The pick moved with our order: the server takes the client's first choice.
                    result.serverCipherPreference(PQCTlsClient.getCipherSuiteName(f), "client");
                }
            }
            engine.fire("done");
        });
    }

    /**
     * enumerate-groups: one TLS 1.3 handshake per candidate named group, each offering only
     * that group, <b>in parallel</b> via {@link Fanout}; record the accepted set as
     * {@code supported-groups} (hybrids first) and the group the main handshake negotiated when
     * every group was offered as {@code server-group-preference}; then fire {@code done}.
     * A TLS 1.2-only server accepts none of them — that is the honest answer, since named-group
     * key shares are a TLS 1.3 mechanism.
     */
    public void enumerateGroups() {
        final int port = currentPort > 0 ? currentPort : target.getPort();
        final Map<Integer, Boolean> accepted = new ConcurrentHashMap<>();
        final int[] candidates = bounded(GroupProbeCallback.CANDIDATE_GROUPS, MAX_ENUMERATION_CHILDREN);
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (int g : candidates) {
            final int group = g;
            children.add(join -> {
                try {
                    GroupProbeCallback probe = new GroupProbeCallback(
                            scheduler, new IPAddress(target.getInetAddress(), port), hostname(), group,
                            (namedGroup, ok) -> {
                                if (ok) {
                                    accepted.put(namedGroup, Boolean.TRUE);
                                }
                                join.childDone();
                            });
                    probe.timeoutInSec(Math.max(timeoutSec, 5));
                    transport.open(probe);
                } catch (Exception e) {
                    join.childDone();
                }
            });
        }
        Fanout.run(children, () -> onGroupsDone(accepted, candidates), executor);
    }

    private void onGroupsDone(Map<Integer, Boolean> accepted, int[] candidates) {
        guarded(() -> {
            for (int g : candidates) {
                if (Boolean.TRUE.equals(accepted.get(g))) {
                    result.addSupportedGroup(GroupProbeCallback.groupName(g));
                }
            }
            PQCSessionConfig cfg = pqcConfig;
            if (cfg != null && cfg.tlsClient != null) {
                String chosen = cfg.tlsClient.getNegotiatedKeyExchangeName();
                if (chosen != null && !"UNKNOWN".equals(chosen)) {
                    result.serverGroupPreference(chosen);
                }
            }
            engine.fire("done");
        });
    }

    /**
     * revocation-check: the certificate's revocation status. A handshake-stapled OCSP response
     * (RFC 6066) answers instantly with no network; when nothing was stapled, an OCSP request
     * goes to the leaf's AIA responder and, failing a definitive answer, its CRL is fetched —
     * both non-blocking on this probe's own {@code NIOSocket}, bounded by the state's
     * {@code revocationTimeoutMs} (default {@value NetworkRevocationChecker#DEFAULT_TIMEOUT_MS} ms),
     * soft-failing to UNKNOWN. Requires a prior {@code tls-handshake}. Asynchronous: fires
     * {@code done} when the answer is in — or at once when there is nothing to check.
     */
    public void checkRevocation(ProbeState state) {
        PQCSessionConfig cfg = pqcConfig;
        if (cfg == null || cfg.tlsClient == null) {
            fire("done");
            return;
        }
        try {
            RevocationResult stapled = RevocationChecker.fromStaple(cfg.tlsClient.getStapledOCSPResponse());
            if (RevocationChecker.METHOD_STAPLED.equals(stapled.getMethod())) {
                recordRevocation(stapled);
                fire("done");
                return;
            }
            X509Certificate[] chain = x509Chain(cfg.tlsClient);
            X509Certificate leaf = chain.length > 0 ? chain[0] : null;
            X509Certificate issuer = chain.length > 1 ? chain[1] : null;
            long budget = state != null && state.getRevocationTimeoutMs() != null
                    ? state.getRevocationTimeoutMs() : NetworkRevocationChecker.DEFAULT_TIMEOUT_MS;
            new NetworkRevocationChecker(httpNio, scheduler).check(leaf, issuer, budget, r -> guarded(() -> {
                recordRevocation(r);
                engine.fire("done");
            }));
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("revocation check skipped: " + e.getMessage());
            fire("done");
        }
    }

    private void recordRevocation(RevocationResult r) {
        if (r == null || r.getStatus() == null) {
            return;
        }
        String date = r.getRevocationDate() != null
                ? java.time.Instant.ofEpochMilli(r.getRevocationDate()).toString() : null;
        result.revocation(r.getStatus().name(), r.getMethod(), date, r.getRevocationReason());
    }

    /** The presented chain as JCA certificates, leaf first; empty when none was presented. */
    private static X509Certificate[] x509Chain(PQCTlsClient client) {
        try {
            Certificate presented = client.getServerCertificate();
            if (presented == null || presented.getLength() == 0) {
                return new X509Certificate[0];
            }
            TlsCertificate[] list = presented.getCertificateList();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate[] out = new X509Certificate[list.length];
            for (int i = 0; i < list.length; i++) {
                out[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(list[i].getEncoded()));
            }
            return out;
        } catch (Exception e) {
            return new X509Certificate[0];
        }
    }

    // ==================== NIO event ingress (from ProbeTCPCallback) ====================

    void onConnected(ProbeTCPCallback cb) {
        guarded(() -> {
            if (cb != currentCallback) return;
            fireArmed("connected");
        });
    }

    void onInbound(ProbeTCPCallback cb, byte[] bytes) {
        guarded(() -> {
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
        });
    }

    void onException(ProbeTCPCallback cb, Throwable t) {
        guarded(() -> {
            if (cb != currentCallback) return;
            if (log.isEnabled()) log.getLogger().info("connection exception: " + t);
            fireArmed(mode == Mode.EXPECT && receivedData ? "nomatch" : "error");
        });
    }

    // ==================== Secure (JSSE) NIO ingress (from ProbeSecureCallback) ====================

    /** TLS handshake completed on the secure channel. */
    void onSecureConnected(ProbeSecureCallback cb) {
        guarded(() -> {
            if (cb != currentSecureCallback) return;
            recordSecureTlsFacts(cb);
            fireArmed("connected");
        });
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
    void onSecureInbound(ProbeSecureCallback cb, byte[] bytes) {
        guarded(() -> {
            if (cb != currentSecureCallback || bytes == null || bytes.length == 0) return;
            receivedData = true;
            accumulator.write(bytes, 0, bytes.length);
            if (mode == Mode.EXPECT) {
                matchExpect();
            }
        });
    }

    void onSecureException(ProbeSecureCallback cb, Throwable t) {
        guarded(() -> {
            if (cb != currentSecureCallback) return;
            if (log.isEnabled()) log.getLogger().info("secure connection exception: " + t);
            fireArmed(mode == Mode.EXPECT && receivedData ? "nomatch" : "error");
        });
    }

    // ==================== UDP ingress (from ProbeUDPCallback) ====================

    /** A response datagram — accumulate and run the {@code expect} matcher. */
    void onUDPInbound(ProbeUDPCallback cb, byte[] bytes) {
        guarded(() -> {
            if (cb != currentUDPCallback || bytes == null || bytes.length == 0) return;
            receivedData = true;
            accumulator.write(bytes, 0, bytes.length);
            if (mode == Mode.EXPECT) {
                matchExpect();
            }
        });
    }

    void onUDPException(ProbeUDPCallback cb, Throwable t) {
        guarded(() -> {
            if (cb != currentUDPCallback) return;
            if (log.isEnabled()) log.getLogger().info("udp exception: " + t);
            fireArmed(mode == Mode.EXPECT && receivedData ? "nomatch" : "error");
        });
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
            transport.abort(key);
        }
    }

    /** The current engine state id — a test probe into the traversal; null before start. */
    String currentStateId() {
        return engine.currentId();
    }

    /** The port of the current connection (0 before the first connect) — a test probe. */
    int currentPort() {
        return currentPort;
    }

    /** The definition this context runs — a test probe. */
    String probeName() {
        return definition.getName();
    }

    /** Whether a wait window is armed right now (a test probe). */
    boolean isArmed() {
        return armed.get();
    }
}
