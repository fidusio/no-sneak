package io.xlogistx.nosneak.probe.runtime;

import io.xlogistx.nosneak.probe.ProbeResult;
import io.xlogistx.nosneak.probe.model.PatternRule;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.scanners.PQCConnectionHelper.PQCHandshakeState;
import io.xlogistx.nosneak.scanners.PQCSSLStateMachine;
import io.xlogistx.nosneak.scanners.PQCSessionConfig;
import io.xlogistx.nosneak.scanners.PQCTlsClient;
import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.SharedBase64;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Execution context for one probe run: it owns the {@link ProbeStateMachine},
 * the live NIO connection(s), the {@link ProbeResult} builder, and the switch
 * between plaintext ({@code expect}) mode and TLS-handshake ({@code pqc-check})
 * mode on a single channel. One session outlives individual connections, so a
 * {@code reconnect} swaps in a fresh callback while the interpreter and the
 * accumulated result persist — that is what makes multi-connection probes work.
 * <p>
 * Concurrency: all state transitions run on the NIO selector thread or the task
 * scheduler thread and are serialised through {@link #fire(String)} /
 * {@link #deliver(boolean, String)} (both synchronized). Every asynchronous wait
 * is guarded by a single {@code armed} token so an inbound event and its timeout
 * can never both fire the same transition. Terminal delivery is exactly-once.
 * <p>
 * The design mirrors the proven {@link io.xlogistx.nosneak.scanners.PQCScanCallback}
 * mother-callback (overall watchdog via {@link TaskUtil#defaultTaskScheduler()},
 * {@code delivered} guard) and the {@link io.xlogistx.nosneak.scanners.TLSProbeCallback}
 * post-connect timeout idiom.
 */
public class ProbeSession {

    public static final LogWrapper log = new LogWrapper(ProbeSession.class).setEnabled(false);

    /** How inbound bytes on the current channel are interpreted. */
    enum Mode { CONNECTING, EXPECT, TLS, IDLE }

    private final NIOSocket nioSocket;
    private final IPAddress target;
    private final ProbeDefinition definition;
    private final int timeoutSec;
    private final Consumer<ProbeResult> userCallback;

    private final ProbeStateMachine machine;
    private final ProbeResult.Builder result;
    private final long startTime = System.currentTimeMillis();

    // Terminal + per-wait guards
    private final AtomicBoolean terminated = new AtomicBoolean(false);
    private final AtomicBoolean armed = new AtomicBoolean(false);
    // Generation stamp for the current wait window. A timeout task captures the
    // generation it was scheduled under; if the window has since been re-armed
    // (openConnection/beginExpect/startTlsHandshake), a stale timeout that is
    // already executing is ignored instead of resolving a later window.
    private final AtomicLong armGen = new AtomicLong();
    private volatile ScheduledFuture<?> waitTimeout;
    private volatile ScheduledFuture<?> overallDeadline;

    // Live connection state
    private volatile ProbeTCPCallback currentCallback;
    private volatile Mode mode = Mode.IDLE;
    private int connectionIndex = 0;
    private int currentPort;
    private boolean receivedData = false;

    // expect() accumulation + active patterns
    private final ByteArrayOutputStream accumulator = new ByteArrayOutputStream();
    private volatile List<PatternRule> expectPatterns;

    // Inner TLS/PQC handshake (reused unchanged).
    // TODO(no-monostatemachine): PQCSSLStateMachine extends MonoStateMachine, which is
    // disallowed project-wide (see PROBE-FRAMEWORK.md). Replace this reuse with a direct
    // BC non-blocking handshake pump (offerInput/readOutput over PQCSessionConfig) or the
    // trigger-based org.zoxweb.server.fsm.StateMachine.
    private volatile PQCSessionConfig pqcConfig;
    private volatile PQCSSLStateMachine pqcSM;
    private volatile boolean tlsUpgrade = false; // true => reached TLS via STARTTLS

    public ProbeSession(NIOSocket nioSocket, IPAddress target, ProbeDefinition definition,
                        int timeoutSec, Consumer<ProbeResult> userCallback) {
        this.nioSocket = nioSocket;
        this.target = target;
        this.definition = definition;
        this.timeoutSec = timeoutSec > 0 ? timeoutSec : 5;
        this.userCallback = userCallback;
        this.machine = new ProbeStateMachine(definition, this);
        this.result = ProbeResult.builder(target.getInetAddress(), target.getPort(), definition.getTransport())
                .probeName(definition.getName())
                .service(definition.getService())
                .observedAtMs(startTime);
    }

    // ==================== Lifecycle ====================

    /** Arm the overall watchdog and enter the start state. */
    public void start() {
        int overall = Math.max(timeoutSec * 4, 30);
        overallDeadline = TaskUtil.defaultTaskScheduler()
                .schedule(() -> deliver(false, "overall-timeout"), overall, TimeUnit.SECONDS);
        machine.start();
    }

    public boolean isTerminated() {
        return terminated.get();
    }

    /** Advance the state machine. Serialised; ignored once terminated. */
    public synchronized void fire(String outcome) {
        machine.fire(outcome);
    }

    /**
     * Deliver the {@link ProbeResult} exactly once and tear the session down.
     */
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
        machine.close();
        ProbeResult r = result.build();
        if (log.isEnabled()) {
            log.getLogger().info("deliver " + r);
        }
        try {
            userCallback.accept(r);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("userCallback error: " + e.getMessage());
        }
    }

    // ==================== Async wait guard ====================

    /** Arm a single-shot wait: the first of (event, timeout) wins. */
    private void arm() {
        long gen = armGen.incrementAndGet();
        armed.set(true);
        cancelWaitTimeout();
        waitTimeout = TaskUtil.defaultTaskScheduler()
                .schedule(() -> fireArmedGen("timeout", gen), timeoutSec, TimeUnit.SECONDS);
    }

    /** Fire {@code outcome} for the current wait window (used by NIO events). */
    private void fireArmed(String outcome) {
        fireArmedGen(outcome, armGen.get());
    }

    /**
     * Fire {@code outcome} iff {@code gen} is still the current wait window and it
     * has not already been resolved. A stale timeout (older generation) is ignored.
     */
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

    /** connect (and reconnect): open a fresh channel to {@code port}. */
    public void openConnection(int port) {
        connectionIndex++;
        currentPort = port;
        mode = Mode.CONNECTING;
        receivedData = false;
        accumulator.reset();
        pqcConfig = null;
        pqcSM = null;
        arm();
        ProbeTCPCallback cb = new ProbeTCPCallback(this, new IPAddress(target.getInetAddress(), port), connectionIndex);
        currentCallback = cb;
        try {
            nioSocket.addClientSocket(cb, timeoutSec);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("connect error: " + e.getMessage());
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
     * send: resolve a state's payload to bytes and write them to the current
     * channel. Prefers the codec-prefixed {@code data} field (binary-capable:
     * {@code hex:} / {@code base64:} / {@code text:}, or plain text if unprefixed)
     * and falls back to the templated-text {@code payload} field.
     *
     * @return {@code true} if written, {@code false} on a null channel, bad
     *         payload, or write failure (the caller should fire an error outcome).
     */
    public boolean send(io.xlogistx.nosneak.probe.model.ProbeState state) {
        byte[] bytes;
        try {
            bytes = resolveSendBytes(state);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("send decode error: " + e.getMessage());
            return false;
        }
        return writeBytes(bytes);
    }

    /** send (text): write templated plaintext bytes (used for protocol commands, e.g. STARTTLS). */
    public boolean write(String payload) {
        return writeBytes(expandTemplate(payload).getBytes(StandardCharsets.UTF_8));
    }

    private byte[] resolveSendBytes(io.xlogistx.nosneak.probe.model.ProbeState state) {
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

    /**
     * tls-handshake: start a Bouncy Castle handshake on the CURRENT already-open
     * channel (mid-session upgrade if {@code upgrade}). When {@code classicalOnly}
     * is true the ClientHello advertises only classical groups (a fully classical
     * handshake, no PQC hybrids); otherwise PQC hybrids are offered. Reuses
     * {@link PQCSessionConfig}/{@link PQCSSLStateMachine}.
     */
    public void startTlsHandshake(boolean upgrade, boolean classicalOnly) {
        this.tlsUpgrade = upgrade;
        this.mode = Mode.TLS;
        arm();
        try {
            // SNI must carry the target HOSTNAME, not the connected peer IP. Use an
            // unresolved address so the name is preserved without a blocking DNS lookup
            // on the selector thread (the channel is already connected).
            InetSocketAddress sni = InetSocketAddress.createUnresolved(hostname(), currentPort);
            pqcConfig = new PQCSessionConfig(sni, classicalOnly);
            pqcConfig.channel = currentCallback.getChannel();
            pqcSM = new PQCSSLStateMachine(pqcConfig);
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

    /**
     * pqc-check: record TLS facts <em>and</em> classify the negotiated key
     * exchange (PQC / classical / unknown).
     */
    public void recordPQC() {
        recordTls(true);
    }

    /**
     * tls-facts: record TLS facts (state, version, cipher, key-exchange group,
     * cert) <em>without</em> any PQC classification. For probes that only need to
     * confirm TLS/STARTTLS, not assess post-quantum readiness.
     */
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
                // Undetermined key exchange is not the same as a confirmed classical one.
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
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("cert facts skipped: " + e.getMessage());
        }
    }

    /** record: merge a note into the result. */
    public void recordNote(String note) {
        result.note(note);
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
            PQCSSLStateMachine sm = pqcSM;
            if (sm != null) {
                sm.processIncomingData(ByteBuffer.wrap(bytes), this::onTlsTransition);
                // The reused handshake machine closes the config on an init/write
                // failure (publish CLOSED) but does not invoke the callback, so a
                // failed handshake would otherwise resolve only via the wait timeout.
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

    private void matchExpect() {
        List<PatternRule> patterns = expectPatterns;
        if (patterns == null) return;
        // ISO-8859-1 is a byte-preserving (lossless) decode of 0..255, so regexes
        // targeting ASCII markers match inside binary responses (e.g. BSON field
        // names in a MongoDB reply) without UTF-8 mangling. ASCII text probes are
        // unaffected (ASCII is a subset).
        String data = accumulator.toString(StandardCharsets.ISO_8859_1);
        for (PatternRule rule : patterns) {
            if (rule.pattern().matcher(data).find()) {
                accumulator.reset();
                fireArmed(rule.getOutcome());
                return;
            }
        }
        // no match yet: keep waiting for more bytes / timeout / close
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
        PQCSSLStateMachine sm = pqcSM;
        if (sm != null) {
            try { sm.close(); } catch (Exception ignored) { }
            pqcSM = null;
        }
        PQCSessionConfig cfg = pqcConfig;
        if (cfg != null) {
            SharedIOUtil.close(cfg); // closes the channel + caches buffers
            pqcConfig = null;
        }
        ProbeTCPCallback cb = currentCallback;
        if (cb != null) {
            SharedIOUtil.close(cb);
        }
    }
}
