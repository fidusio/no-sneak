package io.xlogistx.nosneak.probe;

import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;
import org.zoxweb.shared.util.NVInt;
import org.zoxweb.shared.util.NVLong;

import java.util.ArrayList;
import java.util.List;

/**
 * The structured, <em>facts-only</em> output of one probe run. It records what
 * was <em>observed</em> (transports, TLS state, negotiated parameters, PQC
 * classification, a per-connection trace) and deliberately makes no verdict or
 * score: the deferred rules/record layer consumes these facts and owns any
 * derived judgement. The {@code observedAtMs} timestamp marks the observation
 * (capture time), not a later scoring run.
 */
public class ProbeResult {

    /** Whether/how TLS was reached on this target. */
    public enum TlsState {
        NONE,               // plaintext only; no TLS reached
        DIRECT_TLS,         // TLS negotiated directly on connect (e.g. 443)
        STARTTLS_UPGRADED   // plaintext session upgraded to TLS mid-stream (e.g. 25 STARTTLS)
    }

    /** Post-quantum readiness classification of the negotiated key exchange. */
    public enum PqcStatus {
        PQC,        // a hybrid/PQC group was negotiated
        PQC_READY,  // server accepted an offered hybrid group / advertises support
        CLASSICAL,  // classical key exchange, no PQC
        NOT_READY,  // TLS reached but no PQC path available
        UNKNOWN     // not determined (no TLS, or handshake failed)
    }

    /** One connection attempt within a (possibly multi-connection) probe. */
    public static final class ConnectionTrace {
        public final int index;
        public final int port;
        public final String outcome;   // terminal label / note for this connection
        public ConnectionTrace(int index, int port, String outcome) {
            this.index = index;
            this.port = port;
            this.outcome = outcome;
        }
    }

    private final String host;
    private final int port;
    private final String transport;
    private final String probeName;
    private final String service;
    private final TlsState tlsState;
    private final PqcStatus pqcStatus;
    private final String tlsVersion;
    private final String cipherSuite;
    private final String keyExchangeGroup;
    private final String keyExchangeAlgorithm;
    private final String certSubject;
    private final String certIssuer;
    private final boolean complete;      // did the state machine reach a clean 'done' terminal?
    private final String note;           // free-form annotation (e.g. "no-starttls")
    private final long observedAtMs;     // capture time of the observation
    private final long durationMs;
    private final List<ConnectionTrace> connections;

    private ProbeResult(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.transport = b.transport;
        this.probeName = b.probeName;
        this.service = b.service;
        this.tlsState = b.tlsState;
        this.pqcStatus = b.pqcStatus;
        this.tlsVersion = b.tlsVersion;
        this.cipherSuite = b.cipherSuite;
        this.keyExchangeGroup = b.keyExchangeGroup;
        this.keyExchangeAlgorithm = b.keyExchangeAlgorithm;
        this.certSubject = b.certSubject;
        this.certIssuer = b.certIssuer;
        this.complete = b.complete;
        this.note = b.note;
        this.observedAtMs = b.observedAtMs;
        this.durationMs = b.durationMs;
        this.connections = b.connections;
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getTransport() { return transport; }
    public String getProbeName() { return probeName; }
    public String getService() { return service; }
    public TlsState getTlsState() { return tlsState; }
    public PqcStatus getPqcStatus() { return pqcStatus; }
    public String getTlsVersion() { return tlsVersion; }
    public String getCipherSuite() { return cipherSuite; }
    public String getKeyExchangeGroup() { return keyExchangeGroup; }
    public boolean isComplete() { return complete; }
    public String getNote() { return note; }
    public long getObservedAtMs() { return observedAtMs; }
    public List<ConnectionTrace> getConnections() { return connections; }

    /**
     * Render as an {@link NVGenericMap} in the same house style as
     * {@code PQCScanResult.toNVGenericMap}, for the future record layer / JSON.
     */
    public NVGenericMap toNVGenericMap() {
        NVGenericMap nvgm = new NVGenericMap("ProbeResult");
        nvgm.add("host", host);
        nvgm.add(new NVInt("port", port));
        nvgm.add("transport", transport);
        if (probeName != null) nvgm.add("probe", probeName);
        if (service != null) nvgm.add("service", service);
        nvgm.add("tls-state", tlsState.name());
        nvgm.add("pqc-status", pqcStatus.name());
        if (tlsVersion != null) nvgm.add("tls-version", tlsVersion);
        if (cipherSuite != null) nvgm.add("cipher-suite", cipherSuite);
        if (keyExchangeGroup != null) nvgm.add("key-exchange-group", keyExchangeGroup);
        if (keyExchangeAlgorithm != null) nvgm.add("key-exchange-algorithm", keyExchangeAlgorithm);
        if (certSubject != null) nvgm.add("cert-subject", certSubject);
        if (certIssuer != null) nvgm.add("cert-issuer", certIssuer);
        nvgm.add(new NVBoolean("complete", complete));
        if (note != null) nvgm.add("note", note);
        nvgm.add(new NVLong("observed-at-ms", observedAtMs));
        nvgm.add(new NVLong("duration-ms", durationMs));
        if (connections != null && !connections.isEmpty()) {
            NVGenericMapList list = new NVGenericMapList("connections");
            for (ConnectionTrace c : connections) {
                NVGenericMap cm = new NVGenericMap();
                cm.add(new NVInt("index", c.index));
                cm.add(new NVInt("port", c.port));
                if (c.outcome != null) cm.add("outcome", c.outcome);
                list.add(cm);
            }
            nvgm.add(list);
        }
        return nvgm;
    }

    @Override
    public String toString() {
        return "ProbeResult{" + host + ":" + port + "/" + transport
                + " service=" + service + " tls=" + tlsState + " pqc=" + pqcStatus
                + " complete=" + complete + (note != null ? " note=" + note : "") + "}";
    }

    public static Builder builder(String host, int port, String transport) {
        return new Builder(host, port, transport);
    }

    /**
     * Mutable accumulator the {@code record}/{@code pqc-check} actions write into
     * as the state machine advances; built exactly once at terminal delivery.
     */
    public static final class Builder {
        private final String host;
        private final int port;
        private final String transport;
        private String probeName;
        private String service;
        private TlsState tlsState = TlsState.NONE;
        private PqcStatus pqcStatus = PqcStatus.UNKNOWN;
        private String tlsVersion;
        private String cipherSuite;
        private String keyExchangeGroup;
        private String keyExchangeAlgorithm;
        private String certSubject;
        private String certIssuer;
        private boolean complete = false;
        private String note;
        private long observedAtMs = System.currentTimeMillis();
        private long durationMs;
        private final List<ConnectionTrace> connections = new ArrayList<>();

        private Builder(String host, int port, String transport) {
            this.host = host;
            this.port = port;
            this.transport = transport;
        }

        public Builder probeName(String v) { this.probeName = v; return this; }
        public Builder service(String v) { this.service = v; return this; }
        public Builder tlsState(TlsState v) { this.tlsState = v; return this; }
        public Builder pqcStatus(PqcStatus v) { this.pqcStatus = v; return this; }
        public Builder tlsVersion(String v) { this.tlsVersion = v; return this; }
        public Builder cipherSuite(String v) { this.cipherSuite = v; return this; }
        public Builder keyExchangeGroup(String v) { this.keyExchangeGroup = v; return this; }
        public Builder keyExchangeAlgorithm(String v) { this.keyExchangeAlgorithm = v; return this; }
        public Builder certSubject(String v) { this.certSubject = v; return this; }
        public Builder certIssuer(String v) { this.certIssuer = v; return this; }
        public Builder complete(boolean v) { this.complete = v; return this; }
        public Builder observedAtMs(long v) { this.observedAtMs = v; return this; }
        public Builder durationMs(long v) { this.durationMs = v; return this; }

        /** Merge a note; multiple notes are semicolon-joined so none is lost. */
        public Builder note(String v) {
            if (v == null || v.isEmpty()) return this;
            this.note = (this.note == null) ? v : this.note + "; " + v;
            return this;
        }

        public Builder addConnection(int index, int port, String outcome) {
            this.connections.add(new ConnectionTrace(index, port, outcome));
            return this;
        }

        public TlsState tlsState() { return tlsState; }

        public ProbeResult build() {
            return new ProbeResult(this);
        }
    }
}
