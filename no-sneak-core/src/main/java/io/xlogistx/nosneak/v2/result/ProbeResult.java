package io.xlogistx.nosneak.v2.result;

import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;
import org.zoxweb.shared.util.NVInt;
import org.zoxweb.shared.util.NVLong;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The structured, <em>facts-only</em> output of one probe run. It records what was
 * <em>observed</em> (transports, TLS state, negotiated parameters, PQC
 * classification, captured service facts, a per-connection trace) and deliberately
 * makes no verdict or score: a deferred rules/grading layer consumes these facts.
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
        public final String outcome;
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
    private final String certNotBefore;
    private final String certNotAfter;
    private final String certValidity;
    private final boolean complete;
    private final String note;
    private final long observedAtMs;
    private final long durationMs;
    private final List<ConnectionTrace> connections;
    private final Map<String, String> serviceFacts;
    // Deep-analysis facts (populated by scanner-grade actions).
    private final String certChainTrust;
    private final List<String> supportedProtocolVersions;
    private final List<String> supportedCipherSuites;
    private final String revocationStatus;
    private final String revocationMethod;

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
        this.certNotBefore = b.certNotBefore;
        this.certNotAfter = b.certNotAfter;
        this.certValidity = b.certValidity;
        this.complete = b.complete;
        this.note = b.note;
        this.observedAtMs = b.observedAtMs;
        this.durationMs = b.durationMs;
        this.connections = b.connections;
        this.serviceFacts = b.serviceFacts;
        this.certChainTrust = b.certChainTrust;
        this.supportedProtocolVersions = b.supportedProtocolVersions;
        this.supportedCipherSuites = b.supportedCipherSuites;
        this.revocationStatus = b.revocationStatus;
        this.revocationMethod = b.revocationMethod;
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

    /** All captured service facts (banner-derived), or an empty map if none. */
    public Map<String, String> getServiceFacts() { return serviceFacts; }

    /** The detected service version string (the {@code "version"} fact), or {@code null}. */
    public String getServiceVersion() { return serviceFacts.get("version"); }

    /** A captured service fact by name (e.g. {@code "product"}, {@code "banner"}), or {@code null}. */
    public String getServiceFact(String name) { return serviceFacts.get(name); }

    /** PKIX chain-trust verdict (e.g. TRUSTED / UNTRUSTED_ROOT / …), or {@code null}. */
    public String getCertChainTrust() { return certChainTrust; }
    public String getCertValidity() { return certValidity; }
    public String getCertNotAfter() { return certNotAfter; }

    /** Server-accepted protocol versions from enumeration, or an empty list. */
    public List<String> getSupportedProtocolVersions() { return supportedProtocolVersions; }

    /** Server-accepted cipher suites from enumeration, or an empty list. */
    public List<String> getSupportedCipherSuites() { return supportedCipherSuites; }

    /** Certificate revocation status (GOOD / REVOKED / UNKNOWN / …), or {@code null}. */
    public String getRevocationStatus() { return revocationStatus; }

    /** Render as an {@link NVGenericMap} for the record layer / JSON. */
    public NVGenericMap toNVGenericMap() {
        NVGenericMap nvgm = new NVGenericMap("ProbeResult");
        nvgm.add("host", host);
        nvgm.add(new NVInt("port", port));
        nvgm.add("transport", transport);
        if (probeName != null) nvgm.add("probe", probeName);
        if (service != null) nvgm.add("service", service);
        if (serviceFacts != null) {
            for (Map.Entry<String, String> e : serviceFacts.entrySet()) {
                nvgm.add("service-" + e.getKey(), e.getValue());
            }
        }
        if (certChainTrust != null) nvgm.add("cert-chain-trust", certChainTrust);
        if (revocationStatus != null) nvgm.add("revocation-status", revocationStatus);
        if (revocationMethod != null) nvgm.add("revocation-method", revocationMethod);
        if (supportedProtocolVersions != null && !supportedProtocolVersions.isEmpty()) {
            nvgm.add(new org.zoxweb.shared.util.NVStringList("supported-protocol-versions",
                    supportedProtocolVersions));
        }
        if (supportedCipherSuites != null && !supportedCipherSuites.isEmpty()) {
            nvgm.add(new org.zoxweb.shared.util.NVStringList("supported-cipher-suites",
                    supportedCipherSuites));
        }
        nvgm.add("tls-state", tlsState.name());
        nvgm.add("pqc-status", pqcStatus.name());
        if (tlsVersion != null) nvgm.add("tls-version", tlsVersion);
        if (cipherSuite != null) nvgm.add("cipher-suite", cipherSuite);
        if (keyExchangeGroup != null) nvgm.add("key-exchange-group", keyExchangeGroup);
        if (keyExchangeAlgorithm != null) nvgm.add("key-exchange-algorithm", keyExchangeAlgorithm);
        if (certSubject != null) nvgm.add("cert-subject", certSubject);
        if (certIssuer != null) nvgm.add("cert-issuer", certIssuer);
        if (certNotBefore != null) nvgm.add("cert-not-before", certNotBefore);
        if (certNotAfter != null) nvgm.add("cert-not-after", certNotAfter);
        if (certValidity != null) nvgm.add("cert-validity", certValidity);
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
        String version = serviceFacts.get("version");
        return "ProbeResult{" + host + ":" + port + "/" + transport
                + " service=" + service + (version != null ? " version=" + version : "")
                + " tls=" + tlsState + " pqc=" + pqcStatus
                + " complete=" + complete + (note != null ? " note=" + note : "") + "}";
    }

    public static Builder builder(String host, int port, String transport) {
        return new Builder(host, port, transport);
    }

    /**
     * Mutable accumulator the {@code record}/{@code pqc-check} actions write into
     * as the engine advances; built exactly once at terminal delivery.
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
        private String certNotBefore;
        private String certNotAfter;
        private String certValidity;
        private boolean complete = false;
        private String note;
        private long observedAtMs = System.currentTimeMillis();
        private long durationMs;
        private final List<ConnectionTrace> connections = new ArrayList<>();
        private final Map<String, String> serviceFacts = new LinkedHashMap<>();
        private String certChainTrust;
        private final List<String> supportedProtocolVersions = new ArrayList<>();
        private final List<String> supportedCipherSuites = new ArrayList<>();
        private String revocationStatus;
        private String revocationMethod;

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
        public Builder certNotBefore(String v) { this.certNotBefore = v; return this; }
        public Builder certNotAfter(String v) { this.certNotAfter = v; return this; }
        public Builder certValidity(String v) { this.certValidity = v; return this; }
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

        /**
         * Record a captured service fact (e.g. {@code version}, {@code product},
         * {@code banner}). Blank names/values are ignored; a later capture of the
         * same name overwrites.
         */
        public Builder fact(String name, String value) {
            if (name != null && !name.isEmpty() && value != null && !value.isEmpty()) {
                this.serviceFacts.put(name, value);
            }
            return this;
        }

        public Builder certChainTrust(String v) { this.certChainTrust = v; return this; }

        /** Add a server-accepted protocol version (deduped, insertion order). */
        public Builder addProtocolVersion(String v) {
            if (v != null && !v.isEmpty() && !supportedProtocolVersions.contains(v)) {
                supportedProtocolVersions.add(v);
            }
            return this;
        }

        /** Add a server-accepted cipher suite (deduped, insertion order). */
        public Builder addCipherSuite(String v) {
            if (v != null && !v.isEmpty() && !supportedCipherSuites.contains(v)) {
                supportedCipherSuites.add(v);
            }
            return this;
        }

        public Builder revocation(String status, String method) {
            this.revocationStatus = status;
            this.revocationMethod = method;
            return this;
        }

        public TlsState tlsState() { return tlsState; }

        public ProbeResult build() {
            return new ProbeResult(this);
        }
    }
}
