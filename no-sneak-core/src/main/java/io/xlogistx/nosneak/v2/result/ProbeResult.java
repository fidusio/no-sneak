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

    /**
     * One certificate of the presented chain. The aggregate verdict is
     * {@code cert-chain-trust}; this records each link so a detailed scan shows <em>which</em>
     * certificate is the problem (expired intermediate, self-signed root, …).
     */
    public static final class CertInfo {
        public final int index;
        public final String subject;
        public final String issuer;
        public final String notBefore;
        public final String notAfter;
        public final boolean timeValid;
        public final String validityState; // VALID / EXPIRED / NOT_YET_VALID
        public final boolean selfSigned;
        public final boolean ca;
        public final String role;          // leaf / intermediate / root

        public CertInfo(int index, String subject, String issuer, String notBefore, String notAfter,
                        boolean timeValid, String validityState, boolean selfSigned, boolean ca, String role) {
            this.index = index;
            this.subject = subject;
            this.issuer = issuer;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.timeValid = timeValid;
            this.validityState = validityState;
            this.selfSigned = selfSigned;
            this.ca = ca;
            this.role = role;
        }
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
    // Certificate detail (leaf key/signature analysis + RFC 6125 hostname check).
    private final String certSignatureType;
    private final String certSignatureAlgorithm;
    private final String certPublicKeyType;
    private final int certPublicKeySize;
    private final Boolean certPqcReady;
    private final Boolean certHostnameValid;
    private final String certHostnameMessage;
    // Deep-analysis facts (populated by scanner-grade actions).
    private final String certChainTrust;
    private final String certChainTrustMessage;
    private final Boolean certChainTimeValid;
    private final List<CertInfo> certChain;
    private final List<String> supportedProtocolVersions;
    private final List<String> supportedCipherSuites;
    private final List<CipherSuiteInfo> supportedCipherSuiteDetails;
    private final String serverCipherPreference;
    private final String serverCipherPreferenceMode;
    private final List<String> supportedGroups;
    private final String serverGroupPreference;
    private final String revocationStatus;
    private final String revocationMethod;
    private final String revocationDate;
    private final String revocationReason;

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
        this.certSignatureType = b.certSignatureType;
        this.certSignatureAlgorithm = b.certSignatureAlgorithm;
        this.certPublicKeyType = b.certPublicKeyType;
        this.certPublicKeySize = b.certPublicKeySize;
        this.certPqcReady = b.certPqcReady;
        this.certHostnameValid = b.certHostnameValid;
        this.certHostnameMessage = b.certHostnameMessage;
        this.certChainTrust = b.certChainTrust;
        this.certChainTrustMessage = b.certChainTrustMessage;
        this.certChainTimeValid = b.certChainTimeValid;
        this.certChain = b.certChain;
        this.supportedProtocolVersions = b.supportedProtocolVersions;
        this.supportedCipherSuites = b.supportedCipherSuites;
        this.supportedCipherSuiteDetails = b.supportedCipherSuiteDetails;
        this.serverCipherPreference = b.serverCipherPreference;
        this.serverCipherPreferenceMode = b.serverCipherPreferenceMode;
        this.supportedGroups = b.supportedGroups;
        this.serverGroupPreference = b.serverGroupPreference;
        this.revocationStatus = b.revocationStatus;
        this.revocationMethod = b.revocationMethod;
        this.revocationDate = b.revocationDate;
        this.revocationReason = b.revocationReason;
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
    /** Human-readable PKIX detail behind {@link #getCertChainTrust()}, or {@code null}. */
    public String getCertChainTrustMessage() { return certChainTrustMessage; }
    public String getCertValidity() { return certValidity; }
    public String getCertNotBefore() { return certNotBefore; }
    public String getCertNotAfter() { return certNotAfter; }

    /**
     * Whether every certificate in the chain (intermediates and root included) is within its
     * validity window; {@code null} when the chain was not examined.
     */
    public Boolean getCertChainTimeValid() { return certChainTimeValid; }

    /** RFC 6125 hostname match of the leaf against the scanned host; {@code null} if unchecked. */
    public Boolean getCertHostnameValid() { return certHostnameValid; }
    /** Detail / presented names behind {@link #getCertHostnameValid()}, or {@code null}. */
    public String getCertHostnameMessage() { return certHostnameMessage; }

    /** The presented chain, leaf first, with the resolved root appended when trusted. */
    public List<CertInfo> getCertChain() { return certChain; }

    /** Leaf signature classification (e.g. RSA / ECDSA / ML-DSA), or {@code null}. */
    public String getCertSignatureType() { return certSignatureType; }
    public String getCertSignatureAlgorithm() { return certSignatureAlgorithm; }
    public String getCertPublicKeyType() { return certPublicKeyType; }
    public int getCertPublicKeySize() { return certPublicKeySize; }
    /** Whether the leaf uses a post-quantum signature algorithm; {@code null} if unknown. */
    public Boolean getCertPqcReady() { return certPqcReady; }

    /** Server-accepted protocol versions from enumeration, or an empty list. */
    public List<String> getSupportedProtocolVersions() { return supportedProtocolVersions; }

    /** Server-accepted cipher suites from enumeration, or an empty list. */
    public List<String> getSupportedCipherSuites() { return supportedCipherSuites; }

    /** Certificate revocation status (GOOD / REVOKED / UNKNOWN / …), or {@code null}. */
    public String getRevocationStatus() { return revocationStatus; }

    /** How revocation was established: {@code stapled}, {@code ocsp}, {@code crl}, {@code none}, or {@code <method>-unreachable}. */
    public String getRevocationMethod() { return revocationMethod; }

    /** ISO-8601 revocation instant when the status is REVOKED and the responder/CRL gave one. */
    public String getRevocationDate() { return revocationDate; }

    /** RFC 5280 CRLReason name when the status is REVOKED (UNSPECIFIED when none was given). */
    public String getRevocationReason() { return revocationReason; }

    /** Accepted suites with their version, strength, key exchange and forward secrecy; empty when not enumerated. */
    public List<CipherSuiteInfo> getSupportedCipherSuiteDetails() { return supportedCipherSuiteDetails; }

    /** The suite the server picked when offered every accepted suite at once, or {@code null}. */
    public String getServerCipherPreference() { return serverCipherPreference; }

    /** {@code server} when the pick did not change with the client's order, {@code client} when it did, {@code only-one-accepted} when there was nothing to compare. */
    public String getServerCipherPreferenceMode() { return serverCipherPreferenceMode; }

    /** TLS 1.3 named groups the server completed a handshake on (best first), or an empty list. */
    public List<String> getSupportedGroups() { return supportedGroups; }

    /** The group the server chose when the main handshake offered them all, or {@code null}. */
    public String getServerGroupPreference() { return serverGroupPreference; }

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
        if (certChainTrustMessage != null) nvgm.add("cert-chain-trust-message", certChainTrustMessage);
        // Tri-state facts are emitted as explicit strings, NOT booleans: the framework's JSON
        // serializer omits default values, so a `false` boolean would vanish and be
        // indistinguishable from "not checked" — exactly the distinction these facts carry.
        if (certChainTimeValid != null) {
            nvgm.add("cert-chain-time-validity", certChainTimeValid ? "VALID" : "INVALID");
        }
        if (certHostnameValid != null) {
            nvgm.add("cert-hostname-match", certHostnameValid ? "MATCH" : "MISMATCH");
        }
        if (certHostnameMessage != null) nvgm.add("cert-hostname-message", certHostnameMessage);
        if (revocationStatus != null) nvgm.add("revocation-status", revocationStatus);
        if (revocationMethod != null) nvgm.add("revocation-method", revocationMethod);
        if (revocationDate != null) nvgm.add("revocation-date", revocationDate);
        if (revocationReason != null) nvgm.add("revocation-reason", revocationReason);
        if (supportedProtocolVersions != null && !supportedProtocolVersions.isEmpty()) {
            nvgm.add(new org.zoxweb.shared.util.NVStringList("supported-protocol-versions",
                    supportedProtocolVersions));
        }
        if (supportedCipherSuites != null && !supportedCipherSuites.isEmpty()) {
            nvgm.add(new org.zoxweb.shared.util.NVStringList("supported-cipher-suites",
                    supportedCipherSuites));
        }
        if (supportedCipherSuiteDetails != null && !supportedCipherSuiteDetails.isEmpty()) {
            NVGenericMapList suites = new NVGenericMapList("supported-cipher-suite-details");
            for (CipherSuiteInfo s : supportedCipherSuiteDetails) {
                NVGenericMap sm = new NVGenericMap();
                sm.add("name", s.name);
                if (s.version != null) sm.add("version", s.version);
                if (s.strength != null) sm.add("strength", s.strength);
                if (s.keyExchange != null) sm.add("key-exchange", s.keyExchange);
                // String, not NVBoolean: a `false` boolean vanishes from the JSON (see above).
                sm.add("forward-secrecy", s.forwardSecrecy ? "YES" : "NO");
                suites.add(sm);
            }
            nvgm.add(suites);
        }
        if (serverCipherPreference != null) nvgm.add("server-cipher-preference", serverCipherPreference);
        if (serverCipherPreferenceMode != null) nvgm.add("server-cipher-preference-mode", serverCipherPreferenceMode);
        if (supportedGroups != null && !supportedGroups.isEmpty()) {
            nvgm.add(new org.zoxweb.shared.util.NVStringList("supported-groups", supportedGroups));
        }
        if (serverGroupPreference != null) nvgm.add("server-group-preference", serverGroupPreference);
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
        if (certSignatureType != null) nvgm.add("cert-signature-type", certSignatureType);
        if (certSignatureAlgorithm != null) nvgm.add("cert-signature-algorithm", certSignatureAlgorithm);
        if (certPublicKeyType != null) nvgm.add("cert-public-key-type", certPublicKeyType);
        if (certPublicKeySize > 0) nvgm.add(new NVInt("cert-public-key-size", certPublicKeySize));
        if (certPqcReady != null) nvgm.add("cert-signature-pqc", certPqcReady ? "PQC" : "CLASSICAL");
        if (certChain != null && !certChain.isEmpty()) {
            NVGenericMapList chainList = new NVGenericMapList("cert-chain");
            for (CertInfo c : certChain) {
                NVGenericMap cm = new NVGenericMap();
                cm.add(new NVInt("index", c.index));
                if (c.subject != null) cm.add("subject", c.subject);
                if (c.issuer != null) cm.add("issuer", c.issuer);
                if (c.notBefore != null) cm.add("not-before", c.notBefore);
                if (c.notAfter != null) cm.add("not-after", c.notAfter);
                cm.add(new NVBoolean("time-valid", c.timeValid));
                if (!c.timeValid && c.validityState != null) cm.add("validity-state", c.validityState);
                cm.add(new NVBoolean("self-signed", c.selfSigned));
                cm.add(new NVBoolean("is-ca", c.ca));
                if (c.role != null) cm.add("role", c.role);
                chainList.add(cm);
            }
            nvgm.add(chainList);
        }
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

    /** One server-accepted cipher suite, as observed by {@code enumerate-ciphers}. Facts only. */
    public static final class CipherSuiteInfo {
        public final String name;
        /** The protocol version it was accepted at ({@code TLSv1.3} / {@code TLSv1.2}). */
        public final String version;
        /** {@code STRONG} / {@code ACCEPTABLE} / {@code WEAK} / {@code INSECURE} / {@code UNKNOWN} (opsec's classification). */
        public final String strength;
        /** {@code ECDHE} / {@code DHE} / {@code RSA} / … from the suite name; {@code ECDHE/DHE} for TLS 1.3. */
        public final String keyExchange;
        public final boolean forwardSecrecy;

        public CipherSuiteInfo(String name, String version, String strength, String keyExchange,
                               boolean forwardSecrecy) {
            this.name = name;
            this.version = version;
            this.strength = strength;
            this.keyExchange = keyExchange;
            this.forwardSecrecy = forwardSecrecy;
        }

        @Override
        public String toString() {
            return name + "[" + version + " " + strength + " " + keyExchange + (forwardSecrecy ? " FS" : "") + "]";
        }
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
        private String certSignatureType;
        private String certSignatureAlgorithm;
        private String certPublicKeyType;
        private int certPublicKeySize;
        private Boolean certPqcReady;
        private Boolean certHostnameValid;
        private String certHostnameMessage;
        private String certChainTrust;
        private String certChainTrustMessage;
        private Boolean certChainTimeValid;
        private final List<CertInfo> certChain = new ArrayList<>();
        private final List<String> supportedProtocolVersions = new ArrayList<>();
        private final List<String> supportedCipherSuites = new ArrayList<>();
        private final List<CipherSuiteInfo> supportedCipherSuiteDetails = new ArrayList<>();
        private String serverCipherPreference;
        private String serverCipherPreferenceMode;
        private final List<String> supportedGroups = new ArrayList<>();
        private String serverGroupPreference;
        private String revocationStatus;
        private String revocationMethod;
        private String revocationDate;
        private String revocationReason;

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
        public Builder certChainTrust(String v, String message) {
            this.certChainTrust = v;
            this.certChainTrustMessage = message;
            return this;
        }
        public Builder certChainTimeValid(Boolean v) { this.certChainTimeValid = v; return this; }

        /** Leaf key/signature analysis (from {@code OPSecUtil.analyzeCertificatePQC}). */
        public Builder certKeyAnalysis(String sigType, String sigAlg, String pubKeyType,
                                       int pubKeySize, Boolean pqcReady) {
            this.certSignatureType = sigType;
            this.certSignatureAlgorithm = sigAlg;
            this.certPublicKeyType = pubKeyType;
            this.certPublicKeySize = pubKeySize;
            this.certPqcReady = pqcReady;
            return this;
        }

        /** RFC 6125 hostname check result (report-only — never a trust failure on its own). */
        public Builder certHostname(boolean matched, String message) {
            this.certHostnameValid = matched;
            this.certHostnameMessage = message;
            return this;
        }

        /** Append one certificate of the presented chain (leaf first). */
        public Builder addCert(CertInfo info) {
            if (info != null) {
                this.certChain.add(info);
            }
            return this;
        }

        /** Replace any previously recorded chain (a re-run of {@code cert-chain-validate}). */
        public Builder clearCertChain() {
            this.certChain.clear();
            return this;
        }

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

        /**
         * Add a server-accepted cipher suite with its observed version and opsec's strength
         * classification. Keeps the flat name list in step (deduped, insertion order).
         */
        public Builder addCipherSuite(String name, String version, String strength, String keyExchange,
                                      boolean forwardSecrecy) {
            if (name == null || name.isEmpty()) {
                return this;
            }
            addCipherSuite(name);
            for (CipherSuiteInfo existing : supportedCipherSuiteDetails) {
                if (existing.name.equals(name) && java.util.Objects.equals(existing.version, version)) {
                    return this;
                }
            }
            supportedCipherSuiteDetails.add(new CipherSuiteInfo(name, version, strength, keyExchange, forwardSecrecy));
            return this;
        }

        /** The suite the server picked when offered every accepted suite, and whether its order or ours decided it. */
        public Builder serverCipherPreference(String suite, String mode) {
            this.serverCipherPreference = suite;
            this.serverCipherPreferenceMode = mode;
            return this;
        }

        /** Add a TLS 1.3 named group the server completed a handshake on (deduped, insertion order). */
        public Builder addSupportedGroup(String group) {
            if (group != null && !group.isEmpty() && !supportedGroups.contains(group)) {
                supportedGroups.add(group);
            }
            return this;
        }

        public Builder serverGroupPreference(String group) {
            this.serverGroupPreference = group;
            return this;
        }

        public Builder revocation(String status, String method) {
            return revocation(status, method, null, null);
        }

        /** Revocation status with the date and reason a responder or CRL supplied (both nullable). */
        public Builder revocation(String status, String method, String date, String reason) {
            this.revocationStatus = status;
            this.revocationMethod = method;
            this.revocationDate = date;
            this.revocationReason = reason;
            return this;
        }

        public TlsState tlsState() { return tlsState; }

        public ProbeResult build() {
            return new ProbeResult(this);
        }
    }
}
