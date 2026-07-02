package io.xlogistx.nosneak.scanners;

import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.util.*;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of a PQC (Post-Quantum Cryptography) scan against a TLS server.
 * Captures key exchange, certificate, and TLS version information to assess PQC readiness.
 */
public class PQCScanResult implements Identifier<String> {

    /**
     * Overall PQC readiness status
     */
    public enum PQCStatus {
        /**
         * TLS 1.3 + PQC hybrid key exchange (fully PQC ready)
         */
        READY,
        /**
         * TLS 1.3 + classical ECDHE (can upgrade key exchange)
         */
        PARTIAL,
        /**
         * TLS 1.2 or below, or weak algorithms
         */
        NOT_READY,
        /**
         * Certificate trust failure (expired/not-yet-valid leaf, chain not
         * anchored to a trusted Root CA, or revoked). Outranks READY/PARTIAL/
         * NOT_READY: a connection that cannot be trusted is reported as such
         * regardless of its PQC readiness. Distinct from {@link #ERROR}
         * (which is a scan/connection failure, not a cert verdict).
         */
        UNTRUSTED,
        /**
         * Scan failed or could not connect
         */
        ERROR
    }

    /**
     * Leaf certificate time-validity state.
     */
    public enum CertValidityState {
        VALID,
        EXPIRED,
        NOT_YET_VALID
    }

    /**
     * Concise, backend-computed certificate trust verdict. A single
     * authoritative value the UI can render directly instead of re-deriving
     * trust from several keys. {@code TRUSTED} = chain PKIX-anchored and no
     * trust failure; the rest mirror the conditions that force
     * {@link PQCStatus#UNTRUSTED}; {@code UNKNOWN} = couldn't determine.
     */
    public enum TrustVerdict {
        TRUSTED,
        EXPIRED,
        NOT_YET_VALID,
        UNTRUSTED_CHAIN,
        CHAIN_TIME_INVALID,
        REVOKED,
        UNKNOWN
    }

    /**
     * Key exchange type classification
     */
    public enum KeyExchangeType {
        /**
         * PQC hybrid: ML-KEM combined with classical (X25519MLKEM768, SecP256r1MLKEM768)
         */
        PQC_HYBRID,
        /**
         * Classical elliptic curve: secp256r1, secp384r1, x25519, x448
         */
        ECDHE,
        /**
         * Classical finite field Diffie-Hellman
         */
        DHE,
        /**
         * RSA key exchange (no forward secrecy)
         */
        RSA,
        /**
         * Unknown or could not determine
         */
        UNKNOWN
    }

    /**
     * Certificate signature type classification
     */
    public enum SignatureType {
        /**
         * PQC signature: ML-DSA (Dilithium)
         */
        PQC_SIGNATURE,
        /**
         * Classical ECDSA
         */
        ECDSA,
        /**
         * Classical RSA
         */
        RSA,
        /**
         * EdDSA (Ed25519, Ed448)
         */
        EDDSA,
        /**
         * Unknown or could not determine
         */
        UNKNOWN
    }

    // Connection info
    private String host;
    private int port;
    protected long scanTimeMs;
    private boolean success;
    private boolean secure;  // true if TLS/SSL encryption detected
    private String errorMessage;

    // TLS version
    private String tlsVersion;
    private boolean tlsVersionPqcCapable; // TLS 1.3+ required for PQC

    // Key exchange
    private KeyExchangeType keyExchangeType;
    private String keyExchangeAlgorithm; // e.g., "X25519MLKEM768", "secp256r1"
    private int keyExchangeKeySize;
    private boolean keyExchangePqcReady;

    // Cipher suite
    private String cipherSuite;
    private String scanID;
    public  long scanCount;

    // Certificate info
    private SignatureType certSignatureType;
    private String certSignatureAlgorithm; // e.g., "SHA256withECDSA", "ML-DSA-65"
    private String certPublicKeyType; // e.g., "EC", "RSA", "ML-DSA"
    private int certPublicKeySize;
    private boolean certPqcReady;
    private X509Certificate[] certificateChain;

    // Certificate validity
    private long certNotBefore;      // Timestamp when certificate becomes valid
    private long certNotAfter;       // Timestamp when certificate expires
    private boolean certTimeValid;   // Whether current time is within validity period (leaf)
    private CertValidityState certValidityState; // VALID / EXPIRED / NOT_YET_VALID (leaf)
    private Boolean certChainTimeValid; // null=unknown; false=an intermediate/root is expired/not-yet-valid
    private Boolean certChainValid;  // null=not checked, true=chain anchors to trusted Root CA, false=not
    private String certChainTrust;   // OPSecUtil.ChainTrust name (TRUSTED/UNTRUSTED_ROOT/...)
    private String certChainTrustMessage; // human-readable PKIX detail
    private Boolean certHostnameValid; // null=not checked; RFC6125 match of leaf vs scanned host (report-only)
    private String certHostnameMessage; // detail / presented names when mismatched
    private Boolean certRevoked;     // null=not checked, true=revoked, false=not revoked
    private String certSubject;      // Certificate subject DN
    private String certIssuer;       // Certificate issuer DN

    // Concise backend-computed trust summary (set in Builder.build())
    private TrustVerdict trustVerdict;
    private String trustReason;

    // Revocation details
    private String revocationMethod;      // "OCSP", "CRL", or "NONE"
    private String revocationError;       // Error message if revocation check failed
    private Long revocationDate;          // Timestamp when certificate was revoked (if revoked)
    private String revocationReason;      // CRL reason code (e.g., "KEY_COMPROMISE")

    // Cipher suite enumeration results
    private List<CipherSuiteEnumerator.CipherInfo> supportedCipherSuites;
    private Boolean serverCipherPreference;

    // Protocol version testing results
    private List<String> supportedProtocolVersions;
    private boolean sslv3Supported;
    private boolean deprecatedProtocolsSupported;

    // Overall status
    private PQCStatus overallStatus;
    private List<String> recommendations;

    public PQCScanResult() {
        this.recommendations = new ArrayList<>();
    }

    // Builder pattern for cleaner construction
    public static Builder builder(String host, int port, String scanID) {
        return new Builder(host, port, scanID);
    }

    public static Builder builder(InetSocketAddress socketAddress, String scanID) {
        return new Builder(socketAddress.getHostName(), socketAddress.getPort(), scanID);
    }

    // Getters
    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public long getScanTimeMs() {
        return scanTimeMs;
    }

    public boolean isSuccess() {
        return success;
    }

    public boolean isSecure() {
        return secure;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public boolean isTlsVersionPqcCapable() {
        return tlsVersionPqcCapable;
    }

    public KeyExchangeType getKeyExchangeType() {
        return keyExchangeType;
    }

    public String getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }

    public int getKeyExchangeKeySize() {
        return keyExchangeKeySize;
    }

    public boolean isKeyExchangePqcReady() {
        return keyExchangePqcReady;
    }

    public String getCipherSuite() {
        return cipherSuite;
    }

    public SignatureType getCertSignatureType() {
        return certSignatureType;
    }

    public String getCertSignatureAlgorithm() {
        return certSignatureAlgorithm;
    }

    public String getCertPublicKeyType() {
        return certPublicKeyType;
    }

    public int getCertPublicKeySize() {
        return certPublicKeySize;
    }

    public boolean isCertPqcReady() {
        return certPqcReady;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    public long getCertNotBefore() {
        return certNotBefore;
    }

    public long getCertNotAfter() {
        return certNotAfter;
    }

    public boolean isCertTimeValid() {
        return certTimeValid;
    }

    public CertValidityState getCertValidityState() {
        return certValidityState;
    }

    public Boolean isCertChainTimeValid() {
        return certChainTimeValid;
    }

    public Boolean isCertChainValid() {
        return certChainValid;
    }

    public String getCertChainTrust() {
        return certChainTrust;
    }

    public String getCertChainTrustMessage() {
        return certChainTrustMessage;
    }

    public Boolean isCertHostnameValid() {
        return certHostnameValid;
    }

    public String getCertHostnameMessage() {
        return certHostnameMessage;
    }

    public TrustVerdict getTrustVerdict() {
        return trustVerdict;
    }

    public String getTrustReason() {
        return trustReason;
    }

    public Boolean isCertRevoked() {
        return certRevoked;
    }

    public String getCertSubject() {
        return certSubject;
    }

    public String getCertIssuer() {
        return certIssuer;
    }

    public String getRevocationMethod() {
        return revocationMethod;
    }

    public String getRevocationError() {
        return revocationError;
    }

    public Long getRevocationDate() {
        return revocationDate;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public List<CipherSuiteEnumerator.CipherInfo> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    public Boolean getServerCipherPreference() {
        return serverCipherPreference;
    }

    public List<String> getSupportedProtocolVersions() {
        return supportedProtocolVersions;
    }

    public boolean isSslv3Supported() {
        return sslv3Supported;
    }

    public boolean isDeprecatedProtocolsSupported() {
        return deprecatedProtocolsSupported;
    }

    public PQCStatus getOverallStatus() {
        return overallStatus;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    /**
     * Get the unique identifier for this scan result.
     * Format: host:port (e.g., "google.com:443")
     *
     * @return the identifier string
     */
    @Override
    public String getID() {
        return scanID;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PQCScanResult{\n");
        sb.append("  host='").append(host).append(':').append(port).append("'\n");
        sb.append("  id='").append(getID()).append("'\n");
        sb.append("  success=").append(success);
        sb.append(", secure=").append(secure);
        if (!success && errorMessage != null) {
            sb.append(", error='").append(errorMessage).append("'");
        }
        sb.append("\n");

        if (success) {
            sb.append("  tlsVersion='").append(tlsVersion).append("' (PQC capable: ").append(tlsVersionPqcCapable).append(")\n");
            sb.append("  keyExchange=").append(keyExchangeType).append(" (").append(keyExchangeAlgorithm).append(")\n");
            sb.append("  keyExchangePqcReady=").append(keyExchangePqcReady).append("\n");
            sb.append("  cipherSuite='").append(cipherSuite).append("'\n");
            sb.append("  certSignature=").append(certSignatureType).append(" (").append(certSignatureAlgorithm).append(")\n");
            sb.append("  certPublicKey=").append(certPublicKeyType).append(" (").append(certPublicKeySize).append(" bits)\n");
            sb.append("  certPqcReady=").append(certPqcReady).append("\n");
            // Certificate validity info
            if (certSubject != null) {
                sb.append("  certSubject='").append(certSubject).append("'\n");
            }
            if (certIssuer != null) {
                sb.append("  certIssuer='").append(certIssuer).append("'\n");
            }
            if (certNotBefore > 0) {
                sb.append("  certNotBefore=").append(new java.util.Date(certNotBefore)).append("\n");
                sb.append("  certNotAfter=").append(new java.util.Date(certNotAfter)).append("\n");
                sb.append("  certTimeValid=").append(certTimeValid)
                        .append(certValidityState != null ? " (" + certValidityState + ")" : "").append("\n");
            }
            if (certChainTimeValid != null) {
                sb.append("  certChainTimeValid=").append(certChainTimeValid).append("\n");
            }
            if (certChainValid != null) {
                sb.append("  certChainValid=").append(certChainValid)
                        .append(certChainTrust != null ? " [" + certChainTrust + "]" : "")
                        .append(certChainTrustMessage != null ? " " + certChainTrustMessage : "").append("\n");
            }
            if (certHostnameValid != null) {
                sb.append("  certHostnameValid=").append(certHostnameValid)
                        .append(certHostnameMessage != null ? " (" + certHostnameMessage + ")" : "").append("\n");
            }
            if (certRevoked != null) {
                sb.append("  certRevoked=").append(certRevoked).append("\n");
            }
            // Revocation details
            if (revocationMethod != null) {
                sb.append("  revocationMethod=").append(revocationMethod).append("\n");
            }
            if (revocationError != null) {
                sb.append("  revocationError='").append(revocationError).append("'\n");
            }
            if (revocationDate != null) {
                sb.append("  revocationDate=").append(new java.util.Date(revocationDate)).append("\n");
            }
            if (revocationReason != null) {
                sb.append("  revocationReason=").append(revocationReason).append("\n");
            }
            // Cipher suite enumeration
            if (supportedCipherSuites != null && !supportedCipherSuites.isEmpty()) {
                sb.append("  supportedCipherSuites=[").append(supportedCipherSuites.size()).append(" ciphers]\n");
                if (serverCipherPreference != null) {
                    sb.append("  serverCipherPreference=").append(serverCipherPreference).append("\n");
                }
            }
            // Protocol version testing
            if (supportedProtocolVersions != null && !supportedProtocolVersions.isEmpty()) {
                sb.append("  supportedProtocolVersions=").append(supportedProtocolVersions).append("\n");
                sb.append("  sslv3Supported=").append(sslv3Supported).append("\n");
                sb.append("  deprecatedProtocolsSupported=").append(deprecatedProtocolsSupported).append("\n");
            }
            if (trustVerdict != null) {
                sb.append("  trustVerdict=").append(trustVerdict)
                        .append(trustReason != null ? " (" + trustReason + ")" : "").append("\n");
            }
            sb.append("  overallStatus=").append(overallStatus).append("\n");
            if (!recommendations.isEmpty()) {
                sb.append("  recommendations=[\n");
                for (String rec : recommendations) {
                    sb.append("    - ").append(rec).append("\n");
                }
                sb.append("  ]\n");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert this result to an NVGenericMap for serialization or API responses.
     *
     * @return NVGenericMap containing all scan result data
     */
    public NVGenericMap toNVGenericMap(boolean eAsS) {
        NVGenericMap nvgm = new NVGenericMap("PQCScanResult");

        // Connection info
        nvgm.add("host", host);
        nvgm.add(new NVInt("port", port));
        nvgm.build("scan-id", getID());
        nvgm.build(new NVLong("total-scanned", scanCount));
        nvgm.add(new NVLong("scan-time-in-ms", scanTimeMs));
        nvgm.add(new NVBoolean("success", success));

        if (eAsS)
            nvgm.add(new NVPair("secure", isSecure() ? Const.Bool.YES.getName() : Const.Bool.NO.getName()));
        else
            nvgm.add(new NVBoolean("secure", isSecure()));


        if (errorMessage != null) {
            nvgm.add("error-message", errorMessage);
        }

        // TLS version
        if (tlsVersion != null) {
            nvgm.add("tls-version", tlsVersion);
        }
        nvgm.add(new NVBoolean("tls-version-pqc-capable", tlsVersionPqcCapable));

        // Key exchange
        if (keyExchangeType != null) {
            if (eAsS)
                nvgm.add("key-exchange-type", keyExchangeType.name());
            else
                nvgm.add(new NVEnum("key-exchange-type", keyExchangeType));
        }
        if (keyExchangeAlgorithm != null) {
            nvgm.add("key-exchange-algorithm", keyExchangeAlgorithm);
        }
        if (keyExchangeKeySize > 0) {
            nvgm.add(new NVInt("key-exchange-key-size", keyExchangeKeySize));
        }
        nvgm.add(new NVBoolean("key-exchange-pqc-ready", keyExchangePqcReady));

        // Cipher suite
        if (cipherSuite != null) {
            nvgm.add("cipher-suite", cipherSuite);
        }

        // Certificate info
        if (certSignatureType != null) {
            if (eAsS)
                nvgm.add("cert-signature-type", certSignatureType.name());
            else
                nvgm.add(new NVEnum("cert-signature-type", certSignatureType));
        }
        if (certSignatureAlgorithm != null) {
            nvgm.add("cert-signature-algorithm", certSignatureAlgorithm);
        }
        if (certPublicKeyType != null) {
            nvgm.add("cert-public-key-type", certPublicKeyType);
        }
        if (certPublicKeySize > 0) {
            nvgm.add(new NVInt("cert-public-key-size", certPublicKeySize));
        }
        nvgm.add(new NVBoolean("cert-pqc-ready", certPqcReady));

        // Certificate validity
        if (certNotBefore > 0) {
            nvgm.add(new NVPair("cert-not-before", DateUtil.DEFAULT_GMT_MILLIS.format(certNotBefore)));
        }
        if (certNotAfter > 0) {
            nvgm.add(new NVPair("cert-not-after", DateUtil.DEFAULT_GMT_MILLIS.format(certNotAfter)));
        }
        nvgm.add(new NVBoolean("cert-time-valid", certTimeValid));
        if (certValidityState != null) {
            nvgm.add("cert-validity-state", certValidityState.name());
        }
        if (certChainTimeValid != null) {
            nvgm.add(new NVBoolean("cert-chain-time-valid", certChainTimeValid));
        }
        if (certChainValid != null) {
            nvgm.add(new NVBoolean("cert-chain-valid", certChainValid));
        }
        if (certChainTrust != null) {
            nvgm.add("cert-chain-trust", certChainTrust);
        }
        if (certChainTrustMessage != null) {
            nvgm.add("cert-chain-trust-message", certChainTrustMessage);
        }
        if (certHostnameValid != null) {
            nvgm.add(new NVBoolean("cert-hostname-valid", certHostnameValid));
        }
        if (certHostnameMessage != null) {
            nvgm.add("cert-hostname-message", certHostnameMessage);
        }
        if (certRevoked != null) {
            nvgm.add(new NVBoolean("cert-revoked", certRevoked));
        }
        if (certSubject != null) {
            nvgm.add("cert-subject", certSubject);
        }
        if (certIssuer != null) {
            nvgm.add("cert-issuer", certIssuer);
        }

        // Per-certificate chain breakdown (leaf -> ... -> root as sent by the
        // server). The aggregate verdict is cert-chain-valid/cert-chain-trust;
        // this lists each link so a detailed scan shows WHICH cert is the
        // problem (expired intermediate, self-signed root, etc.).
        if (certificateChain != null && certificateChain.length > 0) {
            long now = System.currentTimeMillis();
            NVGenericMapList chainList = new NVGenericMapList("cert-chain");
            for (int i = 0; i < certificateChain.length; i++) {
                X509Certificate c = certificateChain[i];
                NVGenericMap cm = new NVGenericMap();
                cm.add(new NVInt("index", i));
                cm.add("subject", c.getSubjectX500Principal().getName());
                cm.add("issuer", c.getIssuerX500Principal().getName());
                long nb = c.getNotBefore().getTime();
                long na = c.getNotAfter().getTime();
                cm.add(new NVPair("not-before", DateUtil.DEFAULT_GMT_MILLIS.format(nb)));
                cm.add(new NVPair("not-after", DateUtil.DEFAULT_GMT_MILLIS.format(na)));
                boolean timeValid = now >= nb && now <= na;
                cm.add(new NVBoolean("time-valid", timeValid));
                if (!timeValid) {
                    cm.add("validity-state", now < nb ? "NOT_YET_VALID" : "EXPIRED");
                }
                cm.add(new NVBoolean("self-signed",
                        c.getSubjectX500Principal().equals(c.getIssuerX500Principal())));
                cm.add(new NVBoolean("is-ca", c.getBasicConstraints() != -1));
                cm.add("role", i == 0 ? "leaf"
                        : (c.getSubjectX500Principal().equals(c.getIssuerX500Principal()) ? "root" : "intermediate"));
                chainList.add(cm);
            }
            nvgm.add(chainList);
        }

        // Revocation details
        if (revocationMethod != null) {
            nvgm.add("revocation-method", revocationMethod);
        }
        if (revocationError != null) {
            nvgm.add("revocation-error", revocationError);
        }
        if (revocationDate != null) {
            nvgm.add(new NVPair("revocation-date", DateUtil.DEFAULT_GMT_MILLIS.format(revocationDate)));
        }
        if (revocationReason != null) {
            nvgm.add("revocation-reason", revocationReason);
        }

        // Cipher suite enumeration
        if (supportedCipherSuites != null && !supportedCipherSuites.isEmpty()) {
            NVGenericMapList ciphersList = new NVGenericMapList("supported-cipher-suites");
            for (CipherSuiteEnumerator.CipherInfo cipher : supportedCipherSuites) {
                NVGenericMap cipherMap = new NVGenericMap();
                cipherMap.add("name", cipher.getName());
                cipherMap.add("strength", cipher.getStrength().name());
                cipherMap.add("key-exchange", cipher.getKeyExchange());
                cipherMap.add(new NVBoolean("forward-secrecy", cipher.hasForwardSecrecy()));
                ciphersList.add(cipherMap);
            }
            nvgm.add(ciphersList);
        }
        if (serverCipherPreference != null) {
            nvgm.add(new NVBoolean("server-cipher-preference", serverCipherPreference));
        }

        // Protocol version testing
        if (supportedProtocolVersions != null && !supportedProtocolVersions.isEmpty()) {
            nvgm.add(new NVStringList("supported-protocol-versions", supportedProtocolVersions));
        }
        nvgm.add(new NVBoolean("sslv3-supported", sslv3Supported));
        nvgm.add(new NVBoolean("deprecated-protocols-supported", deprecatedProtocolsSupported));

        // Concise trust summary (single authoritative verdict for the UI)
        if (trustVerdict != null) {
            if (eAsS)
                nvgm.add("trust-verdict", trustVerdict.name());
            else
                nvgm.add(new NVEnum("trust-verdict", trustVerdict));
        }
        if (trustReason != null) {
            nvgm.add("trust-reason", trustReason);
        }

        // Overall status
        if (overallStatus != null) {
            if (eAsS)
                nvgm.add("overall-status", overallStatus.name());
            else
                nvgm.add(new NVEnum("overall-status", overallStatus));
        }

        // Recommendations as a nested NVGenericMap with meaningful keys
        if (recommendations != null && !recommendations.isEmpty()) {
            NVGenericMap recsMap = new NVGenericMap("recommendations");
            for (String rec : recommendations) {
                String key = deriveRecommendationKey(rec);
                recsMap.add(key, rec);
            }
            nvgm.add(recsMap);
        }

        return nvgm;
    }

    /**
     * Derive a meaningful key name from the recommendation text.
     */
    private String deriveRecommendationKey(String recommendation) {
        if (recommendation.contains("TLS 1.3")) {
            return "upgrade-tls-version";
        } else if (recommendation.contains("PQC hybrid key exchange")) {
            return "enable-pqc-key-exchange";
        } else if (recommendation.contains("PQC certificates")) {
            return "upgrade-to-pqc-certificate";
        }
        return "recommendation";
    }

    /**
     * Builder for PQCScanResult
     */
    public static class Builder {
        private final PQCScanResult result;

        public Builder(String host, int port, String scanID) {
            result = new PQCScanResult();
            result.host = host;
            result.port = port;
            result.scanID = scanID;
        }

        public Builder scanTimeMs(long scanTimeMs) {
            result.scanTimeMs = scanTimeMs;
            return this;
        }

        public Builder success(boolean success) {
            result.success = success;
            result.secure = success;  // TLS handshake success means port is secure
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            result.errorMessage = errorMessage;
            result.success = false;
            result.secure = false;
            result.overallStatus = PQCStatus.ERROR;
            return this;
        }

        public Builder tlsVersion(String tlsVersion) {
            result.tlsVersion = tlsVersion;
            result.tlsVersionPqcCapable = "TLSv1.3".equals(tlsVersion) || "TLS 1.3".equals(tlsVersion);
            return this;
        }

        public Builder keyExchange(KeyExchangeType type, String algorithm) {
            result.keyExchangeType = type;
            result.keyExchangeAlgorithm = algorithm;
            result.keyExchangePqcReady = (type == KeyExchangeType.PQC_HYBRID);
            return this;
        }

        public Builder keyExchangeKeySize(int keySize) {
            result.keyExchangeKeySize = keySize;
            return this;
        }

        public Builder cipherSuite(String cipherSuite) {
            result.cipherSuite = cipherSuite;
            return this;
        }

        public Builder certSignature(SignatureType type, String algorithm) {
            result.certSignatureType = type;
            result.certSignatureAlgorithm = algorithm;
            return this;
        }

        public Builder certPublicKey(String type, int keySize) {
            result.certPublicKeyType = type;
            result.certPublicKeySize = keySize;
            result.certPqcReady = type != null &&
                    (type.toUpperCase().contains("DILITHIUM") ||
                            type.toUpperCase().contains("ML-DSA") ||
                            type.toUpperCase().contains("FALCON") ||
                            type.toUpperCase().contains("SPHINCS"));
            return this;
        }

        public Builder certificateChain(X509Certificate[] chain) {
            result.certificateChain = chain;
            return this;
        }

        /**
         * Set certificate validity information from the leaf certificate.
         * Automatically extracts notBefore, notAfter, subject, issuer and validates time.
         *
         * @param cert the leaf certificate
         * @return this builder
         */
        public Builder certValidity(X509Certificate cert) {
            if (cert != null) {
                result.certNotBefore = cert.getNotBefore().getTime();
                result.certNotAfter = cert.getNotAfter().getTime();
                result.certSubject = cert.getSubjectX500Principal().getName();
                result.certIssuer = cert.getIssuerX500Principal().getName();

                // Check if certificate is currently valid (time-wise) and
                // distinguish EXPIRED vs NOT_YET_VALID.
                long now = System.currentTimeMillis();
                if (now < result.certNotBefore) {
                    result.certValidityState = CertValidityState.NOT_YET_VALID;
                    result.certTimeValid = false;
                } else if (now > result.certNotAfter) {
                    result.certValidityState = CertValidityState.EXPIRED;
                    result.certTimeValid = false;
                } else {
                    result.certValidityState = CertValidityState.VALID;
                    result.certTimeValid = true;
                }
            }
            return this;
        }

        /**
         * Record the PKIX trust outcome of validating the chain to a trusted
         * Root CA (see {@code OPSecUtil.validateChain}). Sets the legacy
         * {@code certChainValid} boolean for compatibility.
         *
         * @param trust        ChainTrust enum name (e.g. "TRUSTED")
         * @param trusted      true iff anchored to a trusted root
         * @param message      human-readable PKIX detail (nullable)
         */
        public Builder certChainTrust(String trust, boolean trusted, String message) {
            result.certChainTrust = trust;
            result.certChainTrustMessage = message;
            result.certChainValid = trusted;
            return this;
        }

        /**
         * Whether every cert in the chain is currently within its validity
         * window (null = unknown).
         */
        public Builder certChainTimeValid(Boolean valid) {
            result.certChainTimeValid = valid;
            return this;
        }

        /**
         * RFC 6125 hostname match of the leaf vs the scanned host. Report-only:
         * does NOT by itself force an UNTRUSTED verdict.
         */
        public Builder certHostname(boolean matched, String message) {
            result.certHostnameValid = matched;
            result.certHostnameMessage = message;
            return this;
        }

        /**
         * Set whether the certificate chain was successfully verified.
         *
         * @param valid true if chain is valid, false if invalid, null if not checked
         * @return this builder
         */
        public Builder certChainValid(Boolean valid) {
            result.certChainValid = valid;
            return this;
        }

        /**
         * Set whether the certificate was found to be revoked (via CRL or OCSP).
         *
         * @param revoked true if revoked, false if not revoked, null if not checked
         * @return this builder
         */
        public Builder certRevoked(Boolean revoked) {
            result.certRevoked = revoked;
            return this;
        }

        /**
         * Set the revocation check method used.
         *
         * @param method "OCSP", "CRL", or "NONE"
         * @return this builder
         */
        public Builder revocationMethod(String method) {
            result.revocationMethod = method;
            return this;
        }

        /**
         * Set the revocation check error message.
         *
         * @param error error message if revocation check failed
         * @return this builder
         */
        public Builder revocationError(String error) {
            result.revocationError = error;
            return this;
        }

        /**
         * Set the revocation date.
         *
         * @param date timestamp when certificate was revoked
         * @return this builder
         */
        public Builder revocationDate(Long date) {
            result.revocationDate = date;
            return this;
        }

        /**
         * Set the revocation reason.
         *
         * @param reason CRL reason code (e.g., "KEY_COMPROMISE")
         * @return this builder
         */
        public Builder revocationReason(String reason) {
            result.revocationReason = reason;
            return this;
        }

        /**
         * Set all revocation fields from a RevocationResult.
         *
         * @param revResult the revocation check result
         * @return this builder
         */
        public Builder revocationResult(io.xlogistx.opsec.OPSecUtil.RevocationResult revResult) {
            if (revResult != null) {
                result.revocationMethod = revResult.getMethod();
                result.revocationError = revResult.getErrorMessage();
                result.revocationDate = revResult.getRevocationDate();
                result.revocationReason = revResult.getRevocationReason();

                switch (revResult.getStatus()) {
                    case GOOD:
                        result.certRevoked = false;
                        break;
                    case REVOKED:
                        result.certRevoked = true;
                        break;
                    case NOT_SUPPORTED:
                        // CA-design: revocation not applicable. Not revoked,
                        // not a failure - distinct from UNKNOWN for grading.
                        result.certRevoked = null;
                        break;
                    default:
                        result.certRevoked = null; // UNKNOWN or ERROR
                        break;
                }
            }
            return this;
        }

        /**
         * Set the supported cipher suites from enumeration.
         *
         * @param ciphers list of supported cipher suites
         * @return this builder
         */
        public Builder supportedCipherSuites(List<CipherSuiteEnumerator.CipherInfo> ciphers) {
            result.supportedCipherSuites = ciphers;
            return this;
        }

        /**
         * Set whether the server enforces cipher preference.
         *
         * @param preference true if server enforces preference
         * @return this builder
         */
        public Builder serverCipherPreference(Boolean preference) {
            result.serverCipherPreference = preference;
            return this;
        }

        /**
         * Set the supported protocol versions from testing.
         *
         * @param versions list of supported version names (e.g., "TLSv1.3", "TLSv1.2")
         * @return this builder
         */
        public Builder supportedProtocolVersions(List<String> versions) {
            result.supportedProtocolVersions = versions;
            return this;
        }

        /**
         * Set whether SSLv3 is supported (security risk).
         *
         * @param supported true if SSLv3 is supported
         * @return this builder
         */
        public Builder sslv3Supported(boolean supported) {
            result.sslv3Supported = supported;
            return this;
        }

        /**
         * Set whether deprecated protocols are supported.
         *
         * @param supported true if TLS 1.0, TLS 1.1, or SSLv3 is supported
         * @return this builder
         */
        public Builder deprecatedProtocolsSupported(boolean supported) {
            result.deprecatedProtocolsSupported = supported;
            return this;
        }

        public Builder addRecommendation(String recommendation) {
            result.recommendations.add(recommendation);
            return this;
        }

        public PQCScanResult build() {
            // Calculate overall status
            if (!result.success) {
                result.overallStatus = PQCStatus.ERROR;
            } else if (result.keyExchangePqcReady && result.tlsVersionPqcCapable) {
                result.overallStatus = PQCStatus.READY;
            } else if (result.tlsVersionPqcCapable) {
                result.overallStatus = PQCStatus.PARTIAL;
                if (!result.keyExchangePqcReady) {
                    result.recommendations.add("Enable PQC hybrid key exchange (X25519MLKEM768 or SecP256r1MLKEM768)");
                }
            } else {
                result.overallStatus = PQCStatus.NOT_READY;
                result.recommendations.add("Upgrade to TLS 1.3 for PQC support");
                result.recommendations.add("Enable PQC hybrid key exchange");
            }

            // Certificate TRUST outranks PQC readiness: a connection we cannot
            // trust is reported UNTRUSTED regardless of how quantum-ready it is.
            // Triggers: leaf expired / not-yet-valid, chain not anchored to a
            // trusted Root CA, an expired cert anywhere in the chain, or a
            // confirmed revocation. Hostname mismatch is report-only (does NOT
            // trigger UNTRUSTED) per design.
            if (result.success && result.overallStatus != PQCStatus.ERROR) {
                if (result.certValidityState == CertValidityState.EXPIRED) {
                    result.overallStatus = PQCStatus.UNTRUSTED;
                    result.trustVerdict = TrustVerdict.EXPIRED;
                    result.trustReason = "Certificate is EXPIRED (notAfter "
                            + new java.util.Date(result.certNotAfter) + ") - renew immediately";
                    result.recommendations.add(result.trustReason);
                } else if (result.certValidityState == CertValidityState.NOT_YET_VALID) {
                    result.overallStatus = PQCStatus.UNTRUSTED;
                    result.trustVerdict = TrustVerdict.NOT_YET_VALID;
                    result.trustReason = "Certificate is NOT YET VALID (notBefore "
                            + new java.util.Date(result.certNotBefore) + ") - check server clock / issuance";
                    result.recommendations.add(result.trustReason);
                } else if (Boolean.FALSE.equals(result.certChainValid)) {
                    result.overallStatus = PQCStatus.UNTRUSTED;
                    result.trustVerdict = TrustVerdict.UNTRUSTED_CHAIN;
                    result.trustReason = "Certificate chain does not anchor to a trusted Root CA"
                            + (result.certChainTrust != null ? " [" + result.certChainTrust + "]" : "")
                            + (result.certChainTrustMessage != null ? ": " + result.certChainTrustMessage : "");
                    result.recommendations.add(result.trustReason);
                } else if (Boolean.FALSE.equals(result.certChainTimeValid)) {
                    result.overallStatus = PQCStatus.UNTRUSTED;
                    result.trustVerdict = TrustVerdict.CHAIN_TIME_INVALID;
                    result.trustReason = "An intermediate/root certificate in the chain is expired or not yet valid";
                    result.recommendations.add(result.trustReason);
                } else if (Boolean.TRUE.equals(result.certRevoked)) {
                    result.overallStatus = PQCStatus.UNTRUSTED;
                    result.trustVerdict = TrustVerdict.REVOKED;
                    result.trustReason = "Certificate is REVOKED"
                            + (result.revocationReason != null ? " (" + result.revocationReason + ")" : "");
                    result.recommendations.add(result.trustReason);
                } else {
                    // No trust failure tripped. TRUSTED only if the chain was
                    // positively PKIX-anchored; otherwise we couldn't determine.
                    if (Boolean.TRUE.equals(result.certChainValid)) {
                        result.trustVerdict = TrustVerdict.TRUSTED;
                        result.trustReason = "Certificate chain anchors to a trusted Root CA"
                                + (result.certChainTrust != null ? " [" + result.certChainTrust + "]" : "");
                    } else {
                        result.trustVerdict = TrustVerdict.UNKNOWN;
                        result.trustReason = "Certificate trust could not be determined"
                                + (result.certChainTrustMessage != null ? ": " + result.certChainTrustMessage : "");
                    }
                }
            } else if (!result.success) {
                result.trustVerdict = TrustVerdict.UNKNOWN;
                result.trustReason = result.errorMessage != null
                        ? result.errorMessage : "Scan did not complete";
            }

            // Hostname mismatch: report-only recommendation, no status change.
            if (result.success && Boolean.FALSE.equals(result.certHostnameValid)) {
                result.recommendations.add("Certificate does not match scanned host"
                        + (result.certHostnameMessage != null ? ": " + result.certHostnameMessage : ""));
            }

            // Add certificate recommendations
            if (result.success && !result.certPqcReady) {
                result.recommendations.add("Consider migrating to PQC certificates (ML-DSA) for full quantum resistance");
            }

            return result;
        }
    }
}
