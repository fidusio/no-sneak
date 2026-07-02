package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Integers;
import org.zoxweb.server.logging.LogWrapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Custom TLS client that advertises PQC hybrid key exchange algorithms.
 * Used by PQCScanner to detect server PQC support.
 */
public class PQCTlsClient extends DefaultTlsClient {

    public static final LogWrapper log = new LogWrapper(PQCTlsClient.class).setEnabled(false);

    // Captured handshake information
    private volatile ProtocolVersion negotiatedVersion;
    private volatile int negotiatedCipherSuite;
    private volatile int negotiatedKeyExchange;
    private volatile Certificate serverCertificate;
    private volatile boolean handshakeComplete;
    // DER-encoded OCSP response stapled by the server during the handshake
    // (RFC 6066 status_request). When present, revocation status is known for
    // free - no separate OCSP/CRL network call needed.
    private volatile byte[] stapledOCSPResponse;
    private final InetSocketAddress ipAddress;

    /**
     * Create a PQC-capable TLS client
     * @param ipAddress the server hostname for SNI
     */
    public PQCTlsClient(InetSocketAddress ipAddress) {
        this(createCrypto(), ipAddress);
    }

    /**
     * Create a PQC-capable TLS client with custom crypto
     * @param crypto the TLS crypto instance
     * @param ipAddress the server hostname for SNI
     */
    public PQCTlsClient(TlsCrypto crypto, InetSocketAddress ipAddress) {
        super(crypto);


        this.ipAddress = ipAddress;
    }

    private static TlsCrypto createCrypto() {
        return new BcTlsCrypto(new SecureRandom());
    }

    @Override
    protected Vector<ServerName> getSNIServerNames() {
        Vector<ServerName> serverNames = new Vector<>();
        serverNames.add(new ServerName(NameType.host_name, ipAddress.getHostName().getBytes(StandardCharsets.US_ASCII)));
        return serverNames;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions() {
        // Support TLS 1.2 and 1.3 to detect what server supports
        return new ProtocolVersion[]{
                ProtocolVersion.TLSv13,
                ProtocolVersion.TLSv12
        };
    }

    @Override
    protected int[] getSupportedCipherSuites() {
        // TLS 1.3 cipher suites (required for PQC)
        // Plus TLS 1.2 cipher suites for fallback detection
        return new int[]{
                // TLS 1.3 cipher suites
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,

                // TLS 1.2 cipher suites (for fallback/detection)
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        };
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    protected Vector getSupportedGroups(Vector namedGroupRoles) {
        // Override to advertise PQC hybrid groups first, then classical
        Vector supportedGroups = new Vector();

        // Always add groups regardless of role (we want to discover PQC support)

        // PQC Hybrid key exchanges (TLS 1.3 only)
        supportedGroups.add(Integers.valueOf(NamedGroup.X25519MLKEM768));      // X25519 + ML-KEM-768 hybrid
        supportedGroups.add(Integers.valueOf(NamedGroup.SecP256r1MLKEM768));   // P-256 + ML-KEM-768 hybrid
        supportedGroups.add(Integers.valueOf(NamedGroup.SecP384r1MLKEM1024));  // P-384 + ML-KEM-1024 hybrid

        // Classical ECDHE (fallback for TLS 1.2 and servers without PQC)
        supportedGroups.add(Integers.valueOf(NamedGroup.x25519));
        supportedGroups.add(Integers.valueOf(NamedGroup.x448));
        supportedGroups.add(Integers.valueOf(NamedGroup.secp256r1));
        supportedGroups.add(Integers.valueOf(NamedGroup.secp384r1));
        supportedGroups.add(Integers.valueOf(NamedGroup.secp521r1));

        // FFDHE groups (lower priority)
        supportedGroups.add(Integers.valueOf(NamedGroup.ffdhe2048));
        supportedGroups.add(Integers.valueOf(NamedGroup.ffdhe3072));

        return supportedGroups;
    }

    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        super.notifyServerVersion(serverVersion);
        this.negotiatedVersion = serverVersion;
        if (log.isEnabled()) {
            log.getLogger().info("Server negotiated TLS version: " + serverVersion);
        }
    }

    @Override
    public void notifySelectedCipherSuite(int selectedCipherSuite) {
        super.notifySelectedCipherSuite(selectedCipherSuite);
        this.negotiatedCipherSuite = selectedCipherSuite;
        if (log.isEnabled()) {
            log.getLogger().info("Server selected cipher suite: " +
                    getCipherSuiteName(selectedCipherSuite) + " (0x" + Integer.toHexString(selectedCipherSuite) + ")");
        }
    }

    @Override
    public void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        this.handshakeComplete = true;

        // Try to get key exchange info from security parameters
        if (context != null) {
            SecurityParameters sp = context.getSecurityParametersConnection();
            if (sp != null) {
                int kexAlg = sp.getKeyExchangeAlgorithm();
                if (log.isEnabled()) {
                    log.getLogger().info("KeyExchangeAlgorithm from SecurityParameters: " + kexAlg);
                }
                // For TLS 1.3, check client supported groups - server selected one of these
                int[] clientGroups = sp.getClientSupportedGroups();
                if (clientGroups != null && log.isEnabled()) {
                    StringBuilder sb = new StringBuilder("Client supported groups: ");
                    for (int g : clientGroups) {
                        sb.append(getNamedGroupName(g)).append(" ");
                    }
                    log.getLogger().info(sb.toString());
                }
            }
        }

        if (log.isEnabled()) {
            log.getLogger().info("TLS handshake complete, negotiatedKeyExchange=" + negotiatedKeyExchange);
        }
    }

    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        return new TlsAuthentication() {
            @Override
            public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                serverCertificate = tlsServerCertificate.getCertificate();

                // Capture a stapled OCSP response if the server provided one
                // (we requested it via the status_request extension below).
                try {
                    CertificateStatus cs = tlsServerCertificate.getCertificateStatus();
                    if (cs != null && cs.getStatusType() == CertificateStatusType.ocsp) {
                        org.bouncycastle.asn1.ocsp.OCSPResponse ocsp =
                                (org.bouncycastle.asn1.ocsp.OCSPResponse) cs.getResponse();
                        if (ocsp != null) {
                            stapledOCSPResponse = ocsp.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
                            if (log.isEnabled()) {
                                log.getLogger().info("Captured stapled OCSP response (" +
                                        stapledOCSPResponse.length + " bytes)");
                            }
                        }
                    }
                } catch (Exception e) {
                    if (log.isEnabled()) {
                        log.getLogger().info("Could not read stapled OCSP response: " + e.getMessage());
                    }
                }

                if (log.isEnabled()) {
                    log.getLogger().info("Received server certificate chain with " +
                            (serverCertificate != null ? serverCertificate.getLength() : 0) + " certificates");
                }
            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                // No client certificate
                return null;
            }
        };
    }

    @Override
    public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
        Hashtable<Integer, byte[]> clientExtensions = super.getClientExtensions();
        if (clientExtensions == null) {
            clientExtensions = new Hashtable<>();
        }
        // Request OCSP stapling (RFC 6066 status_request). If the server
        // honors it, revocation status arrives in the handshake for free.
        try {
            TlsExtensionsUtils.addStatusRequestExtension(clientExtensions,
                    new CertificateStatusRequest(CertificateStatusType.ocsp,
                            new OCSPStatusRequest(null, null)));
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Could not add status_request extension: " + e.getMessage());
            }
        }
        return clientExtensions;
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        super.processServerExtensions(serverExtensions);

        if (log.isEnabled()) {
            log.getLogger().info("processServerExtensions called, extensions: " +
                    (serverExtensions != null ? serverExtensions.keySet() : "null"));
        }

        if (serverExtensions == null) {
            return;
        }

        // Extract key_share from ServerHello (TLS 1.3)
        // This contains the server's selected named group for key exchange
        try {
            KeyShareEntry keyShareEntry = TlsExtensionsUtils.getKeyShareServerHello(serverExtensions);
            if (log.isEnabled()) {
                log.getLogger().info("KeyShareEntry from ServerHello: " + keyShareEntry);
            }
            if (keyShareEntry != null) {
                this.negotiatedKeyExchange = keyShareEntry.getNamedGroup();
                if (log.isEnabled()) {
                    log.getLogger().info("Server key_share group: " + getNamedGroupName(negotiatedKeyExchange) +
                            " (0x" + Integer.toHexString(negotiatedKeyExchange) + ")" +
                            " PQC: " + isPQCHybridGroup(negotiatedKeyExchange));
                }
            } else {
                if (log.isEnabled()) {
                    log.getLogger().info("No key_share extension found in ServerHello");
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Could not extract key_share: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    // Getters for scan results

    public ProtocolVersion getNegotiatedVersion() {
        return negotiatedVersion;
    }

    public String getNegotiatedVersionString() {
        if (negotiatedVersion == null) return null;
        if (negotiatedVersion.equals(ProtocolVersion.TLSv13)) return "TLSv1.3";
        if (negotiatedVersion.equals(ProtocolVersion.TLSv12)) return "TLSv1.2";
        if (negotiatedVersion.equals(ProtocolVersion.TLSv11)) return "TLSv1.1";
        if (negotiatedVersion.equals(ProtocolVersion.TLSv10)) return "TLSv1.0";
        return negotiatedVersion.toString();
    }

    public int getNegotiatedCipherSuite() {
        return negotiatedCipherSuite;
    }

    public String getNegotiatedCipherSuiteName() {
        return getCipherSuiteName(negotiatedCipherSuite);
    }

    public Certificate getServerCertificate() {
        return serverCertificate;
    }

    /**
     * @return the DER-encoded OCSP response the server stapled during the
     *         handshake, or {@code null} if the server did not staple one.
     */
    public byte[] getStapledOCSPResponse() {
        return stapledOCSPResponse;
    }

    public boolean isHandshakeComplete() {
        return handshakeComplete;
    }

    /**
     * Get the key exchange algorithm name from the negotiated cipher suite
     * For TLS 1.3, key exchange is negotiated separately via supported_groups
     */
    public String getKeyExchangeAlgorithm() {
        if (negotiatedVersion != null && negotiatedVersion.equals(ProtocolVersion.TLSv13)) {
            // TLS 1.3: key exchange determined by supported_groups extension
            // Return based on negotiated key exchange if known
            if (negotiatedKeyExchange != 0) {
                return getNamedGroupName(negotiatedKeyExchange);
            }
            return "TLS1.3-KeyShare";
        }

        // TLS 1.2: key exchange is part of cipher suite
        String cipherName = getCipherSuiteName(negotiatedCipherSuite);
        if (cipherName.contains("ECDHE")) return "ECDHE";
        if (cipherName.contains("DHE")) return "DHE";
        if (cipherName.contains("RSA")) return "RSA";
        return "UNKNOWN";
    }

    public void setNegotiatedKeyExchange(int keyExchange) {
        this.negotiatedKeyExchange = keyExchange;
    }

    public int getNegotiatedKeyExchange() {
        return negotiatedKeyExchange;
    }

    public String getNegotiatedKeyExchangeName() {
        if (negotiatedKeyExchange == 0) return "UNKNOWN";
        return getNamedGroupName(negotiatedKeyExchange);
    }

    // ==================== Helper Methods ====================

    /**
     * Get human-readable name for a cipher suite
     */
    public static String getCipherSuiteName(int cipherSuite) {
        switch (cipherSuite) {
            // TLS 1.3
            case CipherSuite.TLS_AES_128_GCM_SHA256:
                return "TLS_AES_128_GCM_SHA256";
            case CipherSuite.TLS_AES_256_GCM_SHA384:
                return "TLS_AES_256_GCM_SHA384";
            case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                return "TLS_CHACHA20_POLY1305_SHA256";
            case CipherSuite.TLS_AES_128_CCM_SHA256:
                return "TLS_AES_128_CCM_SHA256";
            case CipherSuite.TLS_AES_128_CCM_8_SHA256:
                return "TLS_AES_128_CCM_8_SHA256";

            // TLS 1.2 ECDHE
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
                return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
                return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";

            default:
                return "CIPHER_0x" + Integer.toHexString(cipherSuite);
        }
    }

    /**
     * Get human-readable name for a named group
     */
    public static String getNamedGroupName(int namedGroup) {
        switch (namedGroup) {
            // PQC Hybrid
            case NamedGroup.X25519MLKEM768:
                return "X25519MLKEM768";
            case NamedGroup.SecP256r1MLKEM768:
                return "SecP256r1MLKEM768";
            case NamedGroup.SecP384r1MLKEM1024:
                return "SecP384r1MLKEM1024";
            case NamedGroup.MLKEM512:
                return "MLKEM512";
            case NamedGroup.MLKEM768:
                return "MLKEM768";
            case NamedGroup.MLKEM1024:
                return "MLKEM1024";

            // Classical ECDHE
            case NamedGroup.x25519:
                return "x25519";
            case NamedGroup.x448:
                return "x448";
            case NamedGroup.secp256r1:
                return "secp256r1";
            case NamedGroup.secp384r1:
                return "secp384r1";
            case NamedGroup.secp521r1:
                return "secp521r1";

            // FFDHE
            case NamedGroup.ffdhe2048:
                return "ffdhe2048";
            case NamedGroup.ffdhe3072:
                return "ffdhe3072";
            case NamedGroup.ffdhe4096:
                return "ffdhe4096";
            case NamedGroup.ffdhe6144:
                return "ffdhe6144";
            case NamedGroup.ffdhe8192:
                return "ffdhe8192";

            default:
                return "GROUP_0x" + Integer.toHexString(namedGroup);
        }
    }

    /**
     * Check if a named group is PQC hybrid
     */
    public static boolean isPQCHybridGroup(int namedGroup) {
        switch (namedGroup) {
            case NamedGroup.X25519MLKEM768:
            case NamedGroup.SecP256r1MLKEM768:
            case NamedGroup.SecP384r1MLKEM1024:
            case NamedGroup.MLKEM512:
            case NamedGroup.MLKEM768:
            case NamedGroup.MLKEM1024:
                return true;
            default:
                return false;
        }
    }
}
