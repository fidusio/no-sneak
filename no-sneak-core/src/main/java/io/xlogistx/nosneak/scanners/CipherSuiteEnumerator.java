package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.zoxweb.server.logging.LogWrapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * Enumerates all cipher suites supported by a TLS server.
 * Uses an iterative approach: connect with all ciphers, note the selected one, remove it, repeat.
 */
public class CipherSuiteEnumerator {

    public static final LogWrapper log = new LogWrapper(CipherSuiteEnumerator.class).setEnabled(false);

    /**
     * Information about a cipher suite
     */
    public static class CipherInfo {
        private final int id;
        private final String name;
        private final OPSecUtil.CipherStrength strength;
        private final String keyExchange;
        private final String authentication;
        private final String encryption;
        private final String mac;
        private final boolean forwardSecrecy;

        public CipherInfo(int id, OPSecUtil.CipherComponents components) {
            this.id = id;
            this.name = components.name;
            this.strength = components.strength;
            this.keyExchange = components.keyExchange;
            this.authentication = components.authentication;
            this.encryption = components.encryption;
            this.mac = components.mac;
            this.forwardSecrecy = components.forwardSecrecy;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public OPSecUtil.CipherStrength getStrength() {
            return strength;
        }

        public String getKeyExchange() {
            return keyExchange;
        }

        public String getAuthentication() {
            return authentication;
        }

        public String getEncryption() {
            return encryption;
        }

        public String getMac() {
            return mac;
        }

        public boolean hasForwardSecrecy() {
            return forwardSecrecy;
        }

        @Override
        public String toString() {
            return name + " (" + strength + ", fs=" + forwardSecrecy + ")";
        }

        /**
         * Convert to a map for JSON serialization (kebab-case keys).
         */
        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", id);
            map.put("name", name);
            map.put("strength", strength.name());
            map.put("key-exchange", keyExchange);
            map.put("authentication", authentication);
            map.put("encryption", encryption);
            map.put("mac", mac);
            map.put("forward-secrecy", forwardSecrecy);
            return map;
        }
    }

    /**
     * Result of cipher suite enumeration
     */
    public static class EnumerationResult {
        private final List<CipherInfo> supportedCiphers;
        private final boolean serverCipherPreference;
        private final String errorMessage;

        public EnumerationResult(List<CipherInfo> supportedCiphers, boolean serverCipherPreference) {
            this.supportedCiphers = supportedCiphers;
            this.serverCipherPreference = serverCipherPreference;
            this.errorMessage = null;
        }

        public EnumerationResult(String errorMessage) {
            this.supportedCiphers = Collections.emptyList();
            this.serverCipherPreference = false;
            this.errorMessage = errorMessage;
        }

        public List<CipherInfo> getSupportedCiphers() {
            return supportedCiphers;
        }

        public boolean hasServerCipherPreference() {
            return serverCipherPreference;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean isSuccess() {
            return errorMessage == null;
        }

        @Override
        public String toString() {
            if (errorMessage != null) {
                return "EnumerationResult{error=" + errorMessage + "}";
            }
            return "EnumerationResult{ciphers=" + supportedCiphers.size() +
                    ", serverPreference=" + serverCipherPreference + "}";
        }
    }

    //private final OPSecUtil opsecUtil;

    public CipherSuiteEnumerator() {

    }

    /**
     * Enumerate all supported cipher suites on a server.
     *
     * @param host the server hostname
     * @param port the server port
     * @param timeoutMs connection timeout in milliseconds
     * @param testWeak whether to test weak cipher suites
     * @param testInsecure whether to test insecure cipher suites
     * @return enumeration result
     */
    public EnumerationResult enumerate(String host, int port, int timeoutMs,
                                       boolean testWeak, boolean testInsecure) {
        List<CipherInfo> supportedCiphers = new ArrayList<>();
        boolean serverPreference = false;

        // Build list of ciphers to test
        List<Integer> ciphersToTest = new ArrayList<>();
        for (int c : OPSecUtil.ALL_TLS13_CIPHERS) ciphersToTest.add(c);
        for (int c : OPSecUtil.ALL_TLS12_STRONG) ciphersToTest.add(c);
        if (testWeak) {
            for (int c : OPSecUtil.ALL_TLS12_WEAK) ciphersToTest.add(c);
        }
        if (testInsecure) {
            for (int c : OPSecUtil.ALL_TLS12_INSECURE) ciphersToTest.add(c);
        }

        // Test TLS 1.3 ciphers first
        List<CipherInfo> tls13Ciphers = enumerateTLS13(host, port, timeoutMs);
        supportedCiphers.addAll(tls13Ciphers);

        // Then TLS 1.2 ciphers
        List<Integer> tls12Ciphers = new ArrayList<>();
        for (int c : OPSecUtil.ALL_TLS12_STRONG) tls12Ciphers.add(c);
        if (testWeak) {
            for (int c : OPSecUtil.ALL_TLS12_WEAK) tls12Ciphers.add(c);
        }
        if (testInsecure) {
            for (int c : OPSecUtil.ALL_TLS12_INSECURE) tls12Ciphers.add(c);
        }

        List<CipherInfo> tls12Supported = enumerateTLS12(host, port, timeoutMs, tls12Ciphers);
        supportedCiphers.addAll(tls12Supported);

        // Check server cipher preference by comparing order
        if (supportedCiphers.size() >= 2) {
            serverPreference = checkServerCipherPreference(host, port, timeoutMs, supportedCiphers);
        }

        return new EnumerationResult(supportedCiphers, serverPreference);
    }

    /**
     * Enumerate TLS 1.3 cipher suites.
     */
    private List<CipherInfo> enumerateTLS13(String host, int port, int timeoutMs) {
        List<CipherInfo> supported = new ArrayList<>();
        Set<Integer> remaining = new LinkedHashSet<>();
        for (int c : OPSecUtil.ALL_TLS13_CIPHERS) remaining.add(c);

        while (!remaining.isEmpty()) {
            int[] ciphers = remaining.stream().mapToInt(Integer::intValue).toArray();
            Integer selected = testCipherSuites(host, port, timeoutMs, ProtocolVersion.TLSv13, ciphers);

            if (selected == null) {
                break; // Server doesn't support any remaining ciphers
            }

            String cipherName = PQCTlsClient.getCipherSuiteName(selected);
            OPSecUtil.CipherComponents components = OPSecUtil.singleton().parseCipherSuite(cipherName);
            supported.add(new CipherInfo(selected, components));
            remaining.remove(selected);
        }

        return supported;
    }

    /**
     * Enumerate TLS 1.2 cipher suites.
     */
    private List<CipherInfo> enumerateTLS12(String host, int port, int timeoutMs, List<Integer> ciphersToTest) {
        List<CipherInfo> supported = new ArrayList<>();
        Set<Integer> remaining = new LinkedHashSet<>(ciphersToTest);

        while (!remaining.isEmpty()) {
            int[] ciphers = remaining.stream().mapToInt(Integer::intValue).toArray();
            Integer selected = testCipherSuites(host, port, timeoutMs, ProtocolVersion.TLSv12, ciphers);

            if (selected == null) {
                break; // Server doesn't support any remaining ciphers
            }

            String cipherName = getCipherSuiteName(selected);
            OPSecUtil.CipherComponents components = OPSecUtil.singleton().parseCipherSuite(cipherName);
            supported.add(new CipherInfo(selected, components));
            remaining.remove(selected);
        }

        return supported;
    }

    /**
     * Test if server supports any of the given cipher suites.
     *
     * @return the selected cipher suite ID, or null if none supported
     */
    private Integer testCipherSuites(String host, int port, int timeoutMs,
                                     ProtocolVersion version, int[] ciphers) {
        if (ciphers.length == 0) return null;

        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            try {
                EnumerationTlsClient client = new EnumerationTlsClient(host, version, ciphers);
                TlsClientProtocol protocol = new TlsClientProtocol(
                        socket.getInputStream(), socket.getOutputStream());

                try {
                    protocol.connect(client);
                    return client.getSelectedCipherSuite();
                } catch (TlsFatalAlert e) {
                    // Server rejected all ciphers
                    if (log.isEnabled()) {
                        log.getLogger().info("TLS alert during cipher test: " + e.getAlertDescription());
                    }
                    return null;
                }
            } finally {
                socket.close();
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error testing ciphers: " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Check if server enforces cipher preference.
     * Connect twice with reversed cipher order and see if the same cipher is selected.
     */
    private boolean checkServerCipherPreference(String host, int port, int timeoutMs,
                                                List<CipherInfo> supportedCiphers) {
        if (supportedCiphers.size() < 2) return false;

        // Get two ciphers
        int cipher1 = supportedCiphers.get(0).getId();
        int cipher2 = supportedCiphers.get(1).getId();

        // Test with cipher1 first
        Integer selected1 = testCipherSuites(host, port, timeoutMs, ProtocolVersion.TLSv12,
                new int[]{cipher1, cipher2});

        // Test with cipher2 first
        Integer selected2 = testCipherSuites(host, port, timeoutMs, ProtocolVersion.TLSv12,
                new int[]{cipher2, cipher1});

        // If server always selects the same cipher regardless of order, it has preference
        return selected1 != null && selected1.equals(selected2);
    }

    /**
     * Get extended cipher suite name (more complete than PQCTlsClient version)
     */
    private String getCipherSuiteName(int cipherSuite) {
        // First try PQCTlsClient's lookup
        String name = PQCTlsClient.getCipherSuiteName(cipherSuite);
        if (!name.startsWith("CIPHER_0x")) {
            return name;
        }

        // Extended lookup for additional cipher suites
        switch (cipherSuite) {
            // TLS 1.2 ECDHE CBC
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
                return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
                return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";

            // DHE
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
            case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
                return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
            case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";

            // RSA
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                return "TLS_RSA_WITH_AES_256_GCM_SHA384";
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                return "TLS_RSA_WITH_AES_128_GCM_SHA256";
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                return "TLS_RSA_WITH_AES_256_CBC_SHA256";
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                return "TLS_RSA_WITH_AES_128_CBC_SHA256";
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                return "TLS_RSA_WITH_AES_256_CBC_SHA";
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                return "TLS_RSA_WITH_AES_128_CBC_SHA";
            case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";

            // 3DES
            case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";

            // Insecure
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                return "TLS_RSA_WITH_NULL_SHA256";
            case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                return "TLS_RSA_WITH_NULL_SHA";
            case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                return "TLS_RSA_WITH_NULL_MD5";
            case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                return "TLS_RSA_WITH_RC4_128_SHA";
            case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                return "TLS_RSA_WITH_RC4_128_MD5";

            default:
                return "CIPHER_0x" + Integer.toHexString(cipherSuite);
        }
    }

    /**
     * TLS client for cipher enumeration - minimal implementation
     */
    private static class EnumerationTlsClient extends DefaultTlsClient {
        private final String hostname;
        private final ProtocolVersion targetVersion;
        private final int[] ciphersToOffer;
        private int selectedCipherSuite;

        public EnumerationTlsClient(String hostname, ProtocolVersion targetVersion, int[] ciphers) {
            super(new BcTlsCrypto(new SecureRandom()));
            this.hostname = hostname;
            this.targetVersion = targetVersion;
            this.ciphersToOffer = ciphers;
        }

        @Override
        protected Vector<ServerName> getSNIServerNames() {
            Vector<ServerName> serverNames = new Vector<>();
            serverNames.add(new ServerName(NameType.host_name, hostname.getBytes(StandardCharsets.US_ASCII)));
            return serverNames;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            if (targetVersion.equals(ProtocolVersion.TLSv13)) {
                return new ProtocolVersion[]{ProtocolVersion.TLSv13};
            }
            return new ProtocolVersion[]{targetVersion};
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return ciphersToOffer;
        }

        @Override
        public void notifySelectedCipherSuite(int selectedCipherSuite) {
            super.notifySelectedCipherSuite(selectedCipherSuite);
            this.selectedCipherSuite = selectedCipherSuite;
        }

        public int getSelectedCipherSuite() {
            return selectedCipherSuite;
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                    // Accept any certificate for enumeration
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
