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
 * Tests which TLS/SSL protocol versions a server supports.
 * Probes each version individually to build a complete picture of server configuration.
 */
public class ProtocolVersionTester {

    public static final LogWrapper log = new LogWrapper(ProtocolVersionTester.class).setEnabled(false);

    /**
     * All TLS/SSL versions to test, in order from most secure to least secure
     */
    public static final ProtocolVersion[] ALL_VERSIONS = {
            ProtocolVersion.TLSv13,
            ProtocolVersion.TLSv12,
            ProtocolVersion.TLSv11,
            ProtocolVersion.TLSv10,
            ProtocolVersion.SSLv3
    };

    /**
     * Result of protocol version testing
     */
    public static class VersionTestResult {
        private final List<String> supportedVersions;
        private final String preferredVersion;
        private final boolean sslv3Supported;
        private final boolean tls10Supported;
        private final boolean tls11Supported;
        private final boolean deprecatedProtocolsSupported;
        private final String errorMessage;

        public VersionTestResult(List<String> supportedVersions, String preferredVersion) {
            this.supportedVersions = supportedVersions;
            this.preferredVersion = preferredVersion;
            this.sslv3Supported = supportedVersions.contains("SSLv3");
            this.tls10Supported = supportedVersions.contains("TLSv1.0");
            this.tls11Supported = supportedVersions.contains("TLSv1.1");
            this.deprecatedProtocolsSupported = sslv3Supported || tls10Supported || tls11Supported;
            this.errorMessage = null;
        }

        public VersionTestResult(String errorMessage) {
            this.supportedVersions = Collections.emptyList();
            this.preferredVersion = null;
            this.sslv3Supported = false;
            this.tls10Supported = false;
            this.tls11Supported = false;
            this.deprecatedProtocolsSupported = false;
            this.errorMessage = errorMessage;
        }

        public List<String> getSupportedVersions() { return supportedVersions; }
        public String getPreferredVersion() { return preferredVersion; }
        public boolean isSslv3Supported() { return sslv3Supported; }
        public boolean isTls10Supported() { return tls10Supported; }
        public boolean isTls11Supported() { return tls11Supported; }
        public boolean isDeprecatedProtocolsSupported() { return deprecatedProtocolsSupported; }
        public String getErrorMessage() { return errorMessage; }
        public boolean isSuccess() { return errorMessage == null; }

        /**
         * Get security recommendations based on supported versions.
         */
        public List<String> getRecommendations() {
            List<String> recommendations = new ArrayList<>();
            if (sslv3Supported) {
                recommendations.add("CRITICAL: Disable SSLv3 (vulnerable to POODLE attack)");
            }
            if (tls10Supported) {
                recommendations.add("Disable TLS 1.0 (deprecated, PCI-DSS non-compliant)");
            }
            if (tls11Supported) {
                recommendations.add("Disable TLS 1.1 (deprecated)");
            }
            if (!supportedVersions.contains("TLSv1.3")) {
                recommendations.add("Enable TLS 1.3 for best security and PQC support");
            }
            return recommendations;
        }

        @Override
        public String toString() {
            if (errorMessage != null) {
                return "VersionTestResult{error=" + errorMessage + "}";
            }
            return "VersionTestResult{supported=" + supportedVersions +
                    ", preferred=" + preferredVersion +
                    ", deprecated=" + deprecatedProtocolsSupported + "}";
        }
    }

    private final OPSecUtil opsecUtil;

    public ProtocolVersionTester() {
        this.opsecUtil = OPSecUtil.singleton();
    }

    /**
     * Test all protocol versions against a server.
     *
     * @param host the server hostname
     * @param port the server port
     * @param timeoutMs connection timeout in milliseconds
     * @return test result containing supported versions
     */
    public VersionTestResult testAllVersions(String host, int port, int timeoutMs) {
        return testAllVersions(host, port, timeoutMs, true, true, true);
    }

    /**
     * Test protocol versions against a server with options.
     *
     * @param host the server hostname
     * @param port the server port
     * @param timeoutMs connection timeout in milliseconds
     * @param testSSLv3 whether to test SSLv3
     * @param testTLS10 whether to test TLS 1.0
     * @param testTLS11 whether to test TLS 1.1
     * @return test result containing supported versions
     */
    public VersionTestResult testAllVersions(String host, int port, int timeoutMs,
                                             boolean testSSLv3, boolean testTLS10, boolean testTLS11) {
        List<String> supportedVersions = new ArrayList<>();
        String preferredVersion = null;

        // Test each version
        for (ProtocolVersion version : ALL_VERSIONS) {
            // Skip versions based on options
            if (version.equals(ProtocolVersion.SSLv3) && !testSSLv3) continue;
            if (version.equals(ProtocolVersion.TLSv10) && !testTLS10) continue;
            if (version.equals(ProtocolVersion.TLSv11) && !testTLS11) continue;

            boolean supported = testVersion(host, port, version, timeoutMs);
            if (supported) {
                String versionName = getVersionName(version);
                supportedVersions.add(versionName);
                if (preferredVersion == null) {
                    preferredVersion = versionName;
                }
            }
        }

        if (supportedVersions.isEmpty()) {
            return new VersionTestResult("No supported TLS versions found");
        }

        return new VersionTestResult(supportedVersions, preferredVersion);
    }

    /**
     * Test if a specific protocol version is supported.
     *
     * @param host the server hostname
     * @param port the server port
     * @param version the protocol version to test
     * @param timeoutMs connection timeout in milliseconds
     * @return true if the version is supported
     */
    public boolean testVersion(String host, int port, ProtocolVersion version, int timeoutMs) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            try {
                VersionTestTlsClient client = new VersionTestTlsClient(host, version);
                TlsClientProtocol protocol = new TlsClientProtocol(
                        socket.getInputStream(), socket.getOutputStream());

                try {
                    protocol.connect(client);
                    return true; // Handshake succeeded
                } catch (TlsFatalAlert e) {
                    // Server rejected this version
                    if (log.isEnabled()) {
                        log.getLogger().info("Version " + getVersionName(version) +
                                " rejected: alert " + e.getAlertDescription());
                    }
                    return false;
                } catch (IOException e) {
                    // Protocol error (version not supported)
                    if (log.isEnabled()) {
                        log.getLogger().info("Version " + getVersionName(version) +
                                " not supported: " + e.getMessage());
                    }
                    return false;
                }
            } finally {
                socket.close();
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error testing version " + getVersionName(version) +
                        ": " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Test if a specific protocol version is supported (string version).
     *
     * @param host the server hostname
     * @param port the server port
     * @param versionName the version name (e.g., "TLSv1.3", "SSLv3")
     * @param timeoutMs connection timeout in milliseconds
     * @return true if the version is supported
     */
    public boolean testVersion(String host, int port, String versionName, int timeoutMs) {
        ProtocolVersion version = parseVersionName(versionName);
        if (version == null) {
            if (log.isEnabled()) {
                log.getLogger().info("Unknown version name: " + versionName);
            }
            return false;
        }
        return testVersion(host, port, version, timeoutMs);
    }

    /**
     * Get the security classification for a protocol version.
     */
    public OPSecUtil.ProtocolSecurity getVersionSecurity(ProtocolVersion version) {
        return opsecUtil.classifyProtocolVersionSecurity(getVersionName(version));
    }

    /**
     * Convert ProtocolVersion to human-readable name.
     */
    public static String getVersionName(ProtocolVersion version) {
        if (version == null) return "UNKNOWN";
        if (version.equals(ProtocolVersion.TLSv13)) return "TLSv1.3";
        if (version.equals(ProtocolVersion.TLSv12)) return "TLSv1.2";
        if (version.equals(ProtocolVersion.TLSv11)) return "TLSv1.1";
        if (version.equals(ProtocolVersion.TLSv10)) return "TLSv1.0";
        if (version.equals(ProtocolVersion.SSLv3)) return "SSLv3";
        return version.toString();
    }

    /**
     * Parse version name to ProtocolVersion.
     */
    public static ProtocolVersion parseVersionName(String name) {
        if (name == null) return null;
        String normalized = name.toUpperCase().replace(" ", "").replace("_", "");
        if (normalized.contains("1.3") || normalized.contains("13")) return ProtocolVersion.TLSv13;
        if (normalized.contains("1.2") || normalized.contains("12")) return ProtocolVersion.TLSv12;
        if (normalized.contains("1.1") || normalized.contains("11")) return ProtocolVersion.TLSv11;
        if (normalized.contains("1.0") || normalized.contains("10")) return ProtocolVersion.TLSv10;
        if (normalized.contains("SSL") || normalized.contains("V3") || normalized.equals("3")) return ProtocolVersion.SSLv3;
        return null;
    }

    /**
     * TLS client for version testing - minimal implementation
     */
    private static class VersionTestTlsClient extends DefaultTlsClient {
        private final String hostname;
        private final ProtocolVersion targetVersion;

        public VersionTestTlsClient(String hostname, ProtocolVersion targetVersion) {
            super(new BcTlsCrypto(new SecureRandom()));
            this.hostname = hostname;
            this.targetVersion = targetVersion;
        }

        @Override
        protected Vector<ServerName> getSNIServerNames() {
            // SSLv3 doesn't support SNI
            if (targetVersion.equals(ProtocolVersion.SSLv3)) {
                return null;
            }
            Vector<ServerName> serverNames = new Vector<>();
            serverNames.add(new ServerName(NameType.host_name, hostname.getBytes(StandardCharsets.US_ASCII)));
            return serverNames;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            // Only offer the version we're testing
            return new ProtocolVersion[]{targetVersion};
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            // Offer ciphers appropriate for the version
            if (targetVersion.equals(ProtocolVersion.TLSv13)) {
                return new int[]{
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256
                };
            }
            // TLS 1.2 and earlier
            return new int[]{
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA
            };
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                    // Accept any certificate for version testing
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
