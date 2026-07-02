package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for new features against real servers.
 * Tests CRL/OCSP checking, cipher enumeration, and protocol version testing.
 */
public class FeatureIntegrationTest {

    private static final String TEST_HOST = "google.com";
    private static final int TEST_PORT = 443;
    private static final int TIMEOUT_MS = 15000;

    @BeforeAll
    static void setup() {
        OPSecUtil.singleton(); // Initialize BC providers
    }

    @Test
    void testCipherEnumeration() {
        System.out.println("\n=== Cipher Suite Enumeration Test ===");
        System.out.println("Target: " + TEST_HOST + ":" + TEST_PORT);

        CipherSuiteEnumerator enumerator = new CipherSuiteEnumerator();
        CipherSuiteEnumerator.EnumerationResult result = enumerator.enumerate(
                TEST_HOST, TEST_PORT, TIMEOUT_MS,
                false,  // testWeak
                false   // testInsecure
        );

        assertTrue(result.isSuccess(), "Enumeration should succeed");
        assertFalse(result.getSupportedCiphers().isEmpty(), "Should find supported ciphers");

        System.out.println("\nSupported Cipher Suites (" + result.getSupportedCiphers().size() + "):");
        for (CipherSuiteEnumerator.CipherInfo cipher : result.getSupportedCiphers()) {
            System.out.println("  - " + cipher.getName());
            System.out.println("    Strength: " + cipher.getStrength());
            System.out.println("    Key Exchange: " + cipher.getKeyExchange());
            System.out.println("    Forward Secrecy: " + cipher.hasForwardSecrecy());
        }

        System.out.println("\nServer Cipher Preference: " + result.hasServerCipherPreference());

        // Verify we found TLS 1.3 ciphers (Google supports TLS 1.3)
        boolean hasTls13Cipher = result.getSupportedCiphers().stream()
                .anyMatch(c -> c.getName().startsWith("TLS_AES_") || c.getName().startsWith("TLS_CHACHA20_"));
        assertTrue(hasTls13Cipher, "Should find TLS 1.3 ciphers");
    }

    @Test
    void testProtocolVersions() {
        System.out.println("\n=== Protocol Version Testing ===");
        System.out.println("Target: " + TEST_HOST + ":" + TEST_PORT);

        ProtocolVersionTester tester = new ProtocolVersionTester();
        ProtocolVersionTester.VersionTestResult result = tester.testAllVersions(
                TEST_HOST, TEST_PORT, TIMEOUT_MS,
                true,  // testSSLv3
                true,  // testTLS10
                true   // testTLS11
        );

        assertTrue(result.isSuccess(), "Version testing should succeed");
        assertFalse(result.getSupportedVersions().isEmpty(), "Should find supported versions");

        System.out.println("\nSupported Protocol Versions:");
        for (String version : result.getSupportedVersions()) {
            OPSecUtil.ProtocolSecurity security = OPSecUtil.singleton()
                    .classifyProtocolVersionSecurity(version);
            System.out.println("  - " + version + " (" + security + ")");
        }

        System.out.println("\nPreferred Version: " + result.getPreferredVersion());
        System.out.println("SSLv3 Supported: " + result.isSslv3Supported());
        System.out.println("TLS 1.0 Supported: " + result.isTls10Supported());
        System.out.println("TLS 1.1 Supported: " + result.isTls11Supported());
        System.out.println("Deprecated Protocols: " + result.isDeprecatedProtocolsSupported());

        System.out.println("\nRecommendations:");
        for (String rec : result.getRecommendations()) {
            System.out.println("  - " + rec);
        }

        // Google should support TLS 1.3 and 1.2
        assertTrue(result.getSupportedVersions().contains("TLSv1.3"), "Should support TLS 1.3");
        assertTrue(result.getSupportedVersions().contains("TLSv1.2"), "Should support TLS 1.2");

        // Google should NOT support SSLv3 (POODLE vulnerable)
        assertFalse(result.isSslv3Supported(), "Should NOT support SSLv3");
    }

    @Test
    void testRevocationChecking() throws Exception {
        System.out.println("\n=== Revocation Checking Test ===");
        System.out.println("Target: " + TEST_HOST + ":" + TEST_PORT);

        // Get certificate from server
        X509Certificate[] chain = getCertificateChain(TEST_HOST, TEST_PORT);
        assertNotNull(chain, "Should get certificate chain");
        assertTrue(chain.length > 0, "Chain should not be empty");

        X509Certificate leafCert = chain[0];
        X509Certificate issuerCert = chain.length > 1 ? chain[1] : null;

        System.out.println("\nCertificate Subject: " + leafCert.getSubjectX500Principal());
        System.out.println("Certificate Issuer: " + leafCert.getIssuerX500Principal());

        OPSecUtil opsec = OPSecUtil.singleton();

        // Extract CRL Distribution Points
        List<String> crlUrls = opsec.extractCRLDistributionPoints(leafCert);
        System.out.println("\nCRL Distribution Points (" + crlUrls.size() + "):");
        for (String url : crlUrls) {
            System.out.println("  - " + url);
        }

        // Extract OCSP Responder URLs
        List<String> ocspUrls = opsec.extractOCSPResponderURLs(leafCert);
        System.out.println("\nOCSP Responder URLs (" + ocspUrls.size() + "):");
        for (String url : ocspUrls) {
            System.out.println("  - " + url);
        }

        // Extract CA Issuer URLs
        List<String> caUrls = opsec.extractCAIssuerURLs(leafCert);
        System.out.println("\nCA Issuer URLs (" + caUrls.size() + "):");
        for (String url : caUrls) {
            System.out.println("  - " + url);
        }

        // Perform revocation check
        System.out.println("\nPerforming revocation check...");
        OPSecUtil.RevocationResult result = opsec.checkRevocation(leafCert, issuerCert, TIMEOUT_MS);

        System.out.println("Revocation Status: " + result.getStatus());
        System.out.println("Method Used: " + result.getMethod());
        if (result.getErrorMessage() != null) {
            System.out.println("Error: " + result.getErrorMessage());
        }
        if (result.getRevocationDate() != null) {
            System.out.println("Revocation Date: " + new java.util.Date(result.getRevocationDate()));
        }
        if (result.getRevocationReason() != null) {
            System.out.println("Revocation Reason: " + result.getRevocationReason());
        }

        // Google's cert should be valid (not revoked)
        if (result.getStatus() == OPSecUtil.RevocationStatus.GOOD) {
            System.out.println("\n✓ Certificate is NOT revoked");
        } else if (result.getStatus() == OPSecUtil.RevocationStatus.ERROR ||
                   result.getStatus() == OPSecUtil.RevocationStatus.UNKNOWN) {
            System.out.println("\n⚠ Could not verify revocation status: " + result.getErrorMessage());
        }
    }

    @Test
    void testCipherStrengthClassification() {
        System.out.println("\n=== Cipher Strength Classification Test ===");

        OPSecUtil opsec = OPSecUtil.singleton();

        String[] ciphers = {
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_RSA_WITH_RC4_128_SHA",
                "TLS_RSA_WITH_NULL_SHA"
        };

        for (String cipher : ciphers) {
            OPSecUtil.CipherStrength strength = opsec.classifyCipherSuiteStrength(cipher);
            OPSecUtil.CipherComponents components = opsec.parseCipherSuite(cipher);

            System.out.println("\n" + cipher);
            System.out.println("  Strength: " + strength);
            System.out.println("  Key Exchange: " + components.keyExchange);
            System.out.println("  Encryption: " + components.encryption);
            System.out.println("  MAC: " + components.mac);
            System.out.println("  Forward Secrecy: " + components.forwardSecrecy);
        }

        // Verify classifications
        assertEquals(OPSecUtil.CipherStrength.STRONG,
                opsec.classifyCipherSuiteStrength("TLS_AES_256_GCM_SHA384"));
        assertEquals(OPSecUtil.CipherStrength.STRONG,
                opsec.classifyCipherSuiteStrength("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
        assertEquals(OPSecUtil.CipherStrength.WEAK,
                opsec.classifyCipherSuiteStrength("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
        assertEquals(OPSecUtil.CipherStrength.INSECURE,
                opsec.classifyCipherSuiteStrength("TLS_RSA_WITH_NULL_SHA"));
    }

    @Test
    void testProtocolSecurityClassification() {
        System.out.println("\n=== Protocol Security Classification Test ===");

        OPSecUtil opsec = OPSecUtil.singleton();

        String[] versions = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"};

        for (String version : versions) {
            OPSecUtil.ProtocolSecurity security = opsec.classifyProtocolVersionSecurity(version);
            boolean pqcCapable = opsec.protocolSupportsPQC(version);

            System.out.println(version + ": " + security + " (PQC capable: " + pqcCapable + ")");
        }

        // Verify classifications
        assertEquals(OPSecUtil.ProtocolSecurity.SECURE,
                opsec.classifyProtocolVersionSecurity("TLSv1.3"));
        assertEquals(OPSecUtil.ProtocolSecurity.SECURE,
                opsec.classifyProtocolVersionSecurity("TLSv1.2"));
        assertEquals(OPSecUtil.ProtocolSecurity.DEPRECATED,
                opsec.classifyProtocolVersionSecurity("TLSv1.1"));
        assertEquals(OPSecUtil.ProtocolSecurity.DEPRECATED,
                opsec.classifyProtocolVersionSecurity("TLSv1.0"));
        assertEquals(OPSecUtil.ProtocolSecurity.CRITICAL,
                opsec.classifyProtocolVersionSecurity("SSLv3"));

        // Only TLS 1.3 supports PQC
        assertTrue(opsec.protocolSupportsPQC("TLSv1.3"));
        assertFalse(opsec.protocolSupportsPQC("TLSv1.2"));
    }

    @Test
    void testMultipleServers() {
        System.out.println("\n=== Multi-Server Test ===");

        String[][] servers = {
                {"google.com", "443"},
                {"cloudflare.com", "443"},
                {"github.com", "443"}
        };

        ProtocolVersionTester versionTester = new ProtocolVersionTester();
        CipherSuiteEnumerator cipherEnumerator = new CipherSuiteEnumerator();

        for (String[] server : servers) {
            String host = server[0];
            int port = Integer.parseInt(server[1]);

            System.out.println("\n--- " + host + ":" + port + " ---");

            // Test protocol versions
            ProtocolVersionTester.VersionTestResult vResult =
                    versionTester.testAllVersions(host, port, TIMEOUT_MS, false, false, false);

            if (vResult.isSuccess()) {
                System.out.println("Protocols: " + vResult.getSupportedVersions());
            } else {
                System.out.println("Protocol test failed: " + vResult.getErrorMessage());
            }

            // Test ciphers (just count, don't enumerate all)
            CipherSuiteEnumerator.EnumerationResult cResult =
                    cipherEnumerator.enumerate(host, port, TIMEOUT_MS, false, false);

            if (cResult.isSuccess()) {
                long strongCount = cResult.getSupportedCiphers().stream()
                        .filter(c -> c.getStrength() == OPSecUtil.CipherStrength.STRONG)
                        .count();
                System.out.println("Ciphers: " + cResult.getSupportedCiphers().size() +
                        " total, " + strongCount + " strong");
                System.out.println("Server preference: " + cResult.hasServerCipherPreference());
            } else {
                System.out.println("Cipher test failed: " + cResult.getErrorMessage());
            }
        }
    }

    /**
     * Helper to get certificate chain from server using Java SSL.
     */
    private X509Certificate[] getCertificateChain(String host, int port) throws Exception {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
            socket.setSoTimeout(TIMEOUT_MS);
            socket.startHandshake();
            return (X509Certificate[]) socket.getSession().getPeerCertificates();
        }
    }
}
