package io.xlogistx.nosneak.scanners;

import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test PQCScanner components against real TLS servers
 */
public class PQCScannerTest {
    public static final LogWrapper log = new LogWrapper(PQCScannerTest.class).setEnabled(true);
    private static final IPAddress[] serversToTest = IPAddress.parseList("https://xlogistx.io",
            "google.com:443",
            "https://cloudflare.com:443",
            "https://backend.zoxweb.com:4443",
            "zoxweb.com:1024",
            "khara:8080",
            "https://10.0.0.8",
            "https://dbs.xlogistx.io");

    private static HTTPNIOSocket httpNIOSocket;


    @BeforeAll
    static void setup() throws IOException {
        // Initialize OPSecUtil to load BC providers
        OPSecUtil.singleton();
        DNSRegistrar.SINGLETON.setResolver("10.0.0.1");
        httpNIOSocket = new HTTPNIOSocket(new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler()));
    }

    @Test
    void testScanCloudflare() throws Exception {
        // Cloudflare supports TLS 1.3 with PQC hybrid (X25519Kyber768)
        doScan("cloudflare.com", 443);
    }

    @Test
    void testScanGoogle() throws Exception {
        // Google supports TLS 1.3
        doScan("google.com", 443);
    }

    @Test
    void testScanGithub() throws Exception {
        // GitHub supports TLS 1.3
        doScan("github.com", 443);
    }


    @Test
    void testScanOther() throws Exception {
        doScan("xlogistx.io", 443);
        doScan("amazon.com", 443);
        doScan("dbs.xlogistx.io", 443);
    }


    /**
     * Direct scan using BC TLS without NIOSocket
     */
    private void doScan(String host, int port) throws Exception {
        System.out.println("\n========== Scanning " + host + ":" + port + " ==========");

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 10000);
            socket.setSoTimeout(10000);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Create BC TLS client and custom protocol
            PQCTlsClient tlsClient = new PQCTlsClient(new InetSocketAddress(host, port));
            PQCTlsClientProtocol protocol = new PQCTlsClientProtocol(in, out);

            // Perform handshake
            protocol.connect(tlsClient);

            // Extract results
            System.out.println("TLS Version: " + tlsClient.getNegotiatedVersionString());
            System.out.println("Cipher Suite: " + tlsClient.getNegotiatedCipherSuiteName());
            System.out.println("Key Exchange: " + tlsClient.getNegotiatedKeyExchangeName());
            System.out.println("Handshake Complete: " + tlsClient.isHandshakeComplete());

            // Analyze results
            OPSecUtil opsec = OPSecUtil.singleton();
            String kexAlg = tlsClient.getNegotiatedKeyExchangeName();
            String kexType = opsec.classifyKeyExchange(kexAlg);

            System.out.println("Key Exchange Type: " + kexType);
            System.out.println("PQC Hybrid: " + opsec.isPQCHybridKeyExchange(kexAlg));

            // Build result with full certificate analysis
            PQCScanResult.Builder builder = PQCScanResult.builder(host, port, UUID.randomUUID().toString())
                    .success(true)
                    .tlsVersion(tlsClient.getNegotiatedVersionString())
                    .cipherSuite(tlsClient.getNegotiatedCipherSuiteName());

            PQCScanResult.KeyExchangeType keyExchangeType = PQCNIOScanner.parseKeyExchangeType(kexType);
            builder.keyExchange(keyExchangeType, kexAlg);

            // Certificate analysis
            if (tlsClient.getServerCertificate() != null && tlsClient.getServerCertificate().getLength() > 0) {
                System.out.println("Certificate chain length: " + tlsClient.getServerCertificate().getLength());

                // Convert first cert and analyze
                org.bouncycastle.tls.crypto.TlsCertificate[] tlsCerts = tlsClient.getServerCertificate().getCertificateList();
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                X509Certificate leafCert = (X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(tlsCerts[0].getEncoded()));

                String[] certAnalysis = opsec.analyzeCertificatePQC(leafCert);
                PQCScanResult.SignatureType sigType = PQCNIOScanner.parseSignatureType(certAnalysis[0]);
                builder.certSignature(sigType, certAnalysis[1]);
                builder.certPublicKey(certAnalysis[2], Integer.parseInt(certAnalysis[3]));

                System.out.println("Certificate Subject: " + leafCert.getSubjectX500Principal());
                System.out.println("Certificate Signature: " + certAnalysis[1]);
                System.out.println("Certificate Public Key: " + certAnalysis[2] + " (" + certAnalysis[3] + " bits)");
            }

            PQCScanResult result = builder.build();

            System.out.println("\n" + result);

            // Assertions
            assertNotNull(result.getTlsVersion());
            assertNotNull(result.getCipherSuite());
            assertTrue(result.isSuccess());

            // Close is inherited from TlsProtocol
        }
    }

    @Test
    void testOPSecUtilPQCDetection() {
        OPSecUtil opsec = OPSecUtil.singleton();

        // Test PQC hybrid detection
        assertTrue(opsec.isPQCHybridKeyExchange("X25519MLKEM768"));
        assertTrue(opsec.isPQCHybridKeyExchange("SecP256r1MLKEM768"));
        assertTrue(opsec.isPQCHybridKeyExchange("X25519Kyber768"));
        assertFalse(opsec.isPQCHybridKeyExchange("x25519"));
        assertFalse(opsec.isPQCHybridKeyExchange("secp256r1"));

        // Test classical ECDHE detection
        assertTrue(opsec.isClassicalECDHE("x25519"));
        assertTrue(opsec.isClassicalECDHE("secp256r1"));
        assertFalse(opsec.isClassicalECDHE("X25519MLKEM768"));

        // Test PQC signature detection
        assertTrue(opsec.isPQCSignatureAlgorithm("ML-DSA-65"));
        assertTrue(opsec.isPQCSignatureAlgorithm("DILITHIUM3"));
        assertFalse(opsec.isPQCSignatureAlgorithm("SHA256withECDSA"));
        assertFalse(opsec.isPQCSignatureAlgorithm("SHA256withRSA"));

        // Test classification
        assertEquals("PQC_HYBRID", opsec.classifyKeyExchange("X25519MLKEM768"));
        assertEquals("ECDHE", opsec.classifyKeyExchange("x25519"));
        assertEquals("DHE", opsec.classifyKeyExchange("DHE_RSA"));
        assertEquals("RSA", opsec.classifyKeyExchange("RSA"));

        assertEquals("PQC_SIGNATURE", opsec.classifySignatureAlgorithm("ML-DSA-65"));
        assertEquals("ECDSA", opsec.classifySignatureAlgorithm("SHA256withECDSA"));
        assertEquals("RSA", opsec.classifySignatureAlgorithm("SHA256withRSA"));
        assertEquals("EDDSA", opsec.classifySignatureAlgorithm("Ed25519"));

        System.out.println("OPSecUtil PQC detection tests passed!");
    }

    @Test
    void testPQCTlsClientHelpers() {
        // Test cipher suite name helper
        assertEquals("TLS_AES_256_GCM_SHA384", PQCTlsClient.getCipherSuiteName(0x1302));
        assertEquals("TLS_AES_128_GCM_SHA256", PQCTlsClient.getCipherSuiteName(0x1301));

        // Test named group helpers
        assertEquals("X25519MLKEM768", PQCTlsClient.getNamedGroupName(0x11EC));
        assertEquals("SecP256r1MLKEM768", PQCTlsClient.getNamedGroupName(0x11EB));
        assertEquals("x25519", PQCTlsClient.getNamedGroupName(29));
        assertEquals("secp256r1", PQCTlsClient.getNamedGroupName(23));

        // Test PQC hybrid detection
        assertTrue(PQCTlsClient.isPQCHybridGroup(0x11EC));  // X25519MLKEM768
        assertTrue(PQCTlsClient.isPQCHybridGroup(0x11EB));  // SecP256r1MLKEM768
        assertFalse(PQCTlsClient.isPQCHybridGroup(29));     // x25519

        System.out.println("PQCTlsClient helper tests passed!");
    }



    /**
     * Test PQCNIOScanner with ScanCallback pattern (handshake only, fully non-blocking)
     */
    @Test
    void testPQCNIOScannerWithStateMachine() throws Exception {
        long overAllTS = System.currentTimeMillis();
        AtomicInteger counter = new AtomicInteger();
        try {
            for (IPAddress address : serversToTest) {
                System.out.println(address);

                long ts = System.currentTimeMillis();
                PQCScanCallback mother = new PQCScanCallback(address, result -> {
                    log.getLogger().info("ScannerMotherCallback result: \n" + result);

                    assertNotNull(result, "Result should not be null");
                    if (result.isSuccess()) {
                        assertTrue(result.isSuccess(), "Scan should succeed");
                        assertNotNull(result.getTlsVersion(), "TLS version should be captured");
                        assertNotNull(result.getCipherSuite(), "Cipher suite should be captured");

                        log.getLogger().info("========== ScannerMotherCallback Result ==========");
                        log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort() + " It took: " + Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
                        log.getLogger().info("TLS Version: " + result.getTlsVersion());
                        log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
                        log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");
                        log.getLogger().info("PQC Ready: " + result.isKeyExchangePqcReady());
                        log.getLogger().info("Overall Status: " + result.getOverallStatus());
                        log.getLogger().info("========================================================");
                    }
                    counter.incrementAndGet();
                }, null, httpNIOSocket);
                mother.dnsResolver(DNSRegistrar.SINGLETON);
                mother.timeoutInSec(5);

                try {
                    mother.start();
                } catch (IOException e) {
                    counter.incrementAndGet();
                    log.getLogger().info(e + " " + Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
                }
            }

            while (counter.get() < serversToTest.length)
                TaskUtil.sleep(25);

            System.out.println("========== ScannerMotherCallback Result ==========  took overAll: " + Const.TimeInMillis.toString(System.currentTimeMillis() - overAllTS));

        } finally {

        }
    }

    @Test
    void testPQCScanResultToNVGenericMap() throws Exception {
        // Create a sample result using the builder
        PQCScanResult result = PQCScanResult.builder("google.com", 443, UUID.randomUUID().toString())
                .success(true)
                .scanTimeMs(150)
                .tlsVersion("TLSv1.3")
                .keyExchange(PQCScanResult.KeyExchangeType.PQC_HYBRID, "X25519MLKEM768")
                .cipherSuite("TLS_AES_256_GCM_SHA384")
                .certSignature(PQCScanResult.SignatureType.ECDSA, "SHA256withECDSA")
                .certPublicKey("ECDSA", 256)
                .build();

        // Convert to NVGenericMap
        org.zoxweb.shared.util.NVGenericMap nvgm = result.toNVGenericMap(false);

        // Verify the conversion
        assertNotNull(nvgm);
        assertEquals("PQCScanResult", nvgm.getName());
        assertEquals("google.com", nvgm.getValue("host"));
        assertEquals(443, (int) nvgm.getValue("port"));
        assertEquals(150L, (long) nvgm.getValue("scan-time-in-ms"));
        assertEquals(true, nvgm.getValue("success"));
        assertEquals("TLSv1.3", nvgm.getValue("tls-version"));
        assertEquals(true, nvgm.getValue("tls-version-pqc-capable"));
        // NVEnum stores the actual enum value, not a String
        assertEquals(PQCScanResult.KeyExchangeType.PQC_HYBRID, nvgm.getValue("key-exchange-type"));
        assertEquals("X25519MLKEM768", nvgm.getValue("key-exchange-algorithm"));
        assertEquals(true, nvgm.getValue("key-exchange-pqc-ready"));
        assertEquals("TLS_AES_256_GCM_SHA384", nvgm.getValue("cipher-suite"));
        assertEquals(PQCScanResult.SignatureType.ECDSA, nvgm.getValue("cert-signature-type"));
        assertEquals("SHA256withECDSA", nvgm.getValue("cert-signature-algorithm"));
        assertEquals("ECDSA", nvgm.getValue("cert-public-key-type"));
        assertEquals(256, (int) nvgm.getValue("cert-public-key-size"));
        assertEquals(PQCScanResult.PQCStatus.READY, nvgm.getValue("overall-status"));

        // Print JSON representation
        String json = org.zoxweb.server.util.GSONUtil.toJSONDefault(nvgm, true);
        System.out.println("PQCScanResult as NVGenericMap JSON:\n" + json);

        System.out.println("testPQCScanResultToNVGenericMap passed!");
    }

    /**
     * Test scanning a non-TLS port (HTTP port 80).
     * Expected: success=false, secure=false, error message indicating TLS failure.
     */
    @Test
    void testScanNonTLSPort() throws Exception {

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        try {
            IPAddress address = new IPAddress("google.com", 80);
            PQCScanCallback mother = new PQCScanCallback(address, result -> {
                log.getLogger().info("Port 80 scan result:\n" + result);
                resultRef.set(result);
                latch.countDown();
            }, null, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(10);
            mother.start();

            boolean completed = latch.await(15, TimeUnit.SECONDS);

            assertTrue(completed, "Scan should complete within timeout");
            PQCScanResult result = resultRef.get();
            assertNotNull(result, "Result should not be null");
            assertFalse(result.isSuccess(), "Scan should fail on non-TLS port");
            assertFalse(result.isSecure(), "Port 80 should not be secure");
            assertNotNull(result.getErrorMessage(), "Error message should be present");

            log.getLogger().info("testScanNonTLSPort passed - port 80 correctly identified as non-secure");
        } finally {

        }
    }

    /**
     * Test ScannerMotherCallback with PQCScanOptions - comprehensive scan including
     * revocation checking, cipher enumeration, and protocol version testing.
     */
    @Test
    void testPQCNIOScannerWithOptions() throws Exception {
        // Create options with all features enabled
        PQCScanOptions options = PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(10000)
                .enumerateCiphers(true)
                .testProtocolVersions(true)
                .testTLS10(true)
                .testTLS11(true)
                .testSSLv3(false)
                .build();


        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        try {
            IPAddress address = new IPAddress("google.com", 443);
            PQCScanCallback mother = new PQCScanCallback(address, result -> {
                log.getLogger().info("ScannerMotherCallback with options result:\n" + result);
                resultRef.set(result);
                latch.countDown();
            }, options, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(60);
            mother.start();

            boolean completed = latch.await(90, TimeUnit.SECONDS);

            assertTrue(completed, "Scan should complete within timeout");
            PQCScanResult result = resultRef.get();
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());
            assertNotNull(result.getTlsVersion(), "TLS version should be captured");
            assertNotNull(result.getCipherSuite(), "Cipher suite should be captured");

            // Verify additional features were executed
            log.getLogger().info("========== ScannerMotherCallback with Options Result ==========");
            log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort());
            log.getLogger().info("TLS Version: " + result.getTlsVersion());
            log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
            log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");

            // Revocation check results
            log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
            log.getLogger().info("Cert Revoked: " + result.isCertRevoked());
            if (result.getRevocationError() != null) {
                log.getLogger().info("Revocation Error: " + result.getRevocationError());
            }

            // Cipher enumeration results
            if (result.getSupportedCipherSuites() != null) {
                log.getLogger().info("Supported Cipher Suites: " + result.getSupportedCipherSuites().size());
                for (CipherSuiteEnumerator.CipherInfo cipher : result.getSupportedCipherSuites()) {
                    log.getLogger().info("  - " + cipher.getName() + " [" + cipher.getStrength() + "]");
                }
                log.getLogger().info("Server Cipher Preference: " + result.getServerCipherPreference());
            }

            // Protocol version results
            if (result.getSupportedProtocolVersions() != null) {
                log.getLogger().info("Supported Protocol Versions: " + result.getSupportedProtocolVersions());
                log.getLogger().info("SSLv3 Supported: " + result.isSslv3Supported());
                log.getLogger().info("Deprecated Protocols: " + result.isDeprecatedProtocolsSupported());
            }

            log.getLogger().info("Overall Status: " + result.getOverallStatus());
            log.getLogger().info("Recommendations: " + result.getRecommendations());
            log.getLogger().info("========================================================");

        } finally {

        }
    }

    /**
     * Test ScannerMotherCallback with revocation checking only.
     */
    @Test
    void testPQCNIOScannerWithRevocationOnly() throws Exception {
        PQCScanOptions options = PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(15000)
                .build();


        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        try {
            IPAddress address = new IPAddress("cloudflare.com", 443);
            PQCScanCallback mother = new PQCScanCallback(address, result -> {
                resultRef.set(result);
                latch.countDown();
            }, options, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(30);
            mother.start();

            boolean completed = latch.await(45, TimeUnit.SECONDS);

            assertTrue(completed, "Scan should complete within timeout");
            PQCScanResult result = resultRef.get();
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());

            // Verify revocation was checked
            log.getLogger().info("=== Revocation Check Results ===");
            log.getLogger().info("Host: " + result.getHost());
            log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
            log.getLogger().info("Cert Revoked: " + result.isCertRevoked());

            // Revocation method should be set if check was performed
            if (result.getRevocationMethod() != null) {
                assertNotNull(result.isCertRevoked(), "Cert revoked status should be set");
            }

        } finally {

        }
    }

    @AfterAll
    static void tearDownAll() {
        SharedIOUtil.close(httpNIOSocket.getNIOSocket());
        TaskUtil.close();;
    }
}
