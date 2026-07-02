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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Test ScannerMotherCallback against real TLS servers.
 */
public class PQCCallbackTest {

    public static final LogWrapper log = new LogWrapper(PQCCallbackTest.class).setEnabled(true);

    private static final IPAddress[] serversToTest = IPAddress.parseList(
            "https://xlogistx.io",
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
        OPSecUtil.singleton();
        DNSRegistrar.SINGLETON.setResolver("10.0.0.1");
        httpNIOSocket = new HTTPNIOSocket(new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler()));
    }

    @Test
    void testBasicScan() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        IPAddress address = new IPAddress("google.com", 443);
        PQCScanCallback mother = new PQCScanCallback(address, result -> {
            log.getLogger().info("Basic scan result:\n" + result);
            resultRef.set(result);
            latch.countDown();
        }, null, httpNIOSocket);
        mother.dnsResolver(DNSRegistrar.SINGLETON);
        mother.timeoutInSec(10);
        mother.start();

        boolean completed = latch.await(30, TimeUnit.SECONDS);
        assertTrue(completed, "Scan should complete within timeout");

        PQCScanResult result = resultRef.get();
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());
        assertNotNull(result.getTlsVersion(), "TLS version should be captured");
        assertNotNull(result.getCipherSuite(), "Cipher suite should be captured");

        log.getLogger().info("========== Basic Scan Result ==========");
        log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort());
        log.getLogger().info("TLS Version: " + result.getTlsVersion());
        log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
        log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");
        log.getLogger().info("Overall Status: " + result.getOverallStatus());
        log.getLogger().info("========================================");
    }

    @Test
    void testComprehensiveScan() throws Exception {
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

        IPAddress address = new IPAddress("google.com", 443);
        PQCScanCallback mother = new PQCScanCallback(address, result -> {
            log.getLogger().info("Comprehensive scan result:\n" + result);
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

        log.getLogger().info("========== Comprehensive Scan Result ==========");
        log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort());
        log.getLogger().info("TLS Version: " + result.getTlsVersion());
        log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
        log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");

        // Revocation
        log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
        log.getLogger().info("Cert Revoked: " + result.isCertRevoked());

        // Ciphers
        if (result.getSupportedCipherSuites() != null) {
            log.getLogger().info("Supported Cipher Suites: " + result.getSupportedCipherSuites().size());
            for (CipherSuiteEnumerator.CipherInfo cipher : result.getSupportedCipherSuites()) {
                log.getLogger().info("  - " + cipher.getName() + " [" + cipher.getStrength() + "]");
            }
            log.getLogger().info("Server Cipher Preference: " + result.getServerCipherPreference());
        }

        // Versions
        if (result.getSupportedProtocolVersions() != null) {
            log.getLogger().info("Supported Protocol Versions: " + result.getSupportedProtocolVersions());
            log.getLogger().info("SSLv3 Supported: " + result.isSslv3Supported());
            log.getLogger().info("Deprecated Protocols: " + result.isDeprecatedProtocolsSupported());
        }

        log.getLogger().info("Overall Status: " + result.getOverallStatus());
        log.getLogger().info("Recommendations: " + result.getRecommendations());
        log.getLogger().info("=================================================");
    }

    @Test
    void testRevocationOnly() throws Exception {
        PQCScanOptions options = PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(15000)
                .build();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

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

        log.getLogger().info("=== Revocation Only Results ===");
        log.getLogger().info("Host: " + result.getHost());
        log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
        log.getLogger().info("Cert Revoked: " + result.isCertRevoked());
    }

    @Test
    void testNonTLSPort() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

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

        log.getLogger().info("testNonTLSPort passed - port 80 correctly identified as non-secure");
    }

    @Test
    void testMultipleTargets() throws Exception {
        long overAllTS = System.currentTimeMillis();
        AtomicInteger counter = new AtomicInteger();

        for (IPAddress address : serversToTest) {
            log.getLogger().info("Scanning: " + address);

            long ts = System.currentTimeMillis();
            PQCScanCallback mother = new PQCScanCallback(address, result -> {
                log.getLogger().info("Result for " + result.getHost() + ":" + result.getPort() +
                        " - " + result.getOverallStatus() + " in " +
                        Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
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

        log.getLogger().info("========== Multiple Targets Result ==========  took overAll: " +
                Const.TimeInMillis.toString(System.currentTimeMillis() - overAllTS));
    }

    /**
     * Detailed (comprehensive) scan against google.com, xlogistx.io and upbound.io.
     * <p>
     * This mirrors the {@code detailed=true} branch of QDZChecker (revocation +
     * cipher enumeration + protocol-version testing) and serves as a regression
     * guard for the post-connect probe-timeout hang: google.com previously
     * passed while xlogistx.io / upbound.io hung forever because their probes
     * never reported a result. The bounded {@code latch.await(...)} turns a
     * hang into a test failure instead of stalling the whole suite.
     */
    @Test
    void testDetailedScanMultipleHosts() throws Exception {
        IPAddress[] hosts = IPAddress.parseList(
                "google.com:443",
                "https://xlogistx.io",
                "https://upbound.io");

        for (IPAddress host : hosts) {
            PQCScanOptions options = PQCScanOptions.builder()
                    .checkRevocation(true)
                    .revocationTimeoutMs(5000)
                    .enumerateCiphers(true)
                    .testProtocolVersions(true)
                    .testTLS10(true)
                    .testTLS11(true)
                    .testSSLv3(false)
                    .build();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

            long ts = System.currentTimeMillis();
            PQCScanCallback mother = new PQCScanCallback(host, result -> {
                resultRef.set(result);
                latch.countDown();
            }, options, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(15);
            mother.overallTimeoutInSec(60);   // master watchdog
            mother.start();

            // With the watchdog the callback is guaranteed to fire; allow a
            // little slack over overallTimeoutInSec for scheduler/delivery.
            boolean completed = latch.await(75, TimeUnit.SECONDS);
            assertTrue(completed, "Detailed scan for " + host +
                    " did not fire callback within 75s even with watchdog " +
                    "(scheduler not running?)");

            PQCScanResult result = resultRef.get();
            assertNotNull(result, "Result should not be null for " + host);

            log.getLogger().info("========== Detailed Scan: " + host + " ==========  took " +
                    Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
            log.getLogger().info("Success: " + result.isSuccess() +
                    " Status: " + result.getOverallStatus());

            // The watchdog stamps an error message describing exactly which
            // stage was still pending. If it fired, fail fast WITH that
            // diagnosis instead of letting weak assertions hide the stall.
            assertNull(result.getErrorMessage(),
                    "Detailed scan for " + host + " did not complete cleanly: "
                            + result.getErrorMessage());

            assertTrue(result.isSuccess(), "Scan should succeed for " + host);
            assertNotNull(result.getTlsVersion(), "TLS version should be captured for " + host);
            assertNotNull(result.getCipherSuite(), "Cipher suite should be captured for " + host);

            // Detailed payload must actually be populated, not silently empty.
            assertNotNull(result.getSupportedProtocolVersions(),
                    "Detailed scan should report protocol versions for " + host);
            assertFalse(result.getSupportedProtocolVersions().isEmpty(),
                    "Protocol version list should be non-empty for " + host);
            assertNotNull(result.getSupportedCipherSuites(),
                    "Detailed scan should report cipher suites for " + host);
            assertFalse(result.getSupportedCipherSuites().isEmpty(),
                    "Cipher suite list should be non-empty for " + host);

            // The detailed serialization path used by the REST endpoint.
            org.zoxweb.shared.util.NVGenericMap nvgm = result.toNVGenericMap(true);
            assertNotNull(nvgm, "Detailed NVGenericMap should not be null for " + host);
            assertEquals(true, nvgm.getValue("success"));
            assertNotNull(nvgm.getValue("supported-protocol-versions"),
                    "Detailed map should include supported-protocol-versions for " + host);

            log.getLogger().info("TLS: " + result.getTlsVersion() +
                    " Versions: " + result.getSupportedProtocolVersions() +
                    " Ciphers: " + result.getSupportedCipherSuites().size() +
                    " RevocationMethod: " + result.getRevocationMethod());
            log.getLogger().info("====================================================");
        }
    }

    /**
     * Certificate TRUST scenarios (badssl.com fixtures). Verifies that a
     * trust failure forces overall-status = UNTRUSTED regardless of PQC
     * readiness, that EXPIRED vs NOT_YET_VALID is distinguished, and that a
     * hostname mismatch is report-only (does NOT force UNTRUSTED).
     * <p>
     * The TLS handshake itself succeeds for all of these (we don't validate in
     * the handshake), so the post-hoc PKIX/expiry/hostname checks are what's
     * under test. Network-unreachable cases are skipped, not failed.
     */
    @Test
    void testCertificateTrust() throws Exception {
        String[] hosts = {
                "https://expired.badssl.com",
                "https://self-signed.badssl.com",
                "https://untrusted-root.badssl.com",
                "https://wrong.host.badssl.com",
                "https://badssl.com",
                "https://xlogistx.io",
        };

        for (String host : hosts) {
            IPAddress addr = IPAddress.parse(host);
            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<PQCScanResult> ref = new AtomicReference<>();

            PQCScanCallback mother = new PQCScanCallback(addr, result -> {
                ref.set(result);
                latch.countDown();
            }, null, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(15);
            mother.overallTimeoutInSec(45);
            mother.start();

            assertTrue(latch.await(60, TimeUnit.SECONDS),
                    "scan of " + host + " did not complete");
            PQCScanResult r = ref.get();
            assertNotNull(r);

            // Don't fail the build on env/network inability to reach badssl.
            assumeTrue(r.isSuccess(),
                    "skipping " + host + " - not reachable: " + r.getErrorMessage());

            log.getLogger().info("[trust] " + host
                    + " state=" + r.getCertValidityState()
                    + " chainValid=" + r.isCertChainValid()
                    + " trust=" + r.getCertChainTrust()
                    + " hostnameValid=" + r.isCertHostnameValid()
                    + " overall=" + r.getOverallStatus());

            if (host.contains("expired.")) {
                assertEquals(PQCScanResult.CertValidityState.EXPIRED, r.getCertValidityState(),
                        "expired.badssl.com leaf should be EXPIRED");
                assertEquals(PQCScanResult.PQCStatus.UNTRUSTED, r.getOverallStatus(),
                        "expired cert must force UNTRUSTED regardless of PQC");
                assertEquals(PQCScanResult.TrustVerdict.EXPIRED, r.getTrustVerdict(),
                        "trust-verdict should be EXPIRED");
                assertNotNull(r.getTrustReason(), "trust-reason should be populated");
            } else if (host.contains("self-signed.")) {
                assertEquals(Boolean.FALSE, r.isCertChainValid(), "self-signed chain is not trusted");
                assertEquals("SELF_SIGNED", r.getCertChainTrust());
                assertEquals(PQCScanResult.PQCStatus.UNTRUSTED, r.getOverallStatus());
            } else if (host.contains("untrusted-root.")) {
                assertEquals(Boolean.FALSE, r.isCertChainValid(),
                        "untrusted-root chain does not anchor to a trusted CA");
                assertEquals(PQCScanResult.PQCStatus.UNTRUSTED, r.getOverallStatus());
            } else if (host.contains("wrong.host.")) {
                // Cert is valid & trusted but for the wrong name: report-only.
                assertEquals(Boolean.FALSE, r.isCertHostnameValid(),
                        "wrong.host.badssl.com should fail hostname match");
                assertNotEquals(PQCScanResult.PQCStatus.UNTRUSTED, r.getOverallStatus(),
                        "hostname mismatch is report-only, must NOT force UNTRUSTED");
            } else { // badssl.com control
                assertEquals(PQCScanResult.CertValidityState.VALID, r.getCertValidityState());
                assertEquals(Boolean.TRUE, r.isCertChainValid(),
                        "badssl.com should anchor to a trusted root");
                assertEquals("TRUSTED", r.getCertChainTrust());
                assertEquals(Boolean.TRUE, r.isCertHostnameValid());
                assertNotEquals(PQCScanResult.PQCStatus.UNTRUSTED, r.getOverallStatus());
                assertEquals(PQCScanResult.TrustVerdict.TRUSTED, r.getTrustVerdict(),
                        "badssl.com trust-verdict should be TRUSTED");
            }
        }
    }

    @AfterAll
    static void tearDownAll() {
        SharedIOUtil.close(httpNIOSocket.getNIOSocket());
        TaskUtil.close();
    }
}
