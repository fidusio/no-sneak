package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.DNSResolverInt;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Main orchestrator for PQC scanning using pure NIO callbacks.
 * Replaces the CompletableFuture/ForkJoinPool approach with callback-driven child probes.
 * <p>
 * Usage:
 * <pre>
 *   ScannerMotherCallback mother = new ScannerMotherCallback(ip, result -> {...}, options, httpNIOSocket);
 *   mother.dnsResolver(dnsRegistrar);
 *   mother.timeoutInSec(10);
 *   mother.start();
 * </pre>
 */
public class PQCScanCallback implements ScanCallback {

    public static final LogWrapper log = new LogWrapper(PQCScanCallback.class).setEnabled(false);

    private final IPAddress address;
    private final Consumer<PQCScanResult> userCallback;
    private final PQCScanOptions options;
    private final HTTPNIOSocket httpNIOSocket;

    private final long startTime;

    // Phase 1 scanner
    private PQCNIOScanner scanner;

    // DNS and timeout config (forwarded to PQCNIOScanner)
    private DNSResolverInt dnsResolver;
    private int timeoutSec = 10;

    // Hard upper bound on the WHOLE scan. This is a safety net: even if a
    // child probe never reports, the selector thread wedges, or the
    // pendingCount accounting is off by one, the user callback is still
    // guaranteed to fire (with a partial / error result) instead of hanging
    // forever. 0 (or negative) disables the watchdog.
    private int overallTimeoutSec = 90;
    private volatile ScheduledFuture<?> scanDeadline;

    // Phase 2 coordination
    private final AtomicInteger pendingCount = new AtomicInteger(0);
    private volatile PQCScanResult.Builder resultBuilder;

    // Cipher enumeration state
    private final List<CipherSuiteEnumerator.CipherInfo> collectedCiphers = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean tls13CiphersDone = false;
    private volatile boolean tls12CiphersDone = false;
    private volatile Boolean serverCipherPreference = null;

    // Version testing state
    private final List<String> supportedVersions = Collections.synchronizedList(new ArrayList<>());

    // Completion guard
    private volatile boolean delivered = false;

    public PQCScanCallback(IPAddress address, Consumer<PQCScanResult> userCallback,
                           PQCScanOptions options, HTTPNIOSocket httpNIOSocket) {
        this.address = address;
        this.userCallback = userCallback;
        this.options = options != null ? options : PQCScanOptions.defaults();
        this.httpNIOSocket = httpNIOSocket;
        this.startTime = System.currentTimeMillis();
    }

    /**
     * Set the DNS resolver for address resolution.
     */
    public PQCScanCallback dnsResolver(DNSResolverInt resolver) {
        this.dnsResolver = resolver;
        return this;
    }

    /**
     * Set the connection timeout in seconds.
     */
    public PQCScanCallback timeoutInSec(int seconds) {
        this.timeoutSec = seconds;
        return this;
    }

    /**
     * Hard upper bound (seconds) on the entire scan, after which the user
     * callback is delivered with whatever has been collected (or an error).
     * Set to {@code <= 0} to disable. Defaults to 90s.
     */
    public PQCScanCallback overallTimeoutInSec(int seconds) {
        this.overallTimeoutSec = seconds;
        return this;
    }

    /**
     * Start the scan by creating a PQCNIOScanner and registering it with NIOSocket.
     */
    public void start() throws IOException {
        scanner = new PQCNIOScanner(address, this);
        if (dnsResolver != null) {
            scanner.dnsResolver(dnsResolver);
        }
        scanner.timeoutInSec(timeoutSec);

        // Arm the master watchdog BEFORE registering the scanner so a failure
        // anywhere (Phase 1 or Phase 2) is still bounded.
        if (overallTimeoutSec > 0) {
            scanDeadline = TaskUtil.defaultTaskScheduler()
                    .schedule(this::onScanTimeout, overallTimeoutSec, TimeUnit.SECONDS);
        }

        httpNIOSocket.getNIOSocket().addClientSocket(scanner);
    }

    /**
     * Master watchdog. Fired by the scheduler if the scan has not delivered a
     * result within {@link #overallTimeoutSec}. Delivers a partial result
     * (whatever Phase 1 / Phase 2 collected) or an error, and records exactly
     * which stage was still pending so the stall is diagnosable.
     */
    private void onScanTimeout() {
        if (delivered) {
            return;
        }

        String stage = "pending=" + pendingCount.get()
                + " tls13Ciphers=" + tls13CiphersDone
                + " tls12Ciphers=" + tls12CiphersDone
                + " collectedCiphers=" + collectedCiphers.size()
                + " versions=" + supportedVersions
                + " resultBuilder=" + (resultBuilder != null);

        if (log.isEnabled()) {
            log.getLogger().info("Scan watchdog fired for " + address + " [" + stage + "]");
        }

        if (resultBuilder != null) {
            // Phase 1 succeeded; deliver whatever Phase 2 managed to collect.
            resultBuilder.errorMessage("Scan timed out after " + overallTimeoutSec
                    + "s; partial result [" + stage + "]");
            deliverResult();
        } else {
            // Never even completed the handshake.
            onError("Scan timed out after " + overallTimeoutSec + "s before handshake [" + stage + "]");
        }
    }

    private void cancelScanDeadline() {
        ScheduledFuture<?> a = scanDeadline;
        if (a != null) {
            scanDeadline = null;
            try {
                // cancel(false): the watchdog may be firing on the scheduler
                // thread right now - never interrupt that worker.
                a.cancel(false);
            } catch (Exception ignored) {
            }
        }
    }

    // ==================== ScanCallback Implementation ====================

    @Override
    public void onHandshakeComplete(PQCSessionConfig config) {
        try {
            PQCTlsClient tlsClient = config.tlsClient;
            String hostname = config.getHostname();
            int port = address.getPort();

            resultBuilder = PQCScanResult.builder(hostname, port, scanner.getID())
                    .scanTimeMs(System.currentTimeMillis() - startTime)
                    .success(true);

            // TLS Version
            String tlsVersion = tlsClient.getNegotiatedVersionString();
            resultBuilder.tlsVersion(tlsVersion);

            // Cipher Suite
            String cipherSuite = tlsClient.getNegotiatedCipherSuiteName();
            resultBuilder.cipherSuite(cipherSuite);

            // Key Exchange
            String keyExchangeAlg = tlsClient.getNegotiatedKeyExchangeName();
            if ("UNKNOWN".equals(keyExchangeAlg) || keyExchangeAlg == null) {
                keyExchangeAlg = tlsClient.getKeyExchangeAlgorithm();
            }

            OPSecUtil opsec = OPSecUtil.singleton();
            String kexType = opsec.classifyKeyExchange(keyExchangeAlg);
            PQCScanResult.KeyExchangeType keyExchangeType = PQCNIOScanner.parseKeyExchangeType(kexType);
            resultBuilder.keyExchange(keyExchangeType, keyExchangeAlg);

            // Certificate analysis
            X509Certificate[] chain = null;
            Certificate serverCert = tlsClient.getServerCertificate();
            if (serverCert != null && serverCert.getLength() > 0) {
                chain = PQCNIOScanner.convertCertificateChain(serverCert);

                if (chain != null && chain.length > 0) {
                    X509Certificate leafCert = chain[0];
                    String[] certAnalysis = opsec.analyzeCertificatePQC(leafCert);

                    PQCScanResult.SignatureType sigType = PQCNIOScanner.parseSignatureType(certAnalysis[0]);
                    resultBuilder.certSignature(sigType, certAnalysis[1]);
                    resultBuilder.certPublicKey(certAnalysis[2], Integer.parseInt(certAnalysis[3]));
                    resultBuilder.certValidity(leafCert);

                    // Real PKIX validation: does the chain anchor to a trusted
                    // Root CA? (replaces the old signature-linkage-only check)
                    OPSecUtil.ChainTrustResult ctr = opsec.validateChain(chain);
                    resultBuilder.certChainTrust(ctr.getTrust().name(),
                            ctr.isTrusted(), ctr.getMessage());

                    // Servers don't send the Root CA in the handshake (the
                    // client is expected to have it). Append the trusted root
                    // resolved from the local trust store so the reported chain
                    // is complete (leaf -> intermediate(s) -> root). Skip if the
                    // server already terminated the chain with a self-signed root.
                    X509Certificate[] displayChain = chain;
                    X509Certificate root = ctr.getTrustAnchor();
                    X509Certificate last = chain[chain.length - 1];
                    boolean serverSentRoot = last.getSubjectX500Principal()
                            .equals(last.getIssuerX500Principal());
                    if (root != null && !serverSentRoot) {
                        displayChain = java.util.Arrays.copyOf(chain, chain.length + 1);
                        displayChain[chain.length] = root;
                    }
                    resultBuilder.certificateChain(displayChain);

                    // Time-validity of the WHOLE chain (intermediates/root too)
                    boolean chainTimeValid = true;
                    for (X509Certificate c : displayChain) {
                        try {
                            c.checkValidity();
                        } catch (Exception expiredOrNotYet) {
                            chainTimeValid = false;
                            break;
                        }
                    }
                    resultBuilder.certChainTimeValid(chainTimeValid);

                    // RFC 6125 hostname match vs the scanned host (report-only)
                    OPSecUtil.HostnameResult hn = opsec.matchesHostname(leafCert, hostname);
                    resultBuilder.certHostname(hn.isMatched(),
                            hn.isMatched() ? null : hn.getMessage());
                }
            }

            // Count and launch Phase 2 tasks
            int taskCount = 0;

            // Revocation check
            boolean doRevocation = options.isCheckRevocation() && chain != null && chain.length > 0;
            if (doRevocation) taskCount++;

            // Cipher enumeration
            boolean doCiphers = options.isEnumerateCiphers();
            if (doCiphers) taskCount++;

            // Version testing
            List<ProtocolVersion> versionsToTest = getVersionsToTest();
            if (options.isTestProtocolVersions() && !versionsToTest.isEmpty()) {
                taskCount += versionsToTest.size();
            }

            // If no Phase 2 tasks, deliver immediately
            if (taskCount == 0) {
                deliverResult();
                return;
            }

            pendingCount.set(taskCount);

            // Launch revocation check
            if (doRevocation) {
                X509Certificate cert = chain[0];
                X509Certificate issuer = chain.length > 1 ? chain[1] : null;
                // Free, instant revocation status if the server stapled it
                // during the handshake (RFC 6066). Otherwise the checker
                // short-circuits (no OCSP/issuer -> NOT_CHECKED) or does one
                // short, soft-fail active OCSP call - never a CRL black hole.
                byte[] stapledOCSP = tlsClient.getStapledOCSPResponse();
                NIORevocationChecker checker = new NIORevocationChecker(httpNIOSocket, options.getRevocationTimeoutMs());
                checker.checkRevocation(cert, issuer, stapledOCSP, this::onRevocationComplete);
            }

            // Launch cipher enumeration
            if (doCiphers) {
                launchCipherEnumeration(hostname);
            }

            // Launch version probes in parallel
            if (options.isTestProtocolVersions() && !versionsToTest.isEmpty()) {
                for (ProtocolVersion version : versionsToTest) {
                    launchVersionProbe(hostname, version);
                }
            }

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error processing handshake result: " + e.getMessage());
            }
            onError("Error processing result: " + e.getMessage());
        }
    }

    @Override
    public synchronized void onError(String errorMessage) {
        if (delivered) return;
        delivered = true;
        cancelScanDeadline();

        long scanTime = System.currentTimeMillis() - startTime;
        PQCScanResult result = PQCScanResult.builder(
                        address.getInetAddress(), address.getPort(),
                        scanner != null ? scanner.getID() : "unknown")
                .scanTimeMs(scanTime)
                .errorMessage(errorMessage)
                .build();

        userCallback.accept(result);
    }

    // ==================== Phase 2: Revocation ====================

    private void onRevocationComplete(OPSecUtil.RevocationResult revResult) {
        if (resultBuilder != null && revResult != null) {
            resultBuilder.revocationResult(revResult);
        }
        checkCompletion();
    }

    // ==================== Phase 2: Cipher Enumeration ====================

    private void launchCipherEnumeration(String hostname) {
        // Start TLS 1.3 enumeration chain
        Set<Integer> tls13Remaining = new LinkedHashSet<>();
        for (int c : OPSecUtil.ALL_TLS13_CIPHERS) tls13Remaining.add(c);

        // Start TLS 1.2 enumeration chain
        Set<Integer> tls12Remaining = new LinkedHashSet<>();
        for (int c : OPSecUtil.ALL_TLS12_STRONG) tls12Remaining.add(c);
        if (options.isIncludeWeakCiphers()) {
            for (int c : OPSecUtil.ALL_TLS12_WEAK) tls12Remaining.add(c);
        }
        if (options.isIncludeInsecureCiphers()) {
            for (int c : OPSecUtil.ALL_TLS12_INSECURE) tls12Remaining.add(c);
        }

        // Launch TLS 1.3 chain first
        launchNextCipherProbe(hostname, ProtocolVersion.TLSv13, tls13Remaining, tls12Remaining);
    }

    private void launchNextCipherProbe(String hostname, ProtocolVersion version,
                                       Set<Integer> remaining, Set<Integer> tls12Remaining) {
        if (remaining.isEmpty()) {
            if (version.equals(ProtocolVersion.TLSv13)) {
                tls13CiphersDone = true;
                // Start TLS 1.2 chain
                if (!tls12Remaining.isEmpty()) {
                    launchNextCipherProbe(hostname, ProtocolVersion.TLSv12, tls12Remaining, tls12Remaining);
                } else {
                    tls12CiphersDone = true;
                    onCipherEnumerationDone(hostname);
                }
            } else {
                tls12CiphersDone = true;
                onCipherEnumerationDone(hostname);
            }
            return;
        }

        int[] ciphers = remaining.stream().mapToInt(Integer::intValue).toArray();
        IPAddress probeAddress = new IPAddress(address.getInetAddress(), address.getPort());

        CipherProbeCallback probe = new CipherProbeCallback(
                probeAddress, hostname, version, ciphers,
                (ver, cipherId) -> {
                    if (cipherId != null) {
                        // Record the supported cipher
                        String cipherName = PQCTlsClient.getCipherSuiteName(cipherId);
                        OPSecUtil.CipherComponents components = OPSecUtil.singleton().parseCipherSuite(cipherName);
                        collectedCiphers.add(new CipherSuiteEnumerator.CipherInfo(cipherId, components));
                        remaining.remove(cipherId);
                        // Continue probing
                        launchNextCipherProbe(hostname, ver, remaining, tls12Remaining);
                    } else {
                        // No more ciphers for this version
                        if (ver.equals(ProtocolVersion.TLSv13)) {
                            tls13CiphersDone = true;
                            if (!tls12Remaining.isEmpty()) {
                                launchNextCipherProbe(hostname, ProtocolVersion.TLSv12, tls12Remaining, tls12Remaining);
                            } else {
                                tls12CiphersDone = true;
                                onCipherEnumerationDone(hostname);
                            }
                        } else {
                            tls12CiphersDone = true;
                            onCipherEnumerationDone(hostname);
                        }
                    }
                }
        );

        if (dnsResolver != null) {
            probe.dnsResolver(dnsResolver);
        }
        probe.timeoutInSec(Math.max(timeoutSec, 5));

        try {
            httpNIOSocket.getNIOSocket().addClientSocket(probe);
        } catch (IOException e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to launch cipher probe: " + e.getMessage());
            }
            // Treat as enumeration done for this version
            if (version.equals(ProtocolVersion.TLSv13)) {
                tls13CiphersDone = true;
                if (!tls12Remaining.isEmpty()) {
                    launchNextCipherProbe(hostname, ProtocolVersion.TLSv12, tls12Remaining, tls12Remaining);
                } else {
                    tls12CiphersDone = true;
                    onCipherEnumerationDone(hostname);
                }
            } else {
                tls12CiphersDone = true;
                onCipherEnumerationDone(hostname);
            }
        }
    }

    private void onCipherEnumerationDone(String hostname) {
        if (!tls13CiphersDone || !tls12CiphersDone) return;

        // Check server cipher preference if we have at least 2 ciphers
        if (collectedCiphers.size() >= 2) {
            checkServerCipherPreference(hostname);
        } else {
            // Apply results directly
            applyCollectedCiphers();
            checkCompletion();
        }
    }

    private void checkServerCipherPreference(String hostname) {
        int cipher1 = collectedCiphers.get(0).getId();
        int cipher2 = collectedCiphers.get(1).getId();
        IPAddress probeAddr1 = new IPAddress(address.getInetAddress(), address.getPort());
        IPAddress probeAddr2 = new IPAddress(address.getInetAddress(), address.getPort());

        final Integer[] results = new Integer[2];
        final AtomicInteger prefCount = new AtomicInteger(2);

        // Test with cipher1 first
        CipherProbeCallback probe1 = new CipherProbeCallback(
                probeAddr1, hostname, ProtocolVersion.TLSv12,
                new int[]{cipher1, cipher2},
                (ver, cipherId) -> {
                    results[0] = cipherId;
                    if (prefCount.decrementAndGet() == 0) {
                        serverCipherPreference = results[0] != null && results[0].equals(results[1]);
                        applyCollectedCiphers();
                        checkCompletion();
                    }
                }
        );
        if (dnsResolver != null) probe1.dnsResolver(dnsResolver);
        probe1.timeoutInSec(Math.max(timeoutSec, 5));

        // Test with cipher2 first
        CipherProbeCallback probe2 = new CipherProbeCallback(
                probeAddr2, hostname, ProtocolVersion.TLSv12,
                new int[]{cipher2, cipher1},
                (ver, cipherId) -> {
                    results[1] = cipherId;
                    if (prefCount.decrementAndGet() == 0) {
                        serverCipherPreference = results[0] != null && results[0].equals(results[1]);
                        applyCollectedCiphers();
                        checkCompletion();
                    }
                }
        );
        if (dnsResolver != null) probe2.dnsResolver(dnsResolver);
        probe2.timeoutInSec(Math.max(timeoutSec, 5));

        try {
            httpNIOSocket.getNIOSocket().addClientSocket(probe1);
            httpNIOSocket.getNIOSocket().addClientSocket(probe2);
        } catch (IOException e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to launch preference probes: " + e.getMessage());
            }
            applyCollectedCiphers();
            checkCompletion();
        }
    }

    private void applyCollectedCiphers() {
        if (resultBuilder != null) {
            resultBuilder.supportedCipherSuites(new ArrayList<>(collectedCiphers));
            resultBuilder.serverCipherPreference(serverCipherPreference);
        }
    }

    // ==================== Phase 2: Version Testing ====================

    private List<ProtocolVersion> getVersionsToTest() {
        List<ProtocolVersion> versions = new ArrayList<>();
        versions.add(ProtocolVersion.TLSv13);
        versions.add(ProtocolVersion.TLSv12);
        if (options.isTestTLS11()) versions.add(ProtocolVersion.TLSv11);
        if (options.isTestTLS10()) versions.add(ProtocolVersion.TLSv10);
        if (options.isTestSSLv3()) versions.add(ProtocolVersion.SSLv3);
        return versions;
    }

    private void launchVersionProbe(String hostname, ProtocolVersion version) {
        IPAddress probeAddress = new IPAddress(address.getInetAddress(), address.getPort());

        VersionProbeCallback probe = new VersionProbeCallback(
                probeAddress, hostname, version,
                (versionName, supported) -> {
                    if (supported) {
                        supportedVersions.add(versionName);
                    }
                    checkCompletion();
                }
        );

        if (dnsResolver != null) {
            probe.dnsResolver(dnsResolver);
        }
        probe.timeoutInSec(Math.max(timeoutSec, 5));

        try {
            httpNIOSocket.getNIOSocket().addClientSocket(probe);
        } catch (IOException e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to launch version probe for " +
                        ProtocolVersionTester.getVersionName(version) + ": " + e.getMessage());
            }
            checkCompletion();
        }
    }

    // ==================== Completion ====================

    private void checkCompletion() {
        if (pendingCount.decrementAndGet() == 0) {
            deliverResult();
        }
    }

    private synchronized void deliverResult() {
        if (delivered) return;

        if (resultBuilder == null) {
            // Delegate WITHOUT marking delivered first, otherwise onError()
            // would no-op and the user callback would never fire (hang).
            onError("No result builder available");
            return;
        }

        delivered = true;
        cancelScanDeadline();

        // Apply version testing results
        if (!supportedVersions.isEmpty()) {
            resultBuilder.supportedProtocolVersions(new ArrayList<>(supportedVersions));
            boolean sslv3 = supportedVersions.contains("SSLv3");
            boolean deprecated = sslv3 || supportedVersions.contains("TLSv1.0") || supportedVersions.contains("TLSv1.1");
            resultBuilder.sslv3Supported(sslv3);
            resultBuilder.deprecatedProtocolsSupported(deprecated);
        }

        PQCScanResult result = resultBuilder.build();
        result.scanTimeMs = System.currentTimeMillis() - startTime;

        if (log.isEnabled()) {
            log.getLogger().info("Scan complete for " + address + ": " + result.getOverallStatus());
        }

        userCallback.accept(result);
    }
}
