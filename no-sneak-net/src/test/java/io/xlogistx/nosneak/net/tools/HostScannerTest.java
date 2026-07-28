package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.ResolveSource;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The degradation contract, which is what an embedding UI actually programs
 * against: a scanner always exists, says what it can do, and fails operations it
 * cannot perform with a reason rather than an empty result.
 * <p>
 * Uses the offline seam, so nothing here opens a socket or a pcap handle.
 */
public class HostScannerTest {

    private static final InetAddress IP = InetAddress.ofLiteral("10.0.0.1");

    private static Throwable causeOf(CompletableFuture<?> f) {
        ExecutionException e = assertThrows(ExecutionException.class, f::get);
        return e.getCause();
    }

    private static void assertFailsWith(CompletableFuture<?> f, String fragment) {
        Throwable cause = causeOf(f);
        assertTrue(cause instanceof DiscoveryException,
                   "expected a DiscoveryException, got " + cause);
        assertTrue(cause.getMessage().contains(fragment),
                   "expected '" + fragment + "' in: " + cause.getMessage());
    }

    @Test
    public void unavailableModeAdvertisesWhatItCannotDo() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.UNAVAILABLE, "Npcap not installed")) {
            assertFalse(s.mode().canPing());
            assertFalse(s.mode().canLayer2());
            assertTrue(s.interfaces().isEmpty());
            assertTrue(s.bindings().isEmpty());
            assertTrue(s.pinger().isEmpty());
            assertTrue(s.capabilities().isEmpty());
            assertTrue(s.diagnostic().contains("Npcap"));
        }
    }

    /** Every operation must fail with the diagnostic, not hang and not return an empty success. */
    @Test
    public void unavailableModeFailsEveryOperationWithTheReason() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.UNAVAILABLE, "Npcap not installed")) {
            assertFailsWith(s.ping(IP, 1, Duration.ofMillis(100)), "Npcap not installed");
            assertFailsWith(s.resolve(IP, Duration.ofMillis(100)), "Npcap not installed");
            assertFailsWith(s.sweep(CidrRange.parse("10.0.0.0/30"), SweepOptions.defaults(), h -> {
            }), "Npcap not installed");
            assertFailsWith(s.sweepVia("eth0", CidrRange.parse("10.0.0.0/30"),
                                       SweepOptions.defaults(), h -> {
                            }), "Npcap not installed");
            assertFailsWith(s.discoverIpv6Segment("eth0", SweepOptions.defaults(), h -> {
            }), "Npcap not installed");
        }
    }

    /** ICMP-only is the unprivileged Linux and macOS shape: layer 2 is refused, and it says so. */
    @Test
    public void icmpOnlyRefusesLayer2ButNotBecauseTheHostIsDown() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.ICMP_ONLY, "needs root for BPF")) {
            assertTrue(s.mode().canPing());
            assertFalse(s.mode().canLayer2());
            assertFailsWith(s.resolve(IP, Duration.ofMillis(100)), "Cannot resolve");
            assertFailsWith(s.sweep(CidrRange.parse("10.0.0.0/30"), SweepOptions.defaults(), h -> {
            }), "Cannot sweep");
        }
    }

    @Test
    public void aBadCidrIsReportedAsSuchAndNotAsABackendFailure() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.UNAVAILABLE, "-")) {
            assertFailsWith(s.sweep("not-a-range", SweepOptions.defaults(), h -> {
            }), "Not a CIDR range");
        }
    }

    @Test
    public void anUnknownHostFailsTheLookupRatherThanTheBackend() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.ICMP_ONLY, "-")) {
            Throwable cause = causeOf(s.lookup("no-such-host.invalid"));
            assertTrue(cause instanceof DiscoveryException
                       || cause instanceof CompletionException, "got " + cause);
            assertTrue(cause.getMessage().contains("no-such-host.invalid"));
        }
    }

    @Test
    public void closeIsIdempotentAndSubsequentOperationsStillFailCleanly() {
        HostScanner s = HostScanner.offline(HostScanner.Mode.ICMP_ONLY, "-");
        s.close();
        s.close();
        assertTrue(s.isClosed());
        assertEquals("closed", s.diagnostic());
        assertFailsWith(s.ping(IP, 1, Duration.ofMillis(100)), "closed");
        s.reopen();   // no effect once closed
        assertTrue(s.isClosed());
    }

    /** An observer on a session with no interfaces registers and unsubscribes without complaint. */
    @Test
    public void observeIsSafeWithNoInterfaces() {
        try (HostScanner s = HostScanner.offline(HostScanner.Mode.ICMP_ONLY, "-")) {
            s.observe(n -> {
            }).close();
        }
    }

    // ------------------------------------------------------------- formatting

    @Test
    public void pingRendersProbesLossAndStats() {
        PingResult r = PingResult.of(IP,
                                     List.of(PingProbe.replied(1, Duration.ofMillis(2)),
                                             PingProbe.failed(2, io.xlogistx.nosneak.net.common.PingError.TIMEOUT)),
                                     null);
        String text = HostScanFormat.ping(r);
        assertTrue(text.contains("PING 10.0.0.1"), text);
        assertTrue(text.contains("seq=1"), text);
        assertTrue(text.contains("no reply (TIMEOUT)"), text);
        assertTrue(text.contains("2 sent, 1 received, 50.0% loss"), text);
        assertTrue(text.contains("rtt min/avg/max/stddev"), text);
        assertFalse(text.endsWith("\n"), "blocks carry no trailing newline");
    }

    @Test
    public void oneLineRenderersCoverTheTableCases() {
        PingResult r = PingResult.of(IP, List.of(PingProbe.replied(1, Duration.ofMillis(2))), null);
        assertTrue(HostScanFormat.pingLine(r).contains("1/1 received"));

        ResolveResult rr = new ResolveResult(IP, Optional.of(MacAddress.parse("aa:bb:cc:dd:ee:ff")),
                                             ResolveOutcome.RESOLVED, ResolveSource.ACTIVE_ARP,
                                             Duration.ofMillis(11));
        String resolved = HostScanFormat.resolve(rr);
        assertTrue(resolved.contains("aa:bb:cc:dd:ee:ff"), resolved);
        assertTrue(resolved.contains("RESOLVED"), resolved);
        assertTrue(resolved.contains("ACTIVE_ARP"), resolved);

        HostRecord h = new HostRecord(IP, Optional.empty(), true,
                                      Optional.of(Duration.ofMillis(1)), 64, Optional.of(0),
                                      ResolveSource.CACHE_HIT, Instant.EPOCH);
        String host = HostScanFormat.host(h);
        assertTrue(host.contains("10.0.0.1"), host);
        assertTrue(host.contains("icmp"), host);
        assertTrue(host.contains("-"), "an unresolved MAC renders as a dash: " + host);

        assertEquals("4 probed, 2 alive (1 by MAC, 2 by ICMP) in 30 ms",
                     HostScanFormat.sweep(new SweepSummary(4, 2, 1, 2, Duration.ofMillis(30))));
    }
}
