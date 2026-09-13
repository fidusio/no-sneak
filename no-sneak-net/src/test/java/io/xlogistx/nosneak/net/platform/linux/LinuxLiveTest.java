package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.PingError;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.ResolveSource;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;
import io.xlogistx.nosneak.net.tools.HostScanner;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The Linux backend on REAL sockets — runs only on Linux as root (or with
 * {@code CAP_NET_RAW}) and is skipped everywhere else, so the ordinary suite stays pure.
 * <p>
 * Every assertion here is about the machine it runs on, not about the segment: our own
 * addresses, the loopback echo, the refusal of an unscoped link-local, the default gateway
 * if there is one, and the {@code discoverIpv6Segment} window (§13.24). Nothing depends on
 * which neighbours happen to exist. Run it with {@code sudo mvn test -Dtest=LinuxLiveTest
 * -DskipTests=false -Dmaven.repo.local=$HOME/.m2/repository}.
 */
class LinuxLiveTest {

    private static ScheduledExecutorService scheduler;
    private static ExecutorService dispatcher;
    private static HostScanner scanner;
    private static NicBinding nic;

    @BeforeAll
    static void openAsRoot() {
        assumeTrue(System.getProperty("os.name").toLowerCase().contains("linux"), "Linux only");
        scheduler = Executors.newScheduledThreadPool(2, r -> new Thread(r, "live-sched"));
        dispatcher = Executors.newFixedThreadPool(4, r -> new Thread(r, "live-dispatch"));
        scanner = HostScanner.open(scheduler, dispatcher);
        if (scanner.mode() != HostScanner.Mode.FULL) {
            String why = scanner.diagnostic();
            // Not root: skip, do not fail. Anything else on a Linux box is a real defect.
            assumeTrue(!why.contains("EPERM") && !why.contains("EACCES"),
                       "needs root or CAP_NET_RAW: " + why);
            throw new AssertionError("layer 2 did not open on Linux as root: " + why);
        }
        nic = scanner.bindings().stream()
                .filter(b -> !b.ipv4().isEmpty())
                .findFirst()
                .orElse(null);
        assumeTrue(nic != null, "no interface with an IPv4 address");
    }

    @AfterAll
    static void close() {
        if (scanner != null) {
            scanner.close();
        }
        if (dispatcher != null) {
            dispatcher.shutdownNow();
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    @Test
    void rootOpensEverythingTheBackendClaims() {
        // The session's capabilities are the PINGER's (no layer 2 there, by design); the
        // interface's own carry ARP/NDP/passive plus the attached pinger's ICMP answers.
        DiscoveryCapabilities pinger = scanner.capabilities().orElseThrow();
        assertEquals(DiscoveryCapabilities.Backend.LINUX_NATIVE, pinger.backend());
        assertTrue(pinger.icmpV4() && pinger.icmpV6(), "both ICMP families");
        assertTrue(pinger.ttlAvailable() && pinger.offLinkIcmp());
        assertFalse(pinger.activeArp() || pinger.activeNdp(), "L2 belongs to the interface");
        DiscoveryCapabilities c = scanner.interfaceNamed(nic.javaName()).orElseThrow().capabilities();
        assertTrue(c.icmpV4() && c.icmpV6(), "pinger attached");
        assertTrue(c.activeArp() && c.activeNdp(), "ARP and NDP");
        assertTrue(c.passiveObservation() && c.rawEvidence() && c.ttlAvailable() && c.offLinkIcmp());
    }

    @Test
    void ourOwnIpv4AddressIsAnsweredFromTheInterfaceNotTheWire() throws Exception {
        InetAddress own = nic.ipv4().get(0).address();
        ResolveResult r = scanner.resolve(own, Duration.ofSeconds(1)).get(5, TimeUnit.SECONDS);
        assertTrue(r.resolved(), r.toString());
        assertEquals(ResolveSource.LOCAL_INTERFACE, r.source());
        assertEquals(nic.hardwareAddress(), r.mac().orElseThrow());
        assertTrue(r.elapsed().toMillis() < 100, "no timeout burned: " + r.elapsed());
    }

    @Test
    void ourOwnLinkLocalIpv6AddressIsAnsweredTheSameWay() throws Exception {
        Optional<InetAddress> own = nic.ipv6().stream().map(NicBinding.LocalAddress::address)
                .filter(InetAddress::isLinkLocalAddress).findFirst();
        assumeTrue(own.isPresent(), "no link-local IPv6 address on " + nic.javaName());
        ResolveResult r = scanner.resolve(own.get(), Duration.ofSeconds(1)).get(5, TimeUnit.SECONDS);
        assertEquals(ResolveSource.LOCAL_INTERFACE, r.source(), r.toString());
        assertEquals(nic.hardwareAddress(), r.mac().orElseThrow());
    }

    @Test
    void pingingOurselvesIsARealLoopbackEchoWithAMeasuredRtt() throws Exception {
        // §13.18: on Linux this goes to the wire's loopback and comes back with a real RTT;
        // the Windows localInterface short-circuit must never be ported here.
        InetAddress own = nic.ipv4().get(0).address();
        PingResult p = scanner.ping(own, 4, Duration.ofSeconds(2)).get(5, TimeUnit.SECONDS);
        assertEquals(4, p.sent());
        assertEquals(4, p.received(), p.toString());
        assertTrue(p.measured() && p.observedOnWire());
        assertTrue(p.avgRtt().toNanos() > 0, "a real RTT, not a fabricated zero");
        assertTrue(p.probes().stream().allMatch(pr -> pr.ttlOrHopLimit() == 64), "loopback TTL is 64");
    }

    @Test
    void anUnscopedLinkLocalIpv6TargetIsRefusedWithoutSending() throws Exception {
        PingResult p = scanner.ping(InetAddress.ofLiteral("fe80::1"), 2, Duration.ofSeconds(1))
                .get(5, TimeUnit.SECONDS);
        assertEquals(Optional.of(PingError.NETWORK_UNREACHABLE), p.error());
        assertEquals(0, p.received());
        assertFalse(p.observedOnWire());
        assertTrue(p.avgRtt() == null || p.avgRtt().isZero() || !p.measured(),
                   "nothing to measure");
    }

    @Test
    void theDefaultGatewayResolvesByActiveArp() throws Exception {
        Optional<Inet4Address> gw = defaultGateway();
        assumeTrue(gw.isPresent(), "no IPv4 default route");
        assumeTrue(nic.isOnLink(gw.get()), "gateway is not on " + nic.javaName());
        scanner.interfaceNamed(nic.javaName()).orElseThrow().cache().clear();
        ResolveResult r = scanner.resolve(gw.get(), Duration.ofSeconds(3)).get(10, TimeUnit.SECONDS);
        assertTrue(r.resolved(), r.toString());
        assertEquals(ResolveSource.ACTIVE_ARP, r.source(), r.toString());
        assertTrue(r.elapsed().toMillis() < 1500, "answered on the first attempt: " + r.elapsed());
    }

    @Test
    void sweepingOurOwnSlash32FindsExactlyUs() throws Exception {
        InetAddress own = nic.ipv4().get(0).address();
        List<HostRecord> seen = new CopyOnWriteArrayList<>();
        SweepSummary s = scanner.sweep(CidrRange.parse(own.getHostAddress() + "/32"),
                                       SweepOptions.defaults(), seen::add)
                .get(10, TimeUnit.SECONDS);
        assertEquals(1, s.total());
        assertEquals(1, s.alive());
        assertEquals(1, s.macsResolved());
        assertEquals(1, s.icmpAlive());
        // Records are dispatched after the summary; give the dispatcher a moment.
        for (int i = 0; i < 50 && seen.isEmpty(); i++) {
            Thread.sleep(20);
        }
        assertEquals(1, seen.size());
        assertEquals(own, seen.get(0).ip());
        assertEquals(nic.hardwareAddress(), seen.get(0).mac().orElseThrow());
        assertTrue(seen.get(0).icmpAlive());
    }

    @Test
    void segmentDiscoveryWaitsOutTheWindowAndCountsOnlyEchoResponders() throws Exception {
        // §13.24: the snapshot is taken when the window closes, never on the first reply.
        // Independent of who answers: with no v6 neighbour it still waits and reports zero.
        Duration window = Duration.ofMillis(700);
        SweepOptions opts = new SweepOptions(256, 2000, window, true, true, 1, 65536);
        List<HostRecord> seen = new CopyOnWriteArrayList<>();
        long t0 = System.nanoTime();
        SweepSummary s = scanner.discoverIpv6Segment(nic.javaName(), opts, seen::add)
                .get(10, TimeUnit.SECONDS);
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(elapsedMs >= window.toMillis(), "returned before the window closed: "
                                                    + elapsedMs + " ms");
        assertTrue(elapsedMs < window.toMillis() + 2000, "far past the window: " + elapsedMs);
        assertEquals(s.total(), s.alive());
        assertEquals(s.total(), s.macsResolved());
        assertTrue(s.icmpAlive() <= s.total());
        for (int i = 0; i < 50 && seen.size() < s.total(); i++) {
            Thread.sleep(20);
        }
        assertEquals(s.total(), seen.size());
        assertEquals(s.icmpAlive(), seen.stream().filter(HostRecord::icmpAlive).count());
        assertTrue(seen.stream().allMatch(h -> h.ip() instanceof Inet6Address && h.mac().isPresent()));
        assertTrue(seen.stream().noneMatch(h -> nic.isLocalAddress(h.ip())), "never ourselves");
    }

    /** The IPv4 default gateway from {@code /proc/net/route}, if any. */
    private static Optional<Inet4Address> defaultGateway() throws IOException {
        for (String line : Files.readAllLines(Path.of("/proc/net/route"))) {
            String[] f = line.trim().split("\\s+");
            if (f.length < 3 || !"00000000".equals(f[1])) {
                continue;
            }
            long hex = Long.parseLong(f[2], 16);       // little-endian on x86-64 and aarch64
            byte[] b = {(byte) hex, (byte) (hex >>> 8), (byte) (hex >>> 16), (byte) (hex >>> 24)};
            if (hex != 0) {
                return Optional.of((Inet4Address) InetAddress.getByAddress(b));
            }
        }
        return Optional.empty();
    }
}
