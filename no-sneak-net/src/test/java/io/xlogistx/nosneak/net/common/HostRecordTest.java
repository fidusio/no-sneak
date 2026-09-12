package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.codecs.TtlDistance;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link HostRecord#fromProbes}, the one record constructor every sweep uses. The
 * local-interface case is the §13.18 shape: {@code reachable()} is true for our own
 * address, and building the record from it fabricated {@code icmp 0.000 ms}.
 */
public class HostRecordTest {

    private static final InetAddress TARGET = InetAddress.ofLiteral("10.0.0.61");
    private static final MacAddress MAC = MacAddress.parse("b0:7b:25:82:64:45");
    private static final Instant NOW = Instant.parse("2026-09-11T12:00:00Z");

    private static ResolveResult resolved(ResolveSource source) {
        return ResolveResult.resolved(TARGET, MAC, source, Duration.ofMillis(1));
    }

    private static ResolveResult unresolved(ResolveOutcome outcome) {
        return ResolveResult.notResolved(TARGET, outcome, Duration.ofSeconds(1));
    }

    private static PingResult pinged(PingProbe... probes) {
        return PingResult.of(TARGET, List.of(probes), null);
    }

    private static PingProbe repliedWithTtl(int seq, Duration rtt, int ttl) {
        return new PingProbe(seq, true, rtt, ttl, null, false, false, Optional.empty());
    }

    @Test
    public void localInterfaceProbeIsAliveButNotIcmpAnsweredAndHasNoRtt() {
        PingResult local = pinged(PingProbe.localInterface(1));
        assertTrue(local.reachable(), "this is why the old code fabricated 0.000 ms");

        HostRecord r = HostRecord.fromProbes(TARGET, resolved(ResolveSource.LOCAL_INTERFACE), local, NOW)
                                 .orElseThrow();
        assertTrue(r.alive());
        assertFalse(r.icmpAlive(), "no packet was answered");
        assertTrue(r.rtt().isEmpty(), "no clock ran, so no RTT");
        assertEquals(PingProbe.TTL_UNAVAILABLE, r.ttlOrHopLimit());
        assertTrue(r.hopCount().isEmpty());
        assertEquals(ResolveSource.LOCAL_INTERFACE, r.macSource());
    }

    @Test
    public void ordinaryHostAnsweringBothHasMacIcmpAndRtt() {
        HostRecord r = HostRecord.fromProbes(TARGET, resolved(ResolveSource.ACTIVE_ARP),
                                             pinged(PingProbe.replied(1, Duration.ofMillis(12))), NOW)
                                 .orElseThrow();
        assertEquals(Optional.of(MAC), r.mac());
        assertTrue(r.icmpAlive());
        assertEquals(Optional.of(Duration.ofMillis(12)), r.rtt());
        assertEquals(ResolveSource.ACTIVE_ARP, r.macSource());
        assertEquals(NOW, r.observedAt());
    }

    @Test
    public void silentHostProducesNoRecord() {
        assertTrue(HostRecord.fromProbes(TARGET, unresolved(ResolveOutcome.TIMEOUT),
                                         pinged(PingProbe.failed(1, PingError.TIMEOUT)), NOW)
                             .isEmpty());
    }

    @Test
    public void macOnlyHostIsAliveWithoutIcmp() {
        HostRecord r = HostRecord.fromProbes(TARGET, resolved(ResolveSource.PASSIVE), pinged(), NOW)
                                 .orElseThrow();
        assertTrue(r.alive());
        assertFalse(r.icmpAlive());
        assertTrue(r.rtt().isEmpty());
        assertEquals(ResolveSource.PASSIVE, r.macSource());
    }

    @Test
    public void icmpOnlyHostHasNoMacAndNoSource() {
        HostRecord r = HostRecord.fromProbes(TARGET, unresolved(ResolveOutcome.UNSUPPORTED),
                                             pinged(PingProbe.replied(1, Duration.ofMillis(3))), NOW)
                                 .orElseThrow();
        assertTrue(r.mac().isEmpty());
        assertNull(r.macSource());
        assertTrue(r.icmpAlive());
    }

    @Test
    public void ttlBecomesHopCountOnlyWhenPresent() {
        HostRecord withTtl = HostRecord.fromProbes(TARGET, unresolved(ResolveOutcome.UNSUPPORTED),
                                                   pinged(repliedWithTtl(1, Duration.ofMillis(5), 64)), NOW)
                                       .orElseThrow();
        assertEquals(64, withTtl.ttlOrHopLimit());
        assertEquals(TtlDistance.hopCount(64), withTtl.hopCount());

        HostRecord without = HostRecord.fromProbes(TARGET, unresolved(ResolveOutcome.UNSUPPORTED),
                                                   pinged(PingProbe.replied(1, Duration.ofMillis(5))), NOW)
                                       .orElseThrow();
        assertEquals(PingProbe.TTL_UNAVAILABLE, without.ttlOrHopLimit());
        assertTrue(without.hopCount().isEmpty());
    }

    @Test
    public void rttIsTheAverageOfMeasuredProbes() {
        HostRecord r = HostRecord.fromProbes(TARGET, unresolved(ResolveOutcome.UNSUPPORTED),
                                             pinged(PingProbe.replied(1, Duration.ofMillis(10)),
                                                    PingProbe.replied(2, Duration.ofMillis(30))), NOW)
                                 .orElseThrow();
        assertEquals(Optional.of(Duration.ofMillis(20)), r.rtt());
    }
}
