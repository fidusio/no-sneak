package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Aggregation arithmetic for {@link PingResult#of}, driven entirely by synthetic
 * probe lists — no network involved.
 */
public class PingResultTest {

    private static final InetAddress TARGET = InetAddress.ofLiteral("192.168.1.50");

    private static PingProbe ok(int seq, long millis) {
        return PingProbe.replied(seq, Duration.ofMillis(millis));
    }

    private static PingProbe lost(int seq) {
        return PingProbe.failed(seq, PingError.TIMEOUT);
    }

    /** A probe that replied but was sent while ARP/NDP was still resolving. */
    private static PingProbe pending(int seq, long millis) {
        return new PingProbe(seq, true, Duration.ofMillis(millis),
                             PingProbe.TTL_UNAVAILABLE, new byte[0], true, Optional.empty());
    }

    // ---- counting ----

    @Test
    public void allReplied() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 10), ok(2, 20), ok(3, 30)), null);

        assertEquals(3, r.sent());
        assertEquals(3, r.received());
        assertTrue(r.reachable());
        assertEquals(0.0, r.lossPercent());
        assertEquals(Duration.ofMillis(10), r.minRtt());
        assertEquals(Duration.ofMillis(20), r.avgRtt());
        assertEquals(Duration.ofMillis(30), r.maxRtt());
        assertTrue(r.error().isEmpty());
    }

    /** An unreachable host is a result with received == 0, never an exception. */
    @Test
    public void allLostYieldsZeroStatisticsAndNoThrow() {
        PingResult r = PingResult.of(TARGET, List.of(lost(1), lost(2), lost(3)),
                                     PingError.TIMEOUT);

        assertEquals(3, r.sent());
        assertEquals(0, r.received());
        assertFalse(r.reachable());
        assertEquals(100.0, r.lossPercent());
        assertEquals(Duration.ZERO, r.minRtt());
        assertEquals(Duration.ZERO, r.avgRtt());
        assertEquals(Duration.ZERO, r.maxRtt());
        assertEquals(Duration.ZERO, r.stdDevRtt());
        assertEquals(Optional.of(PingError.TIMEOUT), r.error());
    }

    @Test
    public void mixedRepliesIgnoreLostProbesInStatistics() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 10), lost(2), ok(3, 30), lost(4)), null);

        assertEquals(4, r.sent());
        assertEquals(2, r.received());
        assertEquals(50.0, r.lossPercent());
        assertEquals(Duration.ofMillis(10), r.minRtt());
        assertEquals(Duration.ofMillis(20), r.avgRtt());
        assertEquals(Duration.ofMillis(30), r.maxRtt());
    }

    @Test
    public void singleProbe() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 15)), null);

        assertEquals(1, r.sent());
        assertEquals(1, r.received());
        assertEquals(Duration.ofMillis(15), r.minRtt());
        assertEquals(Duration.ofMillis(15), r.avgRtt());
        assertEquals(Duration.ofMillis(15), r.maxRtt());
        assertEquals(Duration.ZERO, r.stdDevRtt(), "one sample has no spread");
    }

    @Test
    public void emptyProbeListIsLegal() {
        PingResult r = PingResult.of(TARGET, List.of(), null);

        assertEquals(0, r.sent());
        assertEquals(0, r.received());
        assertEquals(0.0, r.lossPercent(), "no division by zero");
        assertFalse(r.reachable());
    }

    // ---- the neighborResolutionPending exclusion ----

    /**
     * The core §4.6 rule: a probe sent while ARP was still resolving counts as
     * sent and received, but its RTT includes the resolution round trip and so
     * must not pollute the statistics.
     */
    @Test
    public void pendingProbeCountsButIsExcludedFromStatistics() {
        PingResult r = PingResult.of(TARGET,
                List.of(pending(1, 500), ok(2, 10), ok(3, 20), ok(4, 30)), null);

        assertEquals(4, r.sent(), "the pending probe still counts as sent");
        assertEquals(4, r.received(), "and as received");
        assertEquals(0.0, r.lossPercent());

        assertEquals(Duration.ofMillis(10), r.minRtt());
        assertEquals(Duration.ofMillis(20), r.avgRtt(), "500ms outlier must not move the mean");
        assertEquals(Duration.ofMillis(30), r.maxRtt(), "and must not become the maximum");
    }

    /** With one probe there is nothing else to measure with, so the exclusion is off. */
    @Test
    public void singlePendingProbeIsStillMeasured() {
        PingResult r = PingResult.of(TARGET, List.of(pending(1, 500)), null);

        assertEquals(1, r.received());
        assertEquals(Duration.ofMillis(500), r.avgRtt(),
                     "excluding the only sample would report a false zero");
        assertEquals(Duration.ofMillis(500), r.minRtt());
        assertEquals(Duration.ofMillis(500), r.maxRtt());
    }

    /**
     * When every reply was resolution-pending, an inflated-but-real measurement
     * beats a zero that is indistinguishable from "nothing replied".
     */
    @Test
    public void allPendingFallsBackRatherThanReportingZero() {
        PingResult r = PingResult.of(TARGET,
                List.of(pending(1, 400), pending(2, 600), lost(3)), null);

        assertEquals(2, r.received());
        assertTrue(r.reachable());
        assertEquals(Duration.ofMillis(400), r.minRtt());
        assertEquals(Duration.ofMillis(500), r.avgRtt());
        assertEquals(Duration.ofMillis(600), r.maxRtt());
    }

    @Test
    public void multiplePendingProbesAreAllExcludedWhenOthersExist() {
        PingResult r = PingResult.of(TARGET,
                List.of(pending(1, 900), pending(2, 800), ok(3, 40)), null);

        assertEquals(3, r.received());
        assertEquals(Duration.ofMillis(40), r.minRtt());
        assertEquals(Duration.ofMillis(40), r.avgRtt());
        assertEquals(Duration.ofMillis(40), r.maxRtt());
        assertEquals(Duration.ZERO, r.stdDevRtt());
    }

    /** A pending probe that never replied contributes nothing either way. */
    @Test
    public void pendingAndLostIsJustLost() {
        PingProbe pendingLost = new PingProbe(1, false, null, PingProbe.TTL_UNAVAILABLE,
                                              new byte[0], true, Optional.of(PingError.TIMEOUT));
        PingResult r = PingResult.of(TARGET, List.of(pendingLost, ok(2, 10)), null);

        assertEquals(2, r.sent());
        assertEquals(1, r.received());
        assertEquals(Duration.ofMillis(10), r.avgRtt());
    }

    // ---- standard deviation ----

    /**
     * Population standard deviation, not sample: for 10ms and 30ms the mean is
     * 20ms and each deviates by exactly 10ms, so sigma is 10ms. The sample
     * formula (dividing by n-1) would give about 14.1ms.
     */
    @Test
    public void populationStandardDeviationExactVector() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 10), ok(2, 30)), null);

        assertEquals(Duration.ofMillis(20), r.avgRtt());
        assertEquals(Duration.ofMillis(10), r.stdDevRtt());
    }

    /** Four evenly spread samples: mean 25ms, sigma sqrt(125) ~ 11.180ms. */
    @Test
    public void standardDeviationOfSpreadSamples() {
        PingResult r = PingResult.of(TARGET,
                List.of(ok(1, 10), ok(2, 20), ok(3, 30), ok(4, 40)), null);

        assertEquals(Duration.ofMillis(25), r.avgRtt());
        long expected = Math.round(Math.sqrt(125.0) * 1_000_000);
        assertEquals(expected, r.stdDevRtt().toNanos());
    }

    @Test
    public void identicalSamplesHaveZeroDeviation() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 25), ok(2, 25), ok(3, 25)), null);

        assertEquals(Duration.ofMillis(25), r.avgRtt());
        assertEquals(Duration.ZERO, r.stdDevRtt());
    }

    /** Sub-millisecond RTTs must survive: the arithmetic runs in nanoseconds. */
    @Test
    public void subMillisecondPrecisionIsPreserved() {
        PingResult r = PingResult.of(TARGET,
                List.of(PingProbe.replied(1, Duration.ofNanos(120_000)),
                        PingProbe.replied(2, Duration.ofNanos(180_000))), null);

        assertEquals(Duration.ofNanos(120_000), r.minRtt());
        assertEquals(Duration.ofNanos(150_000), r.avgRtt());
        assertEquals(Duration.ofNanos(180_000), r.maxRtt());
        assertEquals(Duration.ofNanos(30_000), r.stdDevRtt());
    }

    // ---- contract ----

    @Test
    public void probeListIsDefensivelyCopied() {
        List<PingProbe> mutable = new java.util.ArrayList<>(List.of(ok(1, 10)));
        PingResult r = PingResult.of(TARGET, mutable, null);
        mutable.add(ok(2, 20));

        assertEquals(1, r.probes().size());
        assertThrows(UnsupportedOperationException.class, () -> r.probes().add(ok(3, 30)));
    }

    @Test
    public void rejectsNullArguments() {
        assertThrows(NullPointerException.class,
                     () -> PingResult.of(null, List.of(ok(1, 1)), null));
        assertThrows(NullPointerException.class, () -> PingResult.of(TARGET, null, null));
    }

    /** A per-call error is carried through even when some probes replied. */
    @Test
    public void callLevelErrorIsPreserved() {
        PingResult r = PingResult.of(TARGET, List.of(ok(1, 10), lost(2)),
                                     PingError.HOST_UNREACHABLE);
        assertEquals(Optional.of(PingError.HOST_UNREACHABLE), r.error());
        assertTrue(r.reachable(), "a call-level error does not erase a reply that arrived");
    }

    @Test
    public void lossPercentIsExactForUnevenCounts() {
        PingResult r = PingResult.of(TARGET,
                List.of(ok(1, 10), lost(2), lost(3)), null);
        assertEquals(200.0 / 3.0, r.lossPercent(), 1e-9);
    }
}
