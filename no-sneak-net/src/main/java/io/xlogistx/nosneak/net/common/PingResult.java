package io.xlogistx.nosneak.net.common;

import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Aggregate result of one {@link ICMPPing#ping} call: one entry in
 * {@link #probes()} per echo request sent, whether it replied or timed out.
 * <p>
 * NOTE: {@link PingProbe} carries an array, so neither type is value-comparable.
 * Do not use them as map keys or in set membership tests.
 *
 * @param minRtt    {@link Duration#ZERO} when {@code received == 0}
 * @param stdDevRtt population standard deviation over the probes that replied
 */
public record PingResult(
        InetAddress target,
        int sent,
        int received,
        List<PingProbe> probes,
        Duration minRtt,
        Duration avgRtt,
        Duration maxRtt,
        Duration stdDevRtt,
        Optional<PingError> error) {

    public PingResult {
        probes = List.copyOf(probes);
        if (error == null) {
            error = Optional.empty();
        }
    }

    /** True when at least one probe came back. */
    public boolean reachable() {
        return received > 0;
    }

    public double lossPercent() {
        return sent == 0 ? 0.0 : 100.0 * (sent - received) / sent;
    }

    /**
     * THE ONLY construction path — computes every aggregate from the probe list.
     * Constructing a {@code PingResult} directly bypasses this arithmetic and is
     * not supported.
     * <p>
     * Probes flagged {@link PingProbe#neighborResolutionPending()} are EXCLUDED
     * from min/avg/max/stdDev when {@code probes.size() > 1}, because their RTT
     * includes the ARP/NDP round trip and so is not a measurement of the target.
     * They still count toward {@code sent} and {@code received} — the packet did
     * come back, it just cannot be timed.
     * <p>
     * With a single probe there is nothing else to measure with, so the exclusion
     * does not apply; otherwise a one-shot ping of a cold neighbour would report
     * no statistics at all.
     * <p>
     * FALLBACK: if excluding the flagged probes would leave nothing measurable —
     * every reply was resolution-pending — the flagged probes are used after all.
     * An inflated RTT that is marked as such in the probe list beats reporting
     * {@link Duration#ZERO}, which a consumer cannot tell apart from the
     * genuine "nothing replied" zero.
     *
     * @param probes one entry per request sent; may be empty, must not be null
     * @param err    call-level error, or null when there was none
     */
    public static PingResult of(InetAddress target, List<PingProbe> probes, PingError err) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(probes, "probes");

        int sent = probes.size();
        int received = 0;
        for (PingProbe p : probes) {
            if (p.replied()) {
                received++;
            }
        }

        long[] samples = measurableRttNanos(probes);
        if (samples.length == 0) {
            return new PingResult(target, sent, received, probes,
                                  Duration.ZERO, Duration.ZERO, Duration.ZERO, Duration.ZERO,
                                  Optional.ofNullable(err));
        }

        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        double total = 0;
        for (long ns : samples) {
            min = Math.min(min, ns);
            max = Math.max(max, ns);
            total += ns;
        }
        double mean = total / samples.length;

        // Population standard deviation, not sample: these are all the
        // measurements taken, not a sample drawn from a larger set.
        double sumSquaredDeviations = 0;
        for (long ns : samples) {
            double d = ns - mean;
            sumSquaredDeviations += d * d;
        }
        double stdDev = Math.sqrt(sumSquaredDeviations / samples.length);

        return new PingResult(target, sent, received, probes,
                              Duration.ofNanos(min),
                              Duration.ofNanos(Math.round(mean)),
                              Duration.ofNanos(max),
                              Duration.ofNanos(Math.round(stdDev)),
                              Optional.ofNullable(err));
    }

    /**
     * The RTTs that actually measure the target: replied, timed, and — when there
     * is more than one probe — not taken while neighbour resolution was in flight.
     */
    private static long[] measurableRttNanos(List<PingProbe> probes) {
        boolean excludePending = probes.size() > 1;

        List<Long> samples = new ArrayList<>(probes.size());
        for (PingProbe p : probes) {
            if (!p.replied() || p.rtt() == null) {
                continue;
            }
            if (excludePending && p.neighborResolutionPending()) {
                continue;
            }
            samples.add(p.rtt().toNanos());
        }

        if (samples.isEmpty() && excludePending) {
            for (PingProbe p : probes) {
                if (p.replied() && p.rtt() != null) {
                    samples.add(p.rtt().toNanos());
                }
            }
        }

        long[] out = new long[samples.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = samples.get(i);
        }
        return out;
    }
}
