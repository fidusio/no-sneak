package io.xlogistx.nosneak.net.common;

import java.time.Duration;

/**
 * Tuning for {@link HostDiscovery#sweep} and
 * {@link HostDiscovery#discoverIpv6Segment}.
 * <p>
 * {@code maxPacketsPerSecond} is not optional polish: sweeping a /16 unpaced from
 * an appliance will churn switch CAM tables and trip customer IDS. Note the cap
 * is PER SWEEP — N concurrent sweeps through one shared {@link ICMPPing} emit up
 * to N times this rate.
 *
 * @param maxInFlight        bounded concurrency window
 * @param maxPacketsPerSecond hard pacing cap; {@code 0} means unlimited
 * @param pingCount          probes per host. Defaults to 1 deliberately: with ARP as the
 *                           liveness oracle, multi-probe is not needed to defend against
 *                           the cold-neighbour drop, and it multiplies sweep wall time
 * @param maxHosts           hard cap; refuses absurd IPv6 ranges before expansion
 */
public record SweepOptions(
        int maxInFlight,
        int maxPacketsPerSecond,
        Duration perHostTimeout,
        boolean doIcmp,
        boolean doMac,
        int pingCount,
        long maxHosts) {

    public SweepOptions {
        if (maxInFlight < 1) {
            throw new IllegalArgumentException("maxInFlight must be >= 1, got " + maxInFlight);
        }
        if (maxPacketsPerSecond < 0) {
            throw new IllegalArgumentException(
                    "maxPacketsPerSecond must be >= 0, got " + maxPacketsPerSecond);
        }
        if (pingCount < 1) {
            throw new IllegalArgumentException("pingCount must be >= 1, got " + pingCount);
        }
        if (maxHosts < 1) {
            throw new IllegalArgumentException("maxHosts must be >= 1, got " + maxHosts);
        }
        if (perHostTimeout == null || perHostTimeout.isNegative() || perHostTimeout.isZero()) {
            throw new IllegalArgumentException("perHostTimeout must be positive");
        }
    }

    public static SweepOptions defaults() {
        return new SweepOptions(256, 2000, Duration.ofMillis(1000), true, true, 1, 65536);
    }
}
