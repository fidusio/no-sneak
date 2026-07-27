package io.xlogistx.nosneak.net.util;

import java.util.concurrent.TimeUnit;

/**
 * A leaky bucket that paces packet emission during a sweep.
 * <p>
 * {@link io.xlogistx.nosneak.net.common.SweepOptions#maxPacketsPerSecond()} is not
 * optional polish: sweeping a /16 unpaced from an appliance churns switch CAM
 * tables and trips customer intrusion detection. A bounded in-flight window
 * (`maxInFlight`) limits how many probes are OUTSTANDING, which is a different
 * thing entirely — 256 outstanding probes that each complete in a millisecond
 * still emit a quarter of a million packets a second.
 * <p>
 * Deliberately not a token bucket with burst capacity: the point is to be gentle
 * on someone else's network, and a burst allowance is exactly what would trip the
 * IDS this exists to avoid.
 * <p>
 * Thread-safe. Callers block in {@link #acquire}, so a sweep's own worker threads
 * provide the back-pressure without a scheduler.
 */
public final class RateLimiter {

    private static final double NANOS_PER_SECOND = 1_000_000_000.0;

    private final double permitsPerSecond;
    private long nextFreeNanos = System.nanoTime();

    private RateLimiter(double permitsPerSecond) {
        this.permitsPerSecond = permitsPerSecond;
    }

    /**
     * @param permitsPerSecond packets per second; {@code 0} or negative means
     *                         unlimited, matching {@code SweepOptions}
     * @return null when unlimited, so callers can skip the machinery entirely
     */
    public static RateLimiter perSecond(int permitsPerSecond) {
        return permitsPerSecond <= 0 ? null : new RateLimiter(permitsPerSecond);
    }

    /**
     * Blocks until {@code permits} packets may be sent.
     * <p>
     * The wake time is computed under the lock but slept OUTSIDE it, so callers
     * queue in arrival order without one sleeping thread holding the monitor.
     *
     * @param limiter may be null, meaning unlimited — the common case
     */
    public static void acquire(RateLimiter limiter, int permits) throws InterruptedException {
        if (limiter != null) {
            limiter.acquire(permits);
        }
    }

    public void acquire(int permits) throws InterruptedException {
        if (permits <= 0) {
            return;
        }
        long waitNanos;
        synchronized (this) {
            long now = System.nanoTime();
            long start = Math.max(now, nextFreeNanos);
            waitNanos = start - now;
            nextFreeNanos = start + (long) (permits * NANOS_PER_SECOND / permitsPerSecond);
        }
        if (waitNanos > 0) {
            TimeUnit.NANOSECONDS.sleep(waitNanos);
        }
    }

    public double permitsPerSecond() {
        return permitsPerSecond;
    }
}
