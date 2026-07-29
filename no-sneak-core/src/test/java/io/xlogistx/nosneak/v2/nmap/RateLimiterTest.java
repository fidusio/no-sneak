package io.xlogistx.nosneak.v2.nmap;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.task.TaskUtil;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the scan throttle's two silent failure modes: an in-flight counter that drifts
 * below zero (which turns {@code --max-inflight} off for the rest of the scan without any
 * error) and unbounded recursion when a launch completes synchronously (a localhost sweep).
 */
public class RateLimiterTest {

    @Test
    public void concurrencyCapIsHonoured() {
        RateLimiter limiter = new RateLimiter(TaskUtil.defaultTaskScheduler(), 3, 0);
        AtomicInteger live = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        Runnable[] finishers = new Runnable[10];
        for (int i = 0; i < 10; i++) {
            final int idx = i;
            limiter.submit(() -> {
                int now = live.incrementAndGet();
                peak.accumulateAndGet(now, Math::max);
                finishers[idx] = () -> {
                    live.decrementAndGet();
                    limiter.release();
                };
            });
        }
        assertEquals(3, peak.get(), "no more than maxInFlight units may be launched at once");
        for (int i = 0; i < 10; i++) {
            if (finishers[i] != null) {
                finishers[i].run();
            }
        }
        assertEquals(0, live.get());
        limiter.close();
    }

    /**
     * A stray extra release must not drive the counter negative — once negative the
     * {@code inFlight >= maxInFlight} test can never trip and the cap is silently disabled.
     */
    @Test
    public void extraReleasesCannotDriveTheCounterNegative() {
        RateLimiter limiter = new RateLimiter(TaskUtil.defaultTaskScheduler(), 2, 0);
        for (int i = 0; i < 20; i++) {
            limiter.release();
        }
        assertEquals(0, limiter.inFlight(), "the in-flight counter must never go below zero");

        AtomicInteger launched = new AtomicInteger();
        for (int i = 0; i < 5; i++) {
            limiter.submit(launched::incrementAndGet);
        }
        assertEquals(2, launched.get(), "the cap must still hold after spurious releases");
        limiter.close();
    }

    /**
     * A launch that completes inside its own {@code run()} (what a loopback connect does)
     * re-enters drain(). Without a re-entrancy guard this recurses once per queued unit.
     */
    @Test
    public void synchronouslyCompletingLaunchesDoNotRecurse() {
        RateLimiter limiter = new RateLimiter(TaskUtil.defaultTaskScheduler(), 1, 0);
        final int n = 20_000;
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            limiter.submit(() -> {
                ran.incrementAndGet();
                limiter.release(); // completes synchronously, like a loopback connect
            });
        }
        assertEquals(n, ran.get(), "every queued unit must run without blowing the stack");
        assertEquals(0, limiter.inFlight());
        limiter.close();
    }

    @Test
    public void unlimitedLimiterDrainsImmediately() {
        RateLimiter limiter = new RateLimiter(TaskUtil.defaultTaskScheduler(), 0, 0);
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < 50; i++) {
            limiter.submit(ran::incrementAndGet);
        }
        assertEquals(50, ran.get());
        limiter.close();
    }

    @Test
    public void perSecondPacingReleasesQueuedWorkOverTime() throws Exception {
        RateLimiter limiter = new RateLimiter(TaskUtil.defaultTaskScheduler(), 0, 20);
        final int n = 25;
        CountDownLatch ran = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            limiter.submit(ran::countDown);
        }
        assertTrue(ran.getCount() < n, "the initial token bucket must let some work start");
        assertTrue(ran.await(15, TimeUnit.SECONDS), "the ticker must drain the remainder");
        limiter.close();
    }
}
