package io.xlogistx.nosneak.net.util;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Sweep pacing — the constraint that keeps a /16 scan from tripping an IDS. */
public class RateLimiterTest {

    /** Zero means unlimited, matching SweepOptions, and costs nothing at the call site. */
    @Test
    public void zeroOrNegativeIsUnlimited() {
        assertNull(RateLimiter.perSecond(0));
        assertNull(RateLimiter.perSecond(-1));
        assertNotNull(RateLimiter.perSecond(1));
    }

    /** A null limiter is the unlimited case and must not throw. */
    @Test
    public void staticAcquireToleratesNull() throws Exception {
        RateLimiter.acquire(null, 100);
    }

    /**
     * The defining property: N permits at R per second take at least (N-1)/R
     * seconds. The first acquire is free — the bucket starts full — so the bound
     * is N-1 intervals, not N.
     */
    @Test
    public void enforcesTheRate() throws Exception {
        RateLimiter limiter = RateLimiter.perSecond(100);   // 10 ms apart
        long start = System.nanoTime();
        for (int i = 0; i < 11; i++) {
            limiter.acquire(1);
        }
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMs >= 90,
                "11 permits at 100/s must take at least ~100 ms, took " + elapsedMs + " ms");
        assertTrue(elapsedMs < 1000, "but should not be wildly slower, took " + elapsedMs + " ms");
    }

    /** Multi-permit acquires cost proportionally — a host is several packets. */
    @Test
    public void multiplePermitsCostProportionally() throws Exception {
        RateLimiter limiter = RateLimiter.perSecond(100);
        long start = System.nanoTime();
        limiter.acquire(1);
        limiter.acquire(5);      // 50 ms of budget
        limiter.acquire(1);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMs >= 45, "expected ~60 ms of pacing, took " + elapsedMs + " ms");
    }

    @Test
    public void zeroPermitsIsFree() throws Exception {
        RateLimiter limiter = RateLimiter.perSecond(1);
        long start = System.nanoTime();
        limiter.acquire(0);
        limiter.acquire(0);
        assertTrue((System.nanoTime() - start) / 1_000_000 < 50, "zero permits must not block");
    }

    /**
     * The rate is global, not per-thread. Eight threads sharing one limiter must
     * still emit at the configured rate in aggregate — otherwise a wide sweep
     * multiplies the cap by its own concurrency, which is exactly the failure the
     * limiter exists to prevent.
     */
    @Test
    public void rateIsSharedAcrossThreads() throws Exception {
        RateLimiter limiter = RateLimiter.perSecond(200);   // 5 ms apart
        int threads = 8;
        int perThread = 5;                                   // 40 permits total
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(1);

        long start = System.nanoTime();
        try {
            for (int t = 0; t < threads; t++) {
                pool.submit(() -> {
                    ready.await();
                    for (int i = 0; i < perThread; i++) {
                        limiter.acquire(1);
                    }
                    return null;
                });
            }
            ready.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        // 40 permits at 200/s is ~195 ms of pacing; allow generous slack for
        // scheduling but require that concurrency did NOT bypass the limiter.
        assertTrue(elapsedMs >= 150,
                "8 threads must share the rate, not multiply it; took " + elapsedMs + " ms");
    }
}
