package io.xlogistx.nosneak.net.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.RateController;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the property §13.22 exists for: a sweep never parks a pool thread, so it cannot wedge
 * the shared pool its own timeouts run on. Every test here uses a deliberately tiny executor —
 * the old fan-out deadlocked with one thread, the driver must not.
 */
public class SweepDriverTest {

    private final List<ExecutorService> pools = new ArrayList<>();

    @AfterEach
    public void shutdown() {
        pools.forEach(ExecutorService::shutdownNow);
    }

    private ScheduledThreadPoolExecutor pool(int threads) {
        ScheduledThreadPoolExecutor p = new ScheduledThreadPoolExecutor(threads);
        pools.add(p);
        return p;
    }

    private static List<InetAddress> targets(int n) {
        List<InetAddress> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            out.add(InetAddress.ofLiteral("10." + ((i >> 16) & 0xFF) + "." + ((i >> 8) & 0xFF)
                                          + "." + (i & 0xFF)));
        }
        return out;
    }

    /** A probe that is answered only by a timer, like a silent host timing out. */
    private static Function<InetAddress, CompletableFuture<Void>> silentHost(
            ScheduledExecutorService scheduler, long millis, AtomicInteger visited) {
        return t -> {
            visited.incrementAndGet();
            CompletableFuture<Void> f = new CompletableFuture<>();
            scheduler.schedule(() -> f.complete(null), millis, TimeUnit.MILLISECONDS);
            return f;
        };
    }

    /**
     * The regression test. One thread serves as both scheduler and dispatcher, exactly the
     * shape zoxweb's default pools have (timers are delivered onto the task pool). 300 silent
     * hosts through a window of 8: the old code parked that one thread on the semaphore and the
     * timeouts that would have released it never ran.
     */
    @Test
    public void doesNotWedgeABoundedPool() throws Exception {
        ScheduledThreadPoolExecutor one = pool(1);
        AtomicInteger visited = new AtomicInteger();

        SweepDriver.run(targets(300).iterator(), 8, null, one, one, silentHost(one, 5, visited))
                   .get(10, TimeUnit.SECONDS);

        assertEquals(300, visited.get());
    }

    @Test
    public void neverExceedsMaxInFlight() throws Exception {
        ScheduledThreadPoolExecutor p = pool(4);
        AtomicInteger current = new AtomicInteger();
        AtomicInteger highWater = new AtomicInteger();
        AtomicInteger visited = new AtomicInteger();
        Function<InetAddress, CompletableFuture<Void>> probe = t -> {
            visited.incrementAndGet();
            int now = current.incrementAndGet();
            highWater.accumulateAndGet(now, Math::max);
            CompletableFuture<Void> f = new CompletableFuture<>();
            p.schedule(() -> {
                current.decrementAndGet();
                f.complete(null);
            }, 2, TimeUnit.MILLISECONDS);
            return f;
        };

        SweepDriver.run(targets(200).iterator(), 5, null, p, p, probe).get(10, TimeUnit.SECONDS);

        assertEquals(200, visited.get());
        assertTrue(highWater.get() <= 5, "in-flight peaked at " + highWater.get());
        assertTrue(highWater.get() >= 2, "window never used: peaked at " + highWater.get());
    }

    /**
     * 20 hosts at 100 hosts/s is 19 intervals of 10 ms, so the sweep cannot finish in under
     * ~190 ms. Unpaced, the same shape finishes in a few milliseconds.
     */
    @Test
    public void honoursTheAggregateRate() throws Exception {
        ScheduledThreadPoolExecutor p = pool(2);
        Function<InetAddress, CompletableFuture<Void>> instant =
                t -> CompletableFuture.completedFuture(null);

        long start = System.nanoTime();
        SweepDriver.run(targets(20).iterator(), 256, SweepDriver.pacer(100, 1), p, p, instant)
                   .get(10, TimeUnit.SECONDS);
        long pacedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        start = System.nanoTime();
        SweepDriver.run(targets(200).iterator(), 256, null, p, p, instant).get(10, TimeUnit.SECONDS);
        long unpacedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertTrue(pacedMs >= 150, "paced sweep took only " + pacedMs + " ms");
        assertTrue(unpacedMs < 500, "unpaced sweep took " + unpacedMs + " ms");
    }

    /** The per-host rate is the packet cap divided by the worst-case frames one host costs. */
    @Test
    public void pacerIsInHostsPerSecondAndRoundsUnderTheCap() {
        assertNull(SweepDriver.pacer(0, 3));
        assertNull(SweepDriver.pacer(-1, 3));

        RateController windows = SweepDriver.pacer(2000, 2);
        assertEquals(1000f, windows.getTPS(), 0.001f);
        assertEquals(1, windows.getDeltaInMillis());

        RateController linux = SweepDriver.pacer(2000, 3);
        assertEquals(2, linux.getDeltaInMillis(), "667 hosts/s must round UP to 2 ms, not down to 1");

        assertEquals(1, SweepDriver.pacer(1000, 0).getDeltaInMillis(), "zero packets per host is paced as one");
        assertEquals(RateController.RCType.TIME, linux.getRCType());
    }

    @Test
    public void emptyTargetsCompleteImmediately() throws Exception {
        ScheduledThreadPoolExecutor p = pool(1);
        AtomicInteger visited = new AtomicInteger();

        SweepDriver.run(targets(0).iterator(), 8, null, p, p, silentHost(p, 5, visited))
                   .get(2, TimeUnit.SECONDS);

        assertEquals(0, visited.get());
    }

    @Test
    public void aFailingProbeDoesNotStallTheSweep() throws Exception {
        ScheduledThreadPoolExecutor p = pool(2);
        AtomicInteger visited = new AtomicInteger();
        Function<InetAddress, CompletableFuture<Void>> flaky = t -> {
            int n = visited.incrementAndGet();
            if (n % 3 == 0) {
                throw new IllegalStateException("synchronous failure " + n);
            }
            if (n % 5 == 0) {
                return CompletableFuture.failedFuture(new IllegalStateException("async failure " + n));
            }
            if (n % 7 == 0) {
                return null;
            }
            return CompletableFuture.completedFuture(null);
        };

        Void v = SweepDriver.run(targets(100).iterator(), 4, null, p, p, flaky).get(5, TimeUnit.SECONDS);

        assertNull(v);
        assertEquals(100, visited.get());
    }

    /** Completion inside launch re-enters admit on the same thread; nothing may be skipped. */
    @Test
    public void synchronousCompletionsDoNotLoseAdmissions() throws Exception {
        ScheduledThreadPoolExecutor p = pool(1);
        AtomicInteger visited = new AtomicInteger();
        Function<InetAddress, CompletableFuture<Void>> instant = t -> {
            visited.incrementAndGet();
            return CompletableFuture.completedFuture(null);
        };

        SweepDriver.run(targets(1000).iterator(), 1, null, p, p, instant).get(10, TimeUnit.SECONDS);

        assertEquals(1000, visited.get());
    }

    @Test
    public void resultCompletesOnTheDispatcher() throws Exception {
        ScheduledThreadPoolExecutor scheduler = pool(1);
        ExecutorService dispatcher = Executors.newSingleThreadExecutor(
                r -> new Thread(r, "sweep-dispatcher"));
        pools.add(dispatcher);
        AtomicInteger visited = new AtomicInteger();

        String thread = SweepDriver
                .run(targets(3).iterator(), 8, null, scheduler, dispatcher,
                     silentHost(scheduler, 20, visited))
                .thenApply(ignored -> Thread.currentThread().getName())
                .get(5, TimeUnit.SECONDS);

        assertEquals("sweep-dispatcher", thread);
    }
}
