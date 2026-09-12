package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.runtime.ParallelJoin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the exactly-once guard on {@code NMapScanner.Unit}: the bug its javadoc records is a
 * double completion that released the limiter twice (driving in-flight negative and silently
 * disabling {@code --max-inflight}) and fired the stage barrier while units were outstanding.
 */
public class UnitTest {

    private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);

    @AfterEach
    public void shutdown() {
        scheduler.shutdownNow();
    }

    @Test
    public void completesExactlyOnceAndReleasesTheLimiterOnce() {
        ScanGate limiter = new ScanGate(scheduler, 1, 0);
        AtomicInteger fired = new AtomicInteger();
        ParallelJoin join = new ParallelJoin(1, fired::incrementAndGet);
        NMapScanner.Unit unit = new NMapScanner.Unit(limiter, join);

        limiter.submit(() -> { });
        assertEquals(1, limiter.inFlight());

        assertTrue(unit.complete());
        assertTrue(unit.isComplete());
        assertEquals(0, limiter.inFlight());
        assertEquals(1, fired.get());

        assertFalse(unit.complete(), "second completion must be a no-op");
        assertEquals(0, limiter.inFlight(), "in-flight must not go negative");
        assertEquals(1, fired.get(), "the barrier must not fire twice");
    }

    @Test
    public void aBarrierWaitsForEveryUnit() {
        ScanGate limiter = new ScanGate(scheduler, 0, 0);
        AtomicInteger fired = new AtomicInteger();
        ParallelJoin join = new ParallelJoin(2, fired::incrementAndGet);
        NMapScanner.Unit a = new NMapScanner.Unit(limiter, join);
        NMapScanner.Unit b = new NMapScanner.Unit(limiter, join);

        a.complete();
        a.complete();
        assertEquals(0, fired.get(), "one unit reported twice must not stand in for two");
        b.complete();
        assertEquals(1, fired.get());
    }
}
