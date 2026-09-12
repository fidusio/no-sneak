package io.xlogistx.nosneak.nmap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gate's silent failure modes — an in-flight counter that drifts below zero (which turns
 * {@code --max-inflight} off for the rest of the scan without any error) and unbounded
 * recursion when a launch completes synchronously (a localhost sweep) — plus the pacing
 * contract: leaky, not bursty, and never parking the submitter.
 */
public class ScanGateTest {

    private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);

    @AfterEach
    public void shutdown() {
        scheduler.shutdownNow();
    }

    @Test
    public void concurrencyCapIsHonoured() {
        ScanGate gate = new ScanGate(scheduler, 3, 0);
        AtomicInteger live = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        Runnable[] finishers = new Runnable[10];
        for (int i = 0; i < 10; i++) {
            final int idx = i;
            gate.submit(() -> {
                int now = live.incrementAndGet();
                peak.accumulateAndGet(now, Math::max);
                finishers[idx] = () -> {
                    live.decrementAndGet();
                    gate.release();
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
        gate.close();
    }

    /**
     * A stray extra release must not drive the counter negative — once negative the
     * {@code inFlight >= maxInFlight} test can never trip and the cap is silently disabled.
     */
    @Test
    public void extraReleasesCannotDriveTheCounterNegative() {
        ScanGate gate = new ScanGate(scheduler, 2, 0);
        for (int i = 0; i < 20; i++) {
            gate.release();
        }
        assertEquals(0, gate.inFlight(), "the in-flight counter must never go below zero");

        AtomicInteger launched = new AtomicInteger();
        for (int i = 0; i < 5; i++) {
            gate.submit(launched::incrementAndGet);
        }
        assertEquals(2, launched.get(), "the cap must still hold after spurious releases");
        gate.close();
    }

    /**
     * A launch that completes inside its own {@code run()} (what a loopback connect does)
     * re-enters drain(). Without a re-entrancy guard this recurses once per queued unit.
     */
    @Test
    public void synchronouslyCompletingLaunchesDoNotRecurse() {
        ScanGate gate = new ScanGate(scheduler, 1, 0);
        final int n = 20_000;
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            gate.submit(() -> {
                ran.incrementAndGet();
                gate.release(); // completes synchronously, like a loopback connect
            });
        }
        assertEquals(n, ran.get(), "every queued unit must run without blowing the stack");
        assertEquals(0, gate.inFlight());
        gate.close();
    }

    @Test
    public void unlimitedGateDrainsImmediately() {
        ScanGate gate = new ScanGate(scheduler, 0, 0);
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < 50; i++) {
            gate.submit(ran::incrementAndGet);
        }
        assertEquals(50, ran.get());
        gate.close();
    }

    /**
     * Leaky, not bursty: at 20/s only the FIRST launch may leave at once; the rest are held and
     * re-offered by the scheduler 50 ms apart. The old token bucket let all 20 leave in the first
     * tick. And submitting never parks the caller — the loop returns at once.
     */
    @Test
    public void pacingIsLeakyAndNeverParksTheSubmitter() throws Exception {
        ScanGate gate = new ScanGate(scheduler, 0, 20);
        final int n = 25;
        CountDownLatch ran = new CountDownLatch(n);
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            gate.submit(ran::countDown);
        }
        long submitMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);

        assertTrue(submitMs < 100, "submit parked the caller for " + submitMs + " ms");
        assertEquals(n - 1, ran.getCount(), "only the first launch may leave immediately");
        assertTrue(gate.isHolding(), "the second launch is admitted and waiting for its send time");
        assertTrue(ran.await(5, TimeUnit.SECONDS), "the scheduler must drain the remainder");
        long totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
        assertTrue(totalMs >= 24 * 50 - 50, "25 launches at 20/s cannot finish in " + totalMs + " ms");
        assertFalse(gate.isHolding());
        gate.close();
    }

    /** The window and the pacer compose: a held launch still holds its slot. */
    @Test
    public void aHeldLaunchCountsAgainstTheWindow() throws Exception {
        ScanGate gate = new ScanGate(scheduler, 2, 20);
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < 5; i++) {
            gate.submit(ran::incrementAndGet);
        }
        assertEquals(1, ran.get());
        assertEquals(2, gate.inFlight(), "the running one plus the held one");
        Thread.sleep(120);
        assertEquals(2, ran.get(), "window full: the third waits for a release, not for the bucket");
        gate.release();
        Thread.sleep(120);
        assertEquals(3, ran.get());
        gate.close();
    }

    /** close() runs a held launch instead of dropping it, so its Unit can still complete. */
    @Test
    public void closeRunsTheHeldLaunchRatherThanDroppingIt() {
        ScanGate gate = new ScanGate(scheduler, 0, 10);
        AtomicInteger ran = new AtomicInteger();
        gate.submit(ran::incrementAndGet);
        gate.submit(ran::incrementAndGet);
        assertEquals(1, ran.get());
        assertTrue(gate.isHolding());
        gate.close();
        assertEquals(2, ran.get());
        assertFalse(gate.isHolding());
    }
}
