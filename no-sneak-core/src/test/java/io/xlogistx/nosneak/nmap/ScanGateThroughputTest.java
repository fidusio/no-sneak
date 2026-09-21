package io.xlogistx.nosneak.nmap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.task.TaskProcessor;
import org.zoxweb.server.task.TaskSchedulerProcessor;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How many launches per second the gate actually lets through at the default caps (256 in
 * flight, 2000/s) on the pools the app uses. A {@code /24} with 21 live hosts is ~21,500
 * connects; if the pacer's per-launch scheduler hop costs more than the 1 ms it asks for, the
 * whole scan is bounded by that hop, not by the caps. Measured, not assumed.
 */
public class ScanGateThroughputTest {

    private TaskProcessor executor;
    private TaskSchedulerProcessor zoxScheduler;
    private final ScheduledThreadPoolExecutor jdkScheduler = new ScheduledThreadPoolExecutor(1);

    @BeforeEach
    public void pools() {
        executor = new TaskProcessor("gate-tp", 64, 4, Thread.NORM_PRIORITY, false);
        zoxScheduler = new TaskSchedulerProcessor(executor);
    }

    @AfterEach
    public void shutdown() {
        try { zoxScheduler.close(); } catch (Exception ignored) { }
        try { executor.close(); } catch (Exception ignored) { }
        jdkScheduler.shutdownNow();
    }

    private static double launchesPerSecond(ScanGate gate, int n) throws Exception {
        CountDownLatch done = new CountDownLatch(n);
        long start = System.nanoTime();
        for (int i = 0; i < n; i++) {
            gate.submit(() -> {
                // a launch that finishes at once: the fastest possible unit
                gate.release();
                done.countDown();
            });
        }
        assertTrue(done.await(60, TimeUnit.SECONDS), "gate never drained " + n + " launches");
        long elapsedNs = System.nanoTime() - start;
        gate.close();
        return n / (elapsedNs / 1_000_000_000.0);
    }

    /**
     * Before the per-slot quantum (2026-09-19) this measured 990/s: the pacer's 1 ms rounding
     * halved the default cap. Now two launches leave per millisecond slot.
     */
    @Test
    public void defaultCapsOnTheZoxwebScheduler() throws Exception {
        ScanGate gate = new ScanGate(zoxScheduler, 256, 2000);
        assertEquals(2, gate.perSlot());
        double rate = launchesPerSecond(gate, 4_000);
        System.out.println("ScanGate 256/2000 on TaskSchedulerProcessor: " + (long) rate + " launches/s");
        assertTrue(rate > 1_400, "expected most of the 2000/s cap, got " + (long) rate);
        assertTrue(rate <= 2_100, "must not exceed the cap: " + (long) rate);
    }

    @Test
    public void defaultCapsOnTheJdkScheduler() throws Exception {
        double rate = launchesPerSecond(new ScanGate(jdkScheduler, 256, 2000), 4_000);
        System.out.println("ScanGate 256/2000 on ScheduledThreadPoolExecutor: " + (long) rate + " launches/s");
        assertTrue(rate > 1_400, "expected most of the 2000/s cap, got " + (long) rate);
        assertTrue(rate <= 2_100, "must not exceed the cap: " + (long) rate);
    }

    /** {@code -T5}: 10000/s must actually be faster than {@code -T3}, not the same 1000/s. */
    @Test
    public void tenThousandPerSecondIsTenPerSlot() throws Exception {
        ScanGate gate = new ScanGate(zoxScheduler, 1024, 10_000);
        assertEquals(10, gate.perSlot());
        double rate = launchesPerSecond(gate, 10_000);
        System.out.println("ScanGate 1024/10000 on TaskSchedulerProcessor: " + (long) rate + " launches/s");
        assertTrue(rate > 5_000, "expected well above the old 1000/s ceiling, got " + (long) rate);
        assertTrue(rate <= 10_500, "must not exceed the cap: " + (long) rate);
    }

    /** Below 1000/s the slot is longer than a millisecond and the quantum is one, as before. */
    @Test
    public void belowAThousandPerSecondTheQuantumIsOne() {
        assertEquals(1, new ScanGate(jdkScheduler, 0, 500).perSlot());
        assertEquals(1, new ScanGate(jdkScheduler, 0, 20).perSlot());
        assertEquals(1, new ScanGate(jdkScheduler, 0, 1000).perSlot());
        assertEquals(1, new ScanGate(jdkScheduler, 0, 0).perSlot(), "unpaced");
    }

    @Test
    public void unpacedGateIsBoundOnlyByTheWindow() throws Exception {
        double rate = launchesPerSecond(new ScanGate(zoxScheduler, 256, 0), 20_000);
        System.out.println("ScanGate 256/unpaced: " + (long) rate + " launches/s");
        assertTrue(rate > 100_000, "an unpaced gate should drain synchronously, got " + (long) rate);
    }
}
