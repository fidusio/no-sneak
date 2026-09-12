package io.xlogistx.nosneak.nmap;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cancellation of a running scan (PENDING-ISSUES P6). The scan pipeline needs a live
 * {@code NIOSocket} to drive end to end, so these tests pin the pieces cancellation is built
 * from directly: the {@link NMapScanner.ScanHandle} contract, the callbacks' {@code abort()},
 * and the {@code cancelled}-report accounting — each pure, no socket.
 */
public class ScanCancelTest {

    // ---- ScanHandle ----

    @Test
    public void cancelIsIdempotentAndRunsEachActionOnce() {
        NMapScanner.ScanHandle h = new NMapScanner.ScanHandle();
        AtomicInteger onCancel = new AtomicInteger();
        h.onCancel(onCancel::incrementAndGet);

        assertFalse(h.isCancelled());
        assertTrue(h.cancel(), "first cancel wins");
        assertTrue(h.isCancelled());
        assertFalse(h.cancel(), "second cancel is a no-op");
        assertEquals(1, onCancel.get(), "the cancel action runs exactly once");
    }

    @Test
    public void aTrackedAbortRunsOnCancelAndOnlyWhileTracked() {
        NMapScanner.ScanHandle h = new NMapScanner.ScanHandle();
        AtomicInteger aborts = new AtomicInteger();
        Runnable abort = aborts::incrementAndGet;

        h.track(abort);
        assertEquals(1, h.tracked());
        h.untrack(abort);              // the probe completed normally before any cancel
        assertEquals(0, h.tracked());

        assertTrue(h.cancel());
        assertEquals(0, aborts.get(), "an untracked probe is not aborted");
    }

    @Test
    public void everyInFlightProbeIsAbortedOnCancel() {
        NMapScanner.ScanHandle h = new NMapScanner.ScanHandle();
        AtomicInteger aborts = new AtomicInteger();
        h.track(aborts::incrementAndGet);
        h.track(aborts::incrementAndGet);
        h.track(aborts::incrementAndGet);

        assertTrue(h.cancel());
        assertEquals(3, aborts.get(), "each outstanding probe's abort ran");
    }

    @Test
    public void aProbeStartedAfterCancelIsAbortedImmediately() {
        NMapScanner.ScanHandle h = new NMapScanner.ScanHandle();
        assertTrue(h.cancel());
        AtomicInteger aborts = new AtomicInteger();
        h.track(aborts::incrementAndGet);           // registered after the cancel
        assertEquals(1, aborts.get(), "a probe registered post-cancel is aborted at once");

        AtomicInteger onCancel = new AtomicInteger();
        h.onCancel(onCancel::incrementAndGet);      // action added after the cancel
        assertEquals(1, onCancel.get(), "an action added post-cancel runs at once");
    }

    // ---- callback abort() ----

    @Test
    public void portScanAbortReportsCancelledWhenNeverConnected() {
        java.util.concurrent.ScheduledThreadPoolExecutor sched =
                new java.util.concurrent.ScheduledThreadPoolExecutor(1);
        try {
            java.util.List<PortScanCallback.Result> out = new java.util.ArrayList<>();
            PortScanCallback cb = new PortScanCallback(sched,
                    new org.zoxweb.shared.net.IPAddress("127.0.0.1", 9), 5, true, out::add);
            cb.abort();
            cb.abort();  // idempotent
            assertEquals(1, out.size());
            assertEquals(PortState.FILTERED, out.get(0).state());
            assertEquals("cancelled", out.get(0).reason());
        } finally {
            sched.shutdownNow();
        }
    }

    @Test
    public void udpScanAbortReportsCancelled() {
        io.xlogistx.nosneak.runtime.ManualScheduler clock =
                new io.xlogistx.nosneak.runtime.ManualScheduler();
        java.util.List<UdpScanCallback.Result> out = new java.util.ArrayList<>();
        UdpScanCallback cb = new UdpScanCallback(clock,
                new java.net.InetSocketAddress("127.0.0.1", 53),
                UdpProbePayloads.forPort(53), 4, out::add);
        cb.abort();
        cb.abort();
        assertEquals(1, out.size());
        assertEquals(PortState.FILTERED, out.get(0).state());
        assertEquals("cancelled", out.get(0).reason());
        assertEquals(-1, out.get(0).rttMs());
    }

    // ---- cancelled-report accounting ----

    @Test
    public void progressCountsWhatFinishedAndWhatWasAbandoned() {
        ScanReport report = new ScanReport();
        ScanReport.HostReport a = new ScanReport.HostReport("10.0.0.1");
        a.reason = "arp-reply";
        ScanReport.PortReport p80 = new ScanReport.PortReport(80, PortState.OPEN);
        p80.reason = "connected";
        ScanReport.PortReport p443 = new ScanReport.PortReport(443, PortState.FILTERED);
        p443.reason = "cancelled";
        a.ports.add(p80);
        a.ports.add(p443);
        ScanReport.HostReport b = new ScanReport.HostReport("10.0.0.2");
        b.reason = "cancelled";
        report.hosts.add(a);
        report.hosts.add(b);

        NMapScanner.Progress prog = NMapScanner.progress(report);
        assertEquals(1, prog.hostsDecided());
        assertEquals(2, prog.hostsTotal());
        assertEquals(1, prog.portsDone());
        assertEquals(1, prog.portsSkipped());
        assertTrue(prog.cancelledLine().contains("1 of 2"));
    }

    @Test
    public void anEmptyTargetScanNeverBlocksTheHandle() {
        NMapScanner.ScanHandle h = new NMapScanner.ScanHandle();
        // No completion is wired without a real NIOSocket; the point here is that a handle with
        // no tracked work cancels cleanly and reports nothing outstanding.
        assertEquals(0, h.tracked());
        assertTrue(h.cancel());
        assertNull(h.completion().getNow(null), "no report until the scan delivers one");
    }
}
