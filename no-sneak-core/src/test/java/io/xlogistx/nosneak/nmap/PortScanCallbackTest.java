package io.xlogistx.nosneak.nmap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link PortScanCallback} through its lifecycle methods directly — no socket, no
 * selector — so the classification table, the banner window and the exactly-once report are
 * pinned without a network. The scheduler is real (one thread) so the deadline and the banner
 * window genuinely fire.
 */
public class PortScanCallbackTest {

    private static final IPAddress ADDR = new IPAddress("127.0.0.1", 9);

    private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
    private final List<PortScanCallback.Result> results = new ArrayList<>();

    @AfterEach
    public void shutdown() {
        scheduler.shutdownNow();
    }

    private PortScanCallback probe(int timeoutSec, boolean banner) {
        return new PortScanCallback(scheduler, ADDR, timeoutSec, banner, r -> {
            synchronized (results) {
                results.add(r);
            }
        });
    }

    private PortScanCallback probeMs(long timeoutMs) {
        return new PortScanCallback(scheduler, ADDR, timeoutMs, true, r -> {
            synchronized (results) {
                results.add(r);
            }
        });
    }

    @Test
    public void aMillisecondDeadlineIsFilteredTimeoutWellUnderASecond() throws Exception {
        long start = System.nanoTime();
        probeMs(150);
        awaitOne(2_000);
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        PortScanCallback.Result r = only();
        assertEquals(PortState.FILTERED, r.state());
        assertEquals("timeout", r.reason());
        assertTrue(elapsedMs < 1_000, "the adaptive deadline must not round up to a second: " + elapsedMs + " ms");
    }

    private PortScanCallback.Result only() {
        synchronized (results) {
            assertEquals(1, results.size(), "expected exactly one report, got " + results);
            return results.get(0);
        }
    }

    private void awaitOne(long ms) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms);
        while (System.nanoTime() < end) {
            synchronized (results) {
                if (!results.isEmpty()) {
                    return;
                }
            }
            Thread.sleep(5);
        }
    }

    // ---- classification (row 11) ----

    @Test
    public void connectExceptionIsClosedRefused() {
        probe(5, false).exception(new ConnectException("Connection refused: connect"));
        assertEquals(PortState.CLOSED, only().state());
        assertEquals("conn-refused", only().reason());
    }

    @Test
    public void refusedByMessageIsClosedRefused() {
        probe(5, false).exception(new IOException("connection refused by peer"));
        assertEquals(PortState.CLOSED, only().state());
        assertEquals("conn-refused", only().reason());
    }

    /** NIOSocket's own connect monitor reports {@code IOException("Connection timed out")}. */
    @Test
    public void nioSocketsConnectionTimedOutIsFilteredTimeout() {
        probe(5, false).exception(new IOException("Connection timed out"));
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("timeout", only().reason());
    }

    @Test
    public void theReleaserRunsExactlyOnceWhenTheProbeFinishes() throws Exception {
        java.util.concurrent.atomic.AtomicInteger released = new java.util.concurrent.atomic.AtomicInteger();
        PortScanCallback p = probeMs(100);
        p.releaseWith(released::incrementAndGet);
        assertEquals(0, released.get(), "not before the probe finishes");
        awaitOne(2_000);
        assertEquals(1, released.get(), "the deadline finished the probe: the NIO appointment is released");
        p.exception(new IOException("late"));            // a second completion is a no-op
        assertEquals(1, released.get());
    }

    @Test
    public void aReleaserSetAfterAnInstantFinishRunsImmediately() {
        java.util.concurrent.atomic.AtomicInteger released = new java.util.concurrent.atomic.AtomicInteger();
        PortScanCallback p = probe(5, false);
        p.exception(new ConnectException("Connection refused"));   // finished before the key came back
        p.releaseWith(released::incrementAndGet);
        assertEquals(1, released.get(), "loopback shape: finish inside addClientSocket, release on return");
    }

    @Test
    public void resetIsClosedReset() {
        probe(5, false).exception(new SocketException("Connection reset"));
        assertEquals(PortState.CLOSED, only().state());
        assertEquals("reset", only().reason());
    }

    @Test
    public void noRouteIsFilteredNoRoute() {
        probe(5, false).exception(new NoRouteToHostException("No route to host"));
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("no-route", only().reason());
        results.clear();
        probe(5, false).exception(new IOException("Network is unreachable"));
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("no-route", only().reason());
    }

    /** The row-11 defect: an error the table has never seen used to read CLOSED. */
    @Test
    public void anUnknownErrorIsFilteredAndNamesTheException() {
        probe(5, false).exception(new IOException("Something the driver made up"));
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("error:IOException", only().reason());
    }

    @Test
    public void aNullThrowableIsFilteredNotClosed() {
        probe(5, false).exception(null);
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("error:unknown", only().reason());
    }

    @Test
    public void theDeadlineIsFilteredTimeout() throws Exception {
        probe(1, false);
        awaitOne(2_500);
        assertEquals(PortState.FILTERED, only().state());
        assertEquals("timeout", only().reason());
    }

    // ---- connect, RTT, banner (row 12) ----

    @Test
    public void aConnectWithoutBannerWindowIsOpenConnectedAtOnce() throws Exception {
        PortScanCallback cb = probe(5, false);
        cb.connectedFinished();
        PortScanCallback.Result r = only();
        assertEquals(PortState.OPEN, r.state());
        assertEquals("connected", r.reason());
        assertTrue(r.rttMs() >= 0, "rtt must be measured");
        assertNull(r.banner());
    }

    @Test
    public void aVolunteeredBannerCompletesTheProbeWithIt() throws Exception {
        PortScanCallback cb = probe(5, true);
        cb.connectedFinished();
        synchronized (results) {
            assertTrue(results.isEmpty(), "must wait for the banner window");
        }
        cb.accept(ByteBuffer.wrap("SSH-2.0-OpenSSH_9.6\r\n".getBytes(StandardCharsets.ISO_8859_1)));
        PortScanCallback.Result r = only();
        assertEquals(PortState.OPEN, r.state());
        assertEquals("connected", r.reason());
        assertEquals("SSH-2.0-OpenSSH_9.6", r.banner());
    }

    @Test
    public void aSilentServerCompletesOpenWhenTheWindowElapses() throws Exception {
        PortScanCallback cb = probe(5, true);
        long t0 = System.nanoTime();
        cb.connectedFinished();
        awaitOne(PortScanCallback.BANNER_WINDOW_MS + 1_500);
        long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
        PortScanCallback.Result r = only();
        assertEquals(PortState.OPEN, r.state());
        assertNull(r.banner());
        assertTrue(waited >= PortScanCallback.BANNER_WINDOW_MS - 50, "window cut short: " + waited);
        assertTrue(waited < PortScanCallback.BANNER_WINDOW_MS + 1_000, "window overran: " + waited);
    }

    @Test
    public void theBannerWindowNeverExceedsTheProbeTimeout() throws Exception {
        PortScanCallback cb = probe(1, true);
        cb.connectedFinished();
        awaitOne(2_500);
        assertEquals(PortState.OPEN, only().state());
        assertEquals("connected", only().reason(), "the FILTERED deadline must not fire after a connect");
    }

    @Test
    public void aResetDuringTheBannerWindowKeepsThePortOpen() throws Exception {
        PortScanCallback cb = probe(5, true);
        cb.connectedFinished();
        cb.exception(new SocketException("Connection reset"));
        assertEquals(PortState.OPEN, only().state());
        assertEquals("connected", only().reason());
    }

    @Test
    public void theBannerIsCappedAndCleaned() throws Exception {
        PortScanCallback cb = probe(5, true);
        cb.connectedFinished();
        byte[] big = new byte[PortScanCallback.BANNER_CAP + 500];
        java.util.Arrays.fill(big, (byte) 'A');
        big[0] = '\r';
        big[1] = '\n';
        big[PortScanCallback.BANNER_CAP + 100] = 0x01; // binary starts past the cap: never even stored
        cb.accept(ByteBuffer.wrap(big));
        String banner = only().banner();
        assertEquals(PortScanCallback.BANNER_CAP - 2, banner.length(), "cap applies, leading CR/LF trimmed");
        assertTrue(banner.chars().allMatch(c -> c == 'A'));

        // binary inside the cap ends the greeting there (2026-09-22; see cleanBannerEndsAtTheFirstBinaryByte)
        PortScanCallback cb2 = probe(5, true);
        cb2.connectedFinished();
        cb2.accept(ByteBuffer.wrap("hello\r\n\u0001AAAA".getBytes(StandardCharsets.ISO_8859_1)));
        assertEquals("hello", results.get(1).banner());
    }

    @Test
    public void bytesBeforeAConnectAreIgnored() {
        PortScanCallback cb = probe(5, true);
        cb.accept(ByteBuffer.wrap("junk".getBytes(StandardCharsets.ISO_8859_1)));
        synchronized (results) {
            assertTrue(results.isEmpty());
        }
    }

    // ---- exactly once ----

    @Test
    public void aSecondCompletionIsANoOp() throws Exception {
        PortScanCallback cb = probe(5, false);
        cb.exception(new ConnectException("refused"));
        cb.connectedFinished();
        cb.exception(new IOException("later"));
        assertEquals(1, results.size());
        assertEquals(PortState.CLOSED, only().state());
    }

    @Test
    public void theStateOnlyConstructorStillReportsAState() throws Exception {
        List<PortState> states = new ArrayList<>();
        PortScanCallback cb = new PortScanCallback(scheduler, ADDR, 5, states::add);
        cb.connectedFinished();
        assertEquals(List.of(PortState.OPEN), states);
    }

    @Test
    public void cleanBannerCollapsesLineBreaksAndDropsEmpty() {
        assertEquals("220 mail ready ESMTP", PortScanCallback.cleanBanner("220 mail ready\r\nESMTP\r\n"));
        assertNull(PortScanCallback.cleanBanner("\r\n\r\n"));
    }

    // 2026-09-22: dropbear sends its binary KEXINIT in the same read as its greeting; the banner
    // ends where the binary starts, so the packet's printable fragments never reach the report.
    @Test
    public void cleanBannerEndsAtTheFirstBinaryByte() {
        String kexinit = "\u0000\u0000\u00043\u0006\u0014" + "sntrup761x25519-sha512,curve25519-sha256" + "\u0000\u0000";
        assertEquals("SSH-2.0-dropbear", PortScanCallback.cleanBanner("SSH-2.0-dropbear\r\n" + kexinit));
        assertNull(PortScanCallback.cleanBanner(kexinit), "a purely binary greeting is no banner");
        assertEquals("a b", PortScanCallback.cleanBanner("a\tb"), "a tab is text, collapsed like a line break");
        assertEquals("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
                PortScanCallback.cleanBanner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19\r\n"));
    }
}
