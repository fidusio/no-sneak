package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.runtime.ManualScheduler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The UDP classification table and the probe's exactly-once completion, driven with no socket:
 * the ingress hooks the selector and the timers would call are invoked directly.
 */
public class UdpScanCallbackTest {

    private ManualScheduler clock;
    private final List<UdpScanCallback.Result> results = new ArrayList<>();

    @BeforeEach
    public void fresh() {
        clock = new ManualScheduler();
        results.clear();
    }

    private UdpScanCallback probe() {
        return new UdpScanCallback(clock, new InetSocketAddress("127.0.0.1", 53),
                                   UdpProbePayloads.forPort(53), 4, results::add);
    }

    @Test
    public void aDatagramBackIsOpenWithRttAndBanner() {
        UdpScanCallback cb = probe();
        cb.onDatagram("HELLO\r\nworld".getBytes(StandardCharsets.ISO_8859_1));
        assertEquals(1, results.size());
        UdpScanCallback.Result r = results.get(0);
        assertEquals(PortState.OPEN, r.state());
        assertEquals("udp-response", r.reason());
        assertTrue(r.rttMs() >= 0, "an answered probe has an RTT");
        assertEquals("HELLO world", r.banner());
    }

    @Test
    public void anEmptyDatagramIsStillOpenJustWithoutABanner() {
        UdpScanCallback cb = probe();
        cb.onDatagram(new byte[0]);
        assertEquals(PortState.OPEN, results.get(0).state());
        assertNull(results.get(0).banner());
    }

    @Test
    public void icmpPortUnreachableIsClosed() {
        UdpScanCallback cb = probe();
        cb.onReceiveError(new PortUnreachableException("ICMP Port Unreachable"));
        assertEquals(PortState.CLOSED, results.get(0).state());
        assertEquals("port-unreach", results.get(0).reason());
    }

    @Test
    public void windowsReportsTheSameIcmpAsAReset() {
        UdpScanCallback.Classification c = UdpScanCallback.classify(
                new SocketException("An existing connection was forcibly closed by the remote host"));
        assertEquals(PortState.CLOSED, c.state());
        assertEquals("port-unreach", c.reason());
    }

    @Test
    public void otherUnreachablesAreFilteredNoRoute() {
        UdpScanCallback.Classification c = UdpScanCallback.classify(new IOException("Network is unreachable"));
        assertEquals(PortState.FILTERED, c.state());
        assertEquals("no-route", c.reason());
        c = UdpScanCallback.classify(new IOException("No route to host"));
        assertEquals(PortState.FILTERED, c.state());
        assertEquals("no-route", c.reason());
    }

    @Test
    public void aKickoffFailureIsClassifiedByItsCause() {
        UdpScanCallback.Classification c = UdpScanCallback.classify(
                new java.io.UncheckedIOException(new PortUnreachableException("ICMP Port Unreachable")));
        assertEquals(PortState.CLOSED, c.state());
        assertEquals("port-unreach", c.reason());
    }

    @Test
    public void anUnknownErrorIsFilteredNamingTheException() {
        UdpScanCallback.Classification c = UdpScanCallback.classify(new IOException("weird"));
        assertEquals(PortState.FILTERED, c.state());
        assertEquals("error:IOException", c.reason());
    }

    @Test
    public void silenceForTheWholeBudgetIsOpenFilteredAfterOneRetransmit() {
        UdpScanCallback cb = probe();
        cb.arm();
        assertEquals(2, clock.tasks.size(), "a retransmit and a deadline");
        assertEquals(2_000, clock.tasks.get(0).delayMs, "retransmit at half the 4 s budget");
        assertEquals(4_000, clock.tasks.get(1).delayMs, "deadline at the full budget");

        clock.tasks.get(0).run();  // retransmit: no channel in this test, so it is a no-op
        assertTrue(results.isEmpty(), "a retransmit alone decides nothing");
        clock.tasks.get(1).run();  // deadline
        assertEquals(1, results.size());
        assertEquals(PortState.OPEN_FILTERED, results.get(0).state());
        assertEquals("no-response", results.get(0).reason());
        assertEquals(-1, results.get(0).rttMs(), "silence has no RTT");
    }

    @Test
    public void completionIsExactlyOnceWhicheverArrivesFirst() {
        UdpScanCallback cb = probe();
        cb.arm();
        cb.onDatagram("x".getBytes(StandardCharsets.ISO_8859_1));
        clock.tasks.get(1).run();                              // a late deadline
        cb.onReceiveError(new PortUnreachableException());     // a late ICMP
        assertEquals(1, results.size());
        assertEquals(PortState.OPEN, results.get(0).state(), "the first verdict stands");
        assertTrue(clock.tasks.get(0).isCancelled(), "the retransmit was cancelled on completion");
        assertTrue(clock.tasks.get(1).isCancelled(), "the deadline was cancelled on completion");
    }

    @Test
    public void bannerIsCappedAndPrintableOnly() {
        byte[] noisy = new byte[600];
        for (int i = 0; i < noisy.length; i++) noisy[i] = (byte) (i % 2 == 0 ? 'A' : 0x01);
        String b = UdpScanCallback.banner(noisy);
        assertEquals(UdpScanCallback.BANNER_CAP / 2, b.length(), "cap applied before cleaning");
        assertTrue(b.chars().allMatch(ch -> ch == 'A'));
    }
}
