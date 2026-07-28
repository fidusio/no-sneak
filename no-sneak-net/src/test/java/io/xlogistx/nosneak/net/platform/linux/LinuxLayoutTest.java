package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.common.PingError;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemoryLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The §11.2 layout assertions for the Linux column, plus the constants and
 * byte-order helpers the backend depends on.
 * <p>
 * These are pure arithmetic over {@link MemoryLayout}s and run on ANY platform —
 * which is the point. A struct-size or field-offset typo is caught on a developer
 * machine rather than only on the appliance. What they cannot check is that these
 * layouts match the real C structs — that came from running the backend on live
 * hardware, x86-64 and aarch64 (§13.6).
 */
public class LinuxLayoutTest {

    @Test
    public void structSizes() {
        assertEquals(16, Libc.SOCKADDR_IN.byteSize(), "sockaddr_in");
        assertEquals(28, Libc.SOCKADDR_IN6.byteSize(), "sockaddr_in6");
        assertEquals(20, Libc.SOCKADDR_LL.byteSize(), "sockaddr_ll");
        assertEquals(16, Libc.TIMEVAL.byteSize(), "timeval");
        assertEquals(16, Libc.PACKET_MREQ.byteSize(), "packet_mreq");
        assertEquals(32, Libc.ICMP6_FILTER_BYTES, "icmp6_filter is 8 x uint32");
    }

    /**
     * The offsets the reader thread reads by hand. {@code sll_protocol} carries the
     * ethertype and {@code sll_addr} the source MAC — reading either from the wrong
     * offset would silently misroute every frame.
     */
    @Test
    public void sockaddrLlOffsets() {
        assertEquals(0, offsetOf(Libc.SOCKADDR_LL, "sll_family"));
        assertEquals(Libc.SLL_PROTOCOL, offsetOf(Libc.SOCKADDR_LL, "sll_protocol"));
        assertEquals(Libc.SLL_IFINDEX, offsetOf(Libc.SOCKADDR_LL, "sll_ifindex"));
        assertEquals(Libc.SLL_HALEN, offsetOf(Libc.SOCKADDR_LL, "sll_halen"));
        assertEquals(Libc.SLL_ADDR, offsetOf(Libc.SOCKADDR_LL, "sll_addr"));
    }

    /** Linux puts the family in two bytes at offset 0 — no leading sin_len, unlike Darwin. */
    @Test
    public void sockaddrInHasNoLengthByte() {
        assertEquals(0, offsetOf(Libc.SOCKADDR_IN, "sin_family"));
        assertEquals(4, offsetOf(Libc.SOCKADDR_IN, "sin_addr"));
        assertEquals(0, offsetOf(Libc.SOCKADDR_IN6, "sin6_family"));
        assertEquals(8, offsetOf(Libc.SOCKADDR_IN6, "sin6_addr"));
        assertEquals(24, offsetOf(Libc.SOCKADDR_IN6, "sin6_scope_id"));
    }

    /** AF_INET6 differs per platform: 10 here, 30 on Darwin, 23 on Windows. */
    @Test
    public void constants() {
        assertEquals(2, Libc.AF_INET);
        assertEquals(10, Libc.AF_INET6);
        assertEquals(17, Libc.AF_PACKET);
        assertEquals(2, Libc.SOCK_DGRAM);
        assertEquals(3, Libc.SOCK_RAW);
        assertEquals(1, Libc.IPPROTO_ICMP);
        assertEquals(58, Libc.IPPROTO_ICMPV6);
        assertEquals(0x0806, Libc.ETH_P_ARP);
        assertEquals(0x86DD, Libc.ETH_P_IPV6);
        assertEquals(1, Libc.SOL_SOCKET);
        assertEquals(20, Libc.SO_RCVTIMEO);
        assertEquals(263, Libc.SOL_PACKET);
    }

    @Test
    public void byteOrderHelpersRoundTrip() {
        assertEquals(0x0806, Libc.ntohs(Libc.htons(0x0806)));
        assertEquals(0x86DD, Libc.ntohs(Libc.htons(0x86DD)));
        // 0x0806 big-endian is 08 06, so the low byte of the network-order short is 0x06
        assertEquals((short) 0x0608, Libc.htons(0x0806));
    }

    /** §4.7's mapping. HOST_UNREACHABLE must never collapse into TIMEOUT. */
    @Test
    public void errnoMapping() {
        assertEquals(PingError.HOST_UNREACHABLE, Libc.toPingError(Libc.EHOSTUNREACH));
        assertEquals(PingError.NETWORK_UNREACHABLE, Libc.toPingError(Libc.ENETUNREACH));
        assertEquals(PingError.PERMISSION, Libc.toPingError(Libc.EACCES));
        assertEquals(PingError.PERMISSION, Libc.toPingError(Libc.EPERM));
        assertEquals(PingError.INTERFACE_DOWN, Libc.toPingError(Libc.ENETDOWN));
        assertEquals(PingError.INTERFACE_DOWN, Libc.toPingError(Libc.ENXIO));
        assertEquals(PingError.IO, Libc.toPingError(Libc.EINVAL));
        assertEquals(PingError.IO, Libc.toPingError(9999));
    }

    /** EAGAIN is the SO_RCVTIMEO tick, not an error — the reader loop depends on it. */
    @Test
    public void timeoutIsRecognised() {
        assertTrue(Libc.isTimeout(Libc.EAGAIN));
        assertFalse(Libc.isTimeout(Libc.EHOSTUNREACH));
        assertEquals(11, Libc.EAGAIN, "EAGAIN == EWOULDBLOCK == 11 on Linux");
    }

    /** The receive timeout must be positive, or shutdown would block forever (§4.4). */
    @Test
    public void receiveTimeoutIsPositiveAndSubSecond() {
        long micros = Libc.RECV_TIMEOUT_SEC * 1_000_000 + Libc.RECV_TIMEOUT_USEC;
        assertTrue(micros > 0, "a zero timeout blocks forever");
        assertTrue(micros <= 1_000_000, "shutdown should not wait more than a second per reader");
    }

    private static long offsetOf(MemoryLayout layout, String field) {
        return layout.byteOffset(MemoryLayout.PathElement.groupElement(field));
    }
}
