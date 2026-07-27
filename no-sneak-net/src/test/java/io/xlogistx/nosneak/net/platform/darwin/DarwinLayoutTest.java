package io.xlogistx.nosneak.net.platform.darwin;

import io.xlogistx.nosneak.net.common.PingError;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemoryLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The §11.2 layout assertions for the Darwin column.
 * <p>
 * The whole point of these is that Darwin's structures are the SAME SIZE as
 * Linux's but a DIFFERENT SHAPE — a leading length byte pushes the family to
 * offset 1. Same size with a different layout fails silently, so the offsets
 * matter more here than the sizes do.
 * <p>
 * Pure arithmetic, so it runs on any platform. It cannot confirm these match the
 * real C structs; the §7.3 probe does that.
 */
public class DarwinLayoutTest {

    @Test
    public void structSizesMatchLinuxButShapesDoNot() {
        assertEquals(16, DarwinLibc.SOCKADDR_IN.byteSize(), "sockaddr_in");
        assertEquals(28, DarwinLibc.SOCKADDR_IN6.byteSize(), "sockaddr_in6");
        assertEquals(16, DarwinLibc.TIMEVAL.byteSize(), "timeval");
    }

    /** The leading sin_len byte is the whole difference from Linux. */
    @Test
    public void familyIsOneByteAtOffsetOne() {
        assertEquals(0, offsetOf(DarwinLibc.SOCKADDR_IN, "sin_len"));
        assertEquals(1, offsetOf(DarwinLibc.SOCKADDR_IN, "sin_family"));
        assertEquals(4, offsetOf(DarwinLibc.SOCKADDR_IN, "sin_addr"));

        assertEquals(0, offsetOf(DarwinLibc.SOCKADDR_IN6, "sin6_len"));
        assertEquals(1, offsetOf(DarwinLibc.SOCKADDR_IN6, "sin6_family"));
        assertEquals(8, offsetOf(DarwinLibc.SOCKADDR_IN6, "sin6_addr"));
        assertEquals(24, offsetOf(DarwinLibc.SOCKADDR_IN6, "sin6_scope_id"));
    }

    /** tv_usec is 32-bit and padded here, unlike Linux where both fields are 64-bit. */
    @Test
    public void timevalIsPaddedNotTwoLongs() {
        assertEquals(0, offsetOf(DarwinLibc.TIMEVAL, "tv_sec"));
        assertEquals(8, offsetOf(DarwinLibc.TIMEVAL, "tv_usec"));
        assertEquals(4, DarwinLibc.TIMEVAL.select(
                MemoryLayout.PathElement.groupElement("tv_usec")).byteSize());
    }

    /** Every one of these differs from the Linux value; that is why they are separate. */
    @Test
    public void constantsDifferFromLinux() {
        assertEquals(30, DarwinLibc.AF_INET6, "10 on Linux, 23 on Windows");
        assertEquals(18, DarwinLibc.AF_LINK);
        assertEquals(0xFFFF, DarwinLibc.SOL_SOCKET, "1 on Linux");
        assertEquals(0x1006, DarwinLibc.SO_RCVTIMEO, "20 on Linux");
        assertEquals(2, DarwinLibc.AF_INET);
        assertEquals(4, DarwinLibc.CTL_NET);
        assertEquals(17, DarwinLibc.PF_ROUTE);
        assertEquals(2, DarwinLibc.NET_RT_FLAGS);
        assertEquals(0x400, DarwinLibc.RTF_LLINFO);
    }

    /** BSD errno numbers are not Linux's — mapping them by Linux value would be wrong. */
    @Test
    public void bsdErrnoValuesAndMapping() {
        assertEquals(65, DarwinLibc.EHOSTUNREACH, "113 on Linux");
        assertEquals(51, DarwinLibc.ENETUNREACH, "101 on Linux");
        assertEquals(50, DarwinLibc.ENETDOWN, "100 on Linux");
        assertEquals(35, DarwinLibc.EAGAIN, "11 on Linux");

        assertEquals(PingError.HOST_UNREACHABLE, DarwinLibc.toPingError(DarwinLibc.EHOSTUNREACH));
        assertEquals(PingError.NETWORK_UNREACHABLE, DarwinLibc.toPingError(DarwinLibc.ENETUNREACH));
        assertEquals(PingError.PERMISSION, DarwinLibc.toPingError(DarwinLibc.EACCES));
        assertEquals(PingError.INTERFACE_DOWN, DarwinLibc.toPingError(DarwinLibc.ENETDOWN));
        assertEquals(PingError.IO, DarwinLibc.toPingError(9999));

        // A Linux EHOSTUNREACH (113) must NOT map to HOST_UNREACHABLE here.
        assertNotEquals(PingError.HOST_UNREACHABLE, DarwinLibc.toPingError(113));
    }

    @Test
    public void receiveTimeoutIsPositiveAndSubSecond() {
        long micros = DarwinLibc.RECV_TIMEOUT_SEC * 1_000_000 + DarwinLibc.RECV_TIMEOUT_USEC;
        assertTrue(micros > 0 && micros <= 1_000_000);
    }

    private static long offsetOf(MemoryLayout layout, String field) {
        return layout.byteOffset(MemoryLayout.PathElement.groupElement(field));
    }
}
