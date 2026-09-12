package io.xlogistx.nosneak.net.platform.darwin;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * What the Darwin fill helpers write: the leading length byte and the one-byte family
 * at offset 1 that distinguish BSD sockaddrs from Linux's. Same size, different shape —
 * which is why the bytes, not just the sizes, are pinned. Segments are pre-filled with
 * {@code 0xAA} so the initial {@code fill(0)} is asserted too.
 */
public class DarwinSockaddrFillTest {

    private static MemorySegment dirty(Arena arena, long size) {
        MemorySegment s = arena.allocate(size);
        s.fill((byte) 0xAA);
        return s;
    }

    private static int u8(MemorySegment s, long offset) {
        return s.get(JAVA_BYTE, offset) & 0xFF;
    }

    @Test
    public void sockaddrInHasLengthSixteenAndFamilyAtOne() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, DarwinLibc.SOCKADDR_IN.byteSize());
            DarwinLibc.fillSockaddrIn(sa, new byte[] {10, 0, 0, 61});

            assertEquals(16, u8(sa, 0), "sin_len");
            assertEquals(DarwinLibc.AF_INET, u8(sa, 1), "sin_family is ONE byte at offset 1");
            assertEquals(0, u8(sa, 2), "sin_port");
            assertEquals(0, u8(sa, 3));
            assertEquals(10, u8(sa, 4));
            assertEquals(61, u8(sa, 7));
            for (long i = 8; i < 16; i++) {
                assertEquals(0, u8(sa, i), "sin_zero[" + (i - 8) + "]");
            }
        }
    }

    @Test
    public void sockaddrIn6HasLengthTwentyEightAndFamilyThirty() {
        byte[] linkLocal = java.net.InetAddress.ofLiteral("fe80::1").getAddress();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, DarwinLibc.SOCKADDR_IN6.byteSize());
            DarwinLibc.fillSockaddrIn6(sa, linkLocal, 4);

            assertEquals(28, u8(sa, 0), "sin6_len");
            assertEquals(30, u8(sa, 1), "sin6_family = AF_INET6 = 30 on Darwin");
            assertEquals(0, u8(sa, 2), "sin6_port");
            assertEquals(0, u8(sa, 3));
            assertEquals(0, sa.get(JAVA_INT, 4), "sin6_flowinfo");
            for (int i = 0; i < 16; i++) {
                assertEquals(linkLocal[i] & 0xFF, u8(sa, 8 + i), "sin6_addr[" + i + "]");
            }
            assertEquals(4, sa.get(JAVA_INT, 24), "sin6_scope_id");
        }
    }
}
