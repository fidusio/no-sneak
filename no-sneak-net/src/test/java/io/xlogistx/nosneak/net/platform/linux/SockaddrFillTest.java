package io.xlogistx.nosneak.net.platform.linux;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The bytes the fill helpers write, not just the offsets the layouts declare — the
 * layout tests pin where a field IS, these pin what goes INTO it. Pure arena
 * arithmetic, no socket. Every segment is pre-filled with {@code 0xAA} so the
 * {@code fill(0)} at the start of each helper is asserted too.
 */
public class SockaddrFillTest {

    private static final byte[] MAC = {(byte) 0xb0, 0x7b, 0x25, (byte) 0x82, 0x64, 0x45};

    private static MemorySegment dirty(Arena arena, long size) {
        MemorySegment s = arena.allocate(size);
        s.fill((byte) 0xAA);
        return s;
    }

    private static int u8(MemorySegment s, long offset) {
        return s.get(JAVA_BYTE, offset) & 0xFF;
    }

    /** The {@code 11 00 08 06} prefix §13.6 captured live: AF_PACKET little-endian, ethertype big-endian. */
    @Test
    public void sockaddrLlCarriesEthertypeBigEndianAndHalenSix() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, Libc.SOCKADDR_LL.byteSize());
            Libc.fillSockaddrLl(sa, 7, Libc.ETH_P_ARP, MAC);

            assertEquals(0x11, u8(sa, 0), "sll_family low byte = AF_PACKET (17)");
            assertEquals(0x00, u8(sa, 1));
            assertEquals(0x08, u8(sa, 2), "sll_protocol is network byte order: 08 06");
            assertEquals(0x06, u8(sa, 3));
            assertEquals(7, sa.get(JAVA_INT, Libc.SLL_IFINDEX));
            assertEquals(0, sa.get(JAVA_SHORT, 8), "sll_hatype zeroed");
            assertEquals(0, u8(sa, 10), "sll_pkttype zeroed");
            assertEquals(6, u8(sa, Libc.SLL_HALEN));
            for (int i = 0; i < 6; i++) {
                assertEquals(MAC[i] & 0xFF, u8(sa, Libc.SLL_ADDR + i), "sll_addr[" + i + "]");
            }
            assertEquals(0, u8(sa, 18), "sll_addr padding zeroed");
            assertEquals(0, u8(sa, 19));
        }
    }

    @Test
    public void sockaddrLlForIpv6Ethertype() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, Libc.SOCKADDR_LL.byteSize());
            Libc.fillSockaddrLl(sa, 3, Libc.ETH_P_IPV6, MAC);
            assertEquals(0x86, u8(sa, 2));
            assertEquals(0xDD, u8(sa, 3));
        }
    }

    @Test
    public void sockaddrInFamilyAtZeroAddressAtFour() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, Libc.SOCKADDR_IN.byteSize());
            Libc.fillSockaddrIn(sa, new byte[] {10, 0, 0, 61});

            assertEquals(Libc.AF_INET, sa.get(JAVA_SHORT, 0));
            assertEquals(0, sa.get(JAVA_SHORT, 2), "sin_port zero: ICMP has no ports");
            assertEquals(10, u8(sa, 4));
            assertEquals(0, u8(sa, 5));
            assertEquals(0, u8(sa, 6));
            assertEquals(61, u8(sa, 7));
            for (long i = 8; i < 16; i++) {
                assertEquals(0, u8(sa, i), "sin_zero[" + (i - 8) + "]");
            }
        }
    }

    @Test
    public void sockaddrIn6ScopeIdAtTwentyFour() {
        byte[] linkLocal = java.net.InetAddress.ofLiteral("fe80::1").getAddress();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = dirty(arena, Libc.SOCKADDR_IN6.byteSize());
            Libc.fillSockaddrIn6(sa, linkLocal, 4);

            assertEquals(Libc.AF_INET6, sa.get(JAVA_SHORT, 0));
            assertEquals(0, sa.get(JAVA_SHORT, 2), "sin6_port");
            assertEquals(0, sa.get(JAVA_INT, 4), "sin6_flowinfo");
            for (int i = 0; i < 16; i++) {
                assertEquals(linkLocal[i] & 0xFF, u8(sa, 8 + i), "sin6_addr[" + i + "]");
            }
            assertEquals(4, sa.get(JAVA_INT, 24), "sin6_scope_id = interface index");
        }
    }
}
