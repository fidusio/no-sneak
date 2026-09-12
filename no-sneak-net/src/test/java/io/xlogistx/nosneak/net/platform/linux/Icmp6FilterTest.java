package io.xlogistx.nosneak.net.platform.linux;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The {@code struct icmp6_filter} bitmap. A SET bit blocks, so the filter starts all-ones
 * and clears {@code word = type >>> 5, bit = type & 31} per passed type. Getting the
 * word/bit arithmetic wrong would silently pass everything or nothing — and the reader
 * would look merely quiet.
 */
public class Icmp6FilterTest {

    private static int[] words(int... passTypes) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment filter = arena.allocate(Libc.ICMP6_FILTER_BYTES);
            filter.fill((byte) 0x55);
            Libc.fillIcmp6Filter(filter, passTypes);
            int[] out = new int[Libc.ICMP6_FILTER_WORDS];
            for (int i = 0; i < out.length; i++) {
                out[i] = filter.get(JAVA_INT, i * 4L);
            }
            return out;
        }
    }

    private static void assertOnly(int[] w, int word, int expected) {
        for (int i = 0; i < w.length; i++) {
            assertEquals(i == word ? expected : 0xFFFFFFFF, w[i], "word " + i);
        }
    }

    /** Exactly what LinuxIcmpPing installs: echo reply (129) → word 4, bit 1. */
    @Test
    public void passingEchoReplyClearsWordFourBitOne() {
        assertOnly(words(129), 4, 0xFFFFFFFD);
    }

    @Test
    public void passingNothingBlocksEverything() {
        for (int w : words()) {
            assertEquals(0xFFFFFFFF, w);
        }
    }

    @Test
    public void neighborAdvertisementIsWordFourBitEight() {
        assertOnly(words(136), 4, 0xFFFFFEFF);
        assertOnly(words(129, 136), 4, 0xFFFFFEFD);
    }

    @Test
    public void typeZeroAndTwoFiftyFiveAreTheEdges() {
        assertOnly(words(0), 0, 0xFFFFFFFE);
        assertOnly(words(255), 7, 0x7FFFFFFF);
    }
}
