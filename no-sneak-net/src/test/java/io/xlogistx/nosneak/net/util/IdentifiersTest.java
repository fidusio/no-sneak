package io.xlogistx.nosneak.net.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two 16-bit fields that correlate an ICMP reply to its probe. A wrong packing
 * here completes the wrong probe; a zero identifier looks like an unset one.
 */
public class IdentifiersTest {

    @Test
    public void correlationKeyPacksIdentifierHighAndSequenceLow() {
        assertEquals(0x12345678L, Identifiers.correlationKey(0x1234, 0x5678));
        assertEquals(0xFFFFFFFFL, Identifiers.correlationKey(0xFFFF, 0xFFFF), "positive, not -1");
        assertEquals(0x10000L, Identifiers.correlationKey(1, 0));
    }

    @Test
    public void correlationKeyMasksTo16Bits() {
        assertEquals(Identifiers.correlationKey(1, 2), Identifiers.correlationKey(0x1_0001, 0x1_0002));
        assertNotEquals(Identifiers.correlationKey(1, 2), Identifiers.correlationKey(2, 1));
    }

    /**
     * The counter is process-wide and cannot be reset, so cross the 16-bit wrap
     * deliberately: no draw may be zero, none may exceed 16 bits, and consecutive
     * draws must differ.
     */
    @Test
    public void nextIdentifierSkipsZeroAcrossTheWrap() {
        int previous = Identifiers.nextIdentifier();
        for (int i = 0; i < 70_000; i++) {
            int id = Identifiers.nextIdentifier();
            assertTrue(id != 0, "identifier 0 must never be handed out");
            assertTrue(id <= 0xFFFF, "identifier must fit 16 bits: " + id);
            assertNotEquals(previous, id, "consecutive identifiers must differ");
            previous = id;
        }
    }

    @Test
    public void sequenceAllocatorStartsAtZeroAndWrapsAt65536() {
        Identifiers.SequenceAllocator seq = Identifiers.newSequenceAllocator();
        assertEquals(0, seq.next());
        int last = 0;
        for (int i = 0; i < 65_535; i++) {
            last = seq.next();
        }
        assertEquals(65535, last);
        assertEquals(0, seq.next(), "wraps to zero");
    }

    @Test
    public void sequenceAllocatorsAreIndependent() {
        Identifiers.SequenceAllocator a = Identifiers.newSequenceAllocator();
        Identifiers.SequenceAllocator b = Identifiers.newSequenceAllocator();
        a.next();
        a.next();
        assertEquals(0, b.next(), "a second socket's sequences start at zero regardless");
        assertEquals(2, a.next());
    }
}
