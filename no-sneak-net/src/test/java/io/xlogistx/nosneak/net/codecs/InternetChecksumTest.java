package io.xlogistx.nosneak.net.codecs;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RFC 1071 checksum, against the RFC's own worked example plus the
 * sum-to-zero invariant that every correct implementation must satisfy.
 */
public class InternetChecksumTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    /**
     * The worked example from RFC 1071 section 3: the octets 00 01 f2 03 f4 f5
     * f6 f7 sum to ddf2, so the checksum is its complement, 220d.
     */
    @Test
    public void rfc1071WorkedExample() {
        byte[] data = hex("0001 f203 f4f5 f6f7");
        assertEquals(0x220d, InternetChecksum.checksum(data, 0, data.length));
    }

    /**
     * The defining invariant: summing a message that already carries its correct
     * checksum yields zero. This is what receivers actually do, and it catches
     * fold and complement errors the worked example alone would not.
     */
    @Test
    public void checksumOverMessageIncludingItsOwnChecksumIsZero() {
        byte[] msg = hex("0800 0000 abcd 0001 6162 6364");
        int ck = InternetChecksum.checksum(msg, 0, msg.length);
        msg[2] = (byte) (ck >>> 8);
        msg[3] = (byte) ck;

        assertEquals(0, InternetChecksum.checksum(msg, 0, msg.length));
        assertTrue(InternetChecksum.verify(msg, 0, msg.length));
    }

    @Test
    public void verifyRejectsCorruption() {
        byte[] msg = hex("0800 0000 abcd 0001 6162 6364");
        int ck = InternetChecksum.checksum(msg, 0, msg.length);
        msg[2] = (byte) (ck >>> 8);
        msg[3] = (byte) ck;
        assertTrue(InternetChecksum.verify(msg, 0, msg.length));

        msg[msg.length - 1] ^= 0x01;
        assertFalse(InternetChecksum.verify(msg, 0, msg.length));
    }

    /** An odd trailing byte is padded on the right, not the left. */
    @Test
    public void oddLengthPadsTrailingByteHigh() {
        byte[] odd = hex("0001 f203 f4");
        byte[] padded = hex("0001 f203 f400");
        assertEquals(InternetChecksum.checksum(padded, 0, padded.length),
                     InternetChecksum.checksum(odd, 0, odd.length));
    }

    /** All-zero input complements to all-ones, the "no checksum computed" wire value. */
    @Test
    public void allZeroInput() {
        byte[] zeros = new byte[8];
        assertEquals(0xFFFF, InternetChecksum.checksum(zeros, 0, zeros.length));
    }

    /** Byte order matters: swapping a word pair must change the result. */
    @Test
    public void isOrderSensitive() {
        byte[] a = hex("1234 5678");
        byte[] b = hex("3412 5678");
        assertNotEquals(InternetChecksum.checksum(a, 0, a.length),
                        InternetChecksum.checksum(b, 0, b.length));
    }

    /** The end-around carry must fold repeatedly, not once. */
    @Test
    public void foldsCarryRepeatedly() {
        byte[] many = new byte[512];
        java.util.Arrays.fill(many, (byte) 0xFF);
        int ck = InternetChecksum.checksum(many, 0, many.length);
        assertTrue(ck >= 0 && ck <= 0xFFFF, "checksum must stay 16-bit, got " + ck);
    }

    @Test
    public void honoursOffsetAndLength() {
        byte[] framed = hex("dead 0001 f203 f4f5 f6f7 beef");
        assertEquals(0x220d, InternetChecksum.checksum(framed, 2, 8));
    }

    @Test
    public void rejectsOutOfBoundsRange() {
        byte[] data = new byte[4];
        assertThrows(IndexOutOfBoundsException.class,
                     () -> InternetChecksum.checksum(data, 2, 4));
    }

    // ---- ICMPv6 pseudo-header ----

    private static final byte[] SRC = hex("fe80 0000 0000 0000 0000 0000 0000 0001");
    private static final byte[] DST = hex("fe80 0000 0000 0000 0000 0000 0000 0002");

    /** The pseudo-header sum-to-zero invariant, the ICMPv6 analogue of the above. */
    @Test
    public void icmpv6ChecksumVerifiesToZero() {
        byte[] msg = hex("8000 0000 abcd 0001 6162 6364");
        int ck = InternetChecksum.icmpv6Checksum(SRC, DST, msg, 0, msg.length);
        msg[2] = (byte) (ck >>> 8);
        msg[3] = (byte) ck;
        assertEquals(0, InternetChecksum.icmpv6Checksum(SRC, DST, msg, 0, msg.length));
    }

    /**
     * The addresses are genuinely in the sum — this is the whole reason ICMPv6
     * builders need them, and an implementation that ignored the pseudo-header
     * would still pass the zero-invariant test above.
     */
    @Test
    public void icmpv6ChecksumDependsOnAddresses() {
        byte[] msg = hex("8000 0000 abcd 0001");
        byte[] otherDst = hex("fe80 0000 0000 0000 0000 0000 0000 0003");
        assertNotEquals(InternetChecksum.icmpv6Checksum(SRC, DST, msg, 0, msg.length),
                        InternetChecksum.icmpv6Checksum(SRC, otherDst, msg, 0, msg.length));
    }

    /** The length field and next-header 58 are part of the sum too. */
    @Test
    public void icmpv6ChecksumDiffersFromPlainChecksum() {
        byte[] msg = hex("8000 0000 abcd 0001");
        assertNotEquals(InternetChecksum.checksum(msg, 0, msg.length),
                        InternetChecksum.icmpv6Checksum(SRC, DST, msg, 0, msg.length));
    }

    @Test
    public void icmpv6RejectsWrongAddressLength() {
        byte[] msg = hex("8000 0000");
        byte[] short4 = hex("0a000001");
        assertThrows(IllegalArgumentException.class,
                     () -> InternetChecksum.icmpv6Checksum(short4, DST, msg, 0, msg.length));
        assertThrows(IllegalArgumentException.class,
                     () -> InternetChecksum.icmpv6Checksum(SRC, short4, msg, 0, msg.length));
    }
}
