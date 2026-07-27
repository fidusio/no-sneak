package io.xlogistx.nosneak.net.codecs;

/**
 * The internet checksum of RFC 1071: the one's-complement sum of 16-bit words,
 * complemented.
 * <p>
 * Two rules govern every use, and getting either wrong produces packets that are
 * silently dropped by the far end rather than rejected locally:
 * <ul>
 *   <li>PRECONDITION — the checksum field inside the input must already be zero
 *       when {@link #checksum} is called.</li>
 *   <li>POSTCONDITION — the returned value is the FINISHED checksum. Write it
 *       into the packet verbatim in network order. Do not complement it again.</li>
 * </ul>
 */
public final class InternetChecksum {

    /** IPv6 next-header value for ICMPv6, used in the pseudo-header. */
    public static final int NEXT_HEADER_ICMPV6 = 58;

    private static final int PSEUDO_HEADER_LENGTH = 40;

    private InternetChecksum() {
    }

    /**
     * @param data the bytes to sum, with the checksum field already zeroed
     * @return the finished checksum as an unsigned 16-bit value
     */
    public static int checksum(byte[] data, int off, int len) {
        return fold(sum(0, data, off, len, true));
    }

    /**
     * Verifies a checksum in place: summing a message that already carries its
     * correct checksum yields zero.
     *
     * @return true when the message's checksum is valid
     */
    public static boolean verify(byte[] data, int off, int len) {
        return checksum(data, off, len) == 0;
    }

    /**
     * ICMPv6 requires an IPv6 pseudo-header in the sum, so unlike ICMPv4 the
     * checksum depends on the source and destination addresses. This is why
     * {@link Icmp6} builders need both addresses even though neither appears in
     * the ICMPv6 message itself.
     * <p>
     * The pseudo-header is {@code src(16) + dst(16) + upperLayerLength(4, big
     * endian) + zeros(3) + nextHeader(1 = 58)}.
     *
     * @param srcAddr16 16-byte source address
     * @param dstAddr16 16-byte destination address
     * @param icmpv6    the ICMPv6 message, checksum field zeroed
     */
    public static int icmpv6Checksum(byte[] srcAddr16, byte[] dstAddr16,
                                     byte[] icmpv6, int off, int len) {
        requireLength(srcAddr16, 16, "srcAddr16");
        requireLength(dstAddr16, 16, "dstAddr16");

        byte[] pseudo = new byte[PSEUDO_HEADER_LENGTH];
        System.arraycopy(srcAddr16, 0, pseudo, 0, 16);
        System.arraycopy(dstAddr16, 0, pseudo, 16, 16);
        pseudo[32] = (byte) (len >>> 24);
        pseudo[33] = (byte) (len >>> 16);
        pseudo[34] = (byte) (len >>> 8);
        pseudo[35] = (byte) len;
        // pseudo[36..38] stay zero
        pseudo[39] = (byte) NEXT_HEADER_ICMPV6;

        // The pseudo-header is a whole number of 16-bit words, so it cannot
        // introduce an odd-byte pad partway through the sum.
        long acc = sum(0, pseudo, 0, PSEUDO_HEADER_LENGTH, false);
        return fold(sum(acc, icmpv6, off, len, true));
    }

    /**
     * @param padOdd when true, a trailing odd byte is padded on the right, which
     *               is correct only for the final segment of a sum
     */
    private static long sum(long acc, byte[] data, int off, int len, boolean padOdd) {
        if (off < 0 || len < 0 || off + len > data.length) {
            throw new IndexOutOfBoundsException(
                    "off=" + off + " len=" + len + " capacity=" + data.length);
        }
        int i = off;
        int end = off + len;
        while (end - i >= 2) {
            acc += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end && padOdd) {
            acc += (data[i] & 0xFF) << 8;
        }
        return acc;
    }

    private static int fold(long acc) {
        while ((acc >>> 16) != 0) {
            acc = (acc & 0xFFFF) + (acc >>> 16);
        }
        return (int) (~acc & 0xFFFF);
    }

    private static void requireLength(byte[] a, int expected, String name) {
        if (a == null || a.length != expected) {
            throw new IllegalArgumentException(
                    name + " must be " + expected + " bytes, got "
                    + (a == null ? "null" : String.valueOf(a.length)));
        }
    }
}
