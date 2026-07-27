package io.xlogistx.nosneak.net.codecs;

import java.util.Arrays;
import java.util.Optional;

/**
 * The fixed 40-byte IPv6 header, RFC 8200.
 * <p>
 * Only the paths that inject below the IP layer build one of these: the Linux
 * {@code AF_PACKET} NDP path and the Windows pcap path. Where the kernel routes
 * for us it builds its own.
 * <p>
 * <b>HOP LIMIT 255 IS A SECURITY REQUIREMENT, NOT A DEFAULT.</b> RFC 4861 §7.1.1
 * requires receivers to discard Neighbor Solicitations and Advertisements whose
 * hop limit is not 255 — it is what proves the sender is on-link, since a router
 * would have decremented it. Getting this wrong produces a total, silent failure
 * of IPv6 resolution with no error reported anywhere, which is why
 * {@link #isValidNeighborDiscovery} exists and must be applied on receive as well
 * as on send.
 */
public final class Ipv6Header {

    public static final int LENGTH = 40;

    /** The only legal hop limit for NS and NA, in both directions. */
    public static final int HOP_LIMIT_NEIGHBOR_DISCOVERY = 255;

    public static final int NEXT_HEADER_ICMPV6 = 58;

    private static final int VERSION_6 = 6;
    private static final int OFF_PAYLOAD_LENGTH = 4;
    private static final int OFF_NEXT_HEADER = 6;
    private static final int OFF_HOP_LIMIT = 7;
    private static final int OFF_SRC = 8;
    private static final int OFF_DST = 24;

    private Ipv6Header() {
    }

    /**
     * Builds a header. Traffic class and flow label are left zero.
     *
     * @param hopLimit MUST be {@value #HOP_LIMIT_NEIGHBOR_DISCOVERY} when the
     *                 payload is an NS or NA
     */
    public static byte[] build(byte[] src16, byte[] dst16, int nextHeader,
                               int hopLimit, int payloadLength) {
        requireAddress(src16, "src16");
        requireAddress(dst16, "dst16");
        if (payloadLength < 0 || payloadLength > 0xFFFF) {
            throw new IllegalArgumentException("payloadLength out of range: " + payloadLength);
        }
        if (hopLimit < 0 || hopLimit > 255) {
            throw new IllegalArgumentException("hopLimit out of range: " + hopLimit);
        }
        byte[] h = new byte[LENGTH];
        h[0] = (byte) (VERSION_6 << 4);
        h[OFF_PAYLOAD_LENGTH] = (byte) (payloadLength >>> 8);
        h[OFF_PAYLOAD_LENGTH + 1] = (byte) payloadLength;
        h[OFF_NEXT_HEADER] = (byte) nextHeader;
        h[OFF_HOP_LIMIT] = (byte) hopLimit;
        System.arraycopy(src16, 0, h, OFF_SRC, 16);
        System.arraycopy(dst16, 0, h, OFF_DST, 16);
        return h;
    }

    /**
     * Builds a header for an NS or NA, with the hop limit fixed at 255 so a caller
     * cannot get it wrong.
     */
    public static byte[] forNeighborDiscovery(byte[] src16, byte[] dst16, int payloadLength) {
        return build(src16, dst16, NEXT_HEADER_ICMPV6,
                     HOP_LIMIT_NEIGHBOR_DISCOVERY, payloadLength);
    }

    /**
     * @return empty when the buffer is too short or the version nibble is not 6
     */
    public static Optional<View> parse(byte[] pkt, int off, int len) {
        if (pkt == null || len < LENGTH || off < 0 || off + len > pkt.length) {
            return Optional.empty();
        }
        if (((pkt[off] & 0xFF) >>> 4) != VERSION_6) {
            return Optional.empty();
        }
        return Optional.of(new View(
                Arrays.copyOfRange(pkt, off + OFF_SRC, off + OFF_SRC + 16),
                Arrays.copyOfRange(pkt, off + OFF_DST, off + OFF_DST + 16),
                pkt[off + OFF_NEXT_HEADER] & 0xFF,
                pkt[off + OFF_HOP_LIMIT] & 0xFF,
                ((pkt[off + OFF_PAYLOAD_LENGTH] & 0xFF) << 8)
                        | (pkt[off + OFF_PAYLOAD_LENGTH + 1] & 0xFF)));
    }

    /**
     * The RFC 4861 §7.1.1 on-link check: an ICMPv6 packet is acceptable as
     * Neighbor Discovery only when its hop limit is exactly 255. Anything else has
     * crossed a router and must be discarded, whatever it claims to be.
     */
    public static boolean isValidNeighborDiscovery(View header) {
        return header != null
                && header.nextHeader() == NEXT_HEADER_ICMPV6
                && header.hopLimit() == HOP_LIMIT_NEIGHBOR_DISCOVERY;
    }

    /** A parsed header. Carries arrays, so not value-comparable. */
    public record View(byte[] src16, byte[] dst16, int nextHeader,
                       int hopLimit, int payloadLength) {
    }

    private static void requireAddress(byte[] a, String name) {
        if (a == null || a.length != 16) {
            throw new IllegalArgumentException(
                    name + " must be 16 bytes, got " + (a == null ? "null" : a.length));
        }
    }
}
