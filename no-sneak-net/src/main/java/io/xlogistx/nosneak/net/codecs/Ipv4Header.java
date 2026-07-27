package io.xlogistx.nosneak.net.codecs;

import java.util.Arrays;
import java.util.Optional;

/**
 * The IPv4 header, RFC 791 — 20 bytes with no options.
 * <p>
 * Built only on the pcap path, which bypasses OS routing and so must produce the
 * whole packet. Where the kernel routes (Linux, macOS) it builds this itself.
 * <p>
 * The header carries its OWN checksum, covering the header alone — distinct from
 * the ICMP checksum over the message. Both are ours to compute when injecting at
 * L2, and getting either wrong means the far end drops the packet without a word.
 */
public final class Ipv4Header {

    public static final int LENGTH = 20;

    public static final int PROTOCOL_ICMP = 1;

    /** Matches the Linux/BSD convention, so a reply looks unremarkable. */
    public static final int DEFAULT_TTL = 64;

    private static final int VERSION_4 = 4;
    private static final int OFF_TOTAL_LENGTH = 2;
    private static final int OFF_IDENTIFICATION = 4;
    private static final int OFF_TTL = 8;
    private static final int OFF_PROTOCOL = 9;
    private static final int OFF_CHECKSUM = 10;
    private static final int OFF_SRC = 12;
    private static final int OFF_DST = 16;

    private Ipv4Header() {
    }

    /**
     * Builds a header with the header checksum computed.
     *
     * @param identification IP ID; only meaningful for fragment reassembly, but
     *                       some stacks and middleboxes dislike a constant zero
     * @param payloadLength  bytes following the header, NOT the total length
     */
    public static byte[] build(byte[] src4, byte[] dst4, int protocol, int ttl,
                               int identification, int payloadLength) {
        requireAddress(src4, "src4");
        requireAddress(dst4, "dst4");
        if (ttl < 0 || ttl > 255) {
            throw new IllegalArgumentException("ttl out of range: " + ttl);
        }
        int total = LENGTH + payloadLength;
        if (payloadLength < 0 || total > 0xFFFF) {
            throw new IllegalArgumentException("payloadLength out of range: " + payloadLength);
        }

        byte[] h = new byte[LENGTH];
        h[0] = (byte) ((VERSION_4 << 4) | (LENGTH / 4));
        h[1] = 0;                                   // DSCP/ECN
        h[OFF_TOTAL_LENGTH] = (byte) (total >>> 8);
        h[OFF_TOTAL_LENGTH + 1] = (byte) total;
        h[OFF_IDENTIFICATION] = (byte) (identification >>> 8);
        h[OFF_IDENTIFICATION + 1] = (byte) identification;
        h[6] = 0x40;                                // Don't Fragment
        h[7] = 0;
        h[OFF_TTL] = (byte) ttl;
        h[OFF_PROTOCOL] = (byte) protocol;
        // checksum stays zero while it is computed - RFC 1071 precondition
        System.arraycopy(src4, 0, h, OFF_SRC, 4);
        System.arraycopy(dst4, 0, h, OFF_DST, 4);

        int checksum = InternetChecksum.checksum(h, 0, LENGTH);
        h[OFF_CHECKSUM] = (byte) (checksum >>> 8);
        h[OFF_CHECKSUM + 1] = (byte) checksum;
        return h;
    }

    /** An ICMP-carrying header with the conventional TTL. */
    public static byte[] forIcmp(byte[] src4, byte[] dst4, int identification, int payloadLength) {
        return build(src4, dst4, PROTOCOL_ICMP, DEFAULT_TTL, identification, payloadLength);
    }

    /**
     * Parses a header, verifying its checksum.
     *
     * @return empty when too short, not version 4, the IHL is implausible, or the
     *         header checksum does not verify
     */
    public static Optional<View> parse(byte[] pkt, int off, int len) {
        if (pkt == null || off < 0 || len < LENGTH || off + len > pkt.length) {
            return Optional.empty();
        }
        int versionIhl = pkt[off] & 0xFF;
        if ((versionIhl >>> 4) != VERSION_4) {
            return Optional.empty();
        }
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < LENGTH || ihl > len) {
            return Optional.empty();
        }
        if (!InternetChecksum.verify(pkt, off, ihl)) {
            return Optional.empty();
        }
        return Optional.of(new View(
                Arrays.copyOfRange(pkt, off + OFF_SRC, off + OFF_SRC + 4),
                Arrays.copyOfRange(pkt, off + OFF_DST, off + OFF_DST + 4),
                pkt[off + OFF_PROTOCOL] & 0xFF,
                pkt[off + OFF_TTL] & 0xFF,
                ihl,
                ((pkt[off + OFF_TOTAL_LENGTH] & 0xFF) << 8)
                        | (pkt[off + OFF_TOTAL_LENGTH + 1] & 0xFF)));
    }

    /**
     * A parsed header. Carries arrays, so not value-comparable.
     *
     * @param headerLength IHL in BYTES — the payload starts here, and it is not
     *                     always 20: options are legal and do occur
     */
    public record View(byte[] src4, byte[] dst4, int protocol, int ttl,
                       int headerLength, int totalLength) {

        public boolean isIcmp() {
            return protocol == PROTOCOL_ICMP;
        }

        /** Payload length per the header's own total-length field. */
        public int payloadLength() {
            return Math.max(0, totalLength - headerLength);
        }
    }

    private static void requireAddress(byte[] a, String name) {
        if (a == null || a.length != 4) {
            throw new IllegalArgumentException(
                    name + " must be 4 bytes, got " + (a == null ? "null" : a.length));
        }
    }
}
