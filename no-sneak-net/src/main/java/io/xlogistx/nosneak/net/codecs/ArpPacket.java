package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;

import java.util.Arrays;
import java.util.Optional;

/**
 * ARP request and reply, RFC 826. Fixed at {@value #LENGTH} bytes.
 * <p>
 * This is the ARP PAYLOAD only. On Linux the kernel prepends and strips the
 * Ethernet header for an {@code AF_PACKET}/{@code SOCK_DGRAM} socket, so nothing
 * here ever builds one; the Windows pcap path hand-builds its own frame around
 * this payload.
 */
public final class ArpPacket {

    /** An ARP payload is always exactly 28 bytes. */
    public static final int LENGTH = 28;

    public static final int HTYPE_ETHERNET = 0x0001;
    public static final int PTYPE_IPV4 = 0x0800;
    public static final int HLEN_ETHERNET = 6;
    public static final int PLEN_IPV4 = 4;

    public static final int OPER_REQUEST = 1;
    public static final int OPER_REPLY = 2;

    private static final int OFF_HTYPE = 0;
    private static final int OFF_PTYPE = 2;
    private static final int OFF_HLEN = 4;
    private static final int OFF_PLEN = 5;
    private static final int OFF_OPER = 6;
    private static final int OFF_SHA = 8;
    private static final int OFF_SPA = 14;
    private static final int OFF_THA = 18;
    private static final int OFF_TPA = 24;

    private ArpPacket() {
    }

    /**
     * Builds a "who has {@code targetIpv4}, tell {@code senderIpv4}" request. The
     * target hardware address is left all-zero, which is what makes it a query.
     */
    public static byte[] request(MacAddress senderMac, byte[] senderIpv4, byte[] targetIpv4) {
        return build(OPER_REQUEST, senderMac, senderIpv4, null, targetIpv4);
    }

    /** Builds a reply announcing that {@code senderMac} owns {@code senderIpv4}. */
    public static byte[] reply(MacAddress senderMac, byte[] senderIpv4,
                               MacAddress targetMac, byte[] targetIpv4) {
        return build(OPER_REPLY, senderMac, senderIpv4, targetMac, targetIpv4);
    }

    private static byte[] build(int oper, MacAddress senderMac, byte[] senderIpv4,
                                MacAddress targetMac, byte[] targetIpv4) {
        if (senderMac == null) {
            throw new IllegalArgumentException("senderMac is null");
        }
        requireIpv4(senderIpv4, "senderIpv4");
        requireIpv4(targetIpv4, "targetIpv4");

        byte[] p = new byte[LENGTH];
        putShort(p, OFF_HTYPE, HTYPE_ETHERNET);
        putShort(p, OFF_PTYPE, PTYPE_IPV4);
        p[OFF_HLEN] = HLEN_ETHERNET;
        p[OFF_PLEN] = PLEN_IPV4;
        putShort(p, OFF_OPER, oper);
        System.arraycopy(senderMac.bytes(), 0, p, OFF_SHA, 6);
        System.arraycopy(senderIpv4, 0, p, OFF_SPA, 4);
        if (targetMac != null) {
            System.arraycopy(targetMac.bytes(), 0, p, OFF_THA, 6);
        }
        System.arraycopy(targetIpv4, 0, p, OFF_TPA, 4);
        return p;
    }

    /**
     * Parses an ARP payload, rejecting anything that is not Ethernet-over-IPv4.
     *
     * @return empty when the frame is too short or the fixed fields do not match
     */
    public static Optional<ArpView> parse(byte[] frame, int off, int len) {
        if (frame == null || len < LENGTH || off < 0 || off + len > frame.length) {
            return Optional.empty();
        }
        if (getShort(frame, off + OFF_HTYPE) != HTYPE_ETHERNET
                || getShort(frame, off + OFF_PTYPE) != PTYPE_IPV4
                || (frame[off + OFF_HLEN] & 0xFF) != HLEN_ETHERNET
                || (frame[off + OFF_PLEN] & 0xFF) != PLEN_IPV4) {
            return Optional.empty();
        }
        return Optional.of(new ArpView(
                getShort(frame, off + OFF_OPER),
                new MacAddress(Arrays.copyOfRange(frame, off + OFF_SHA, off + OFF_SHA + 6)),
                Arrays.copyOfRange(frame, off + OFF_SPA, off + OFF_SPA + 4),
                new MacAddress(Arrays.copyOfRange(frame, off + OFF_THA, off + OFF_THA + 6)),
                Arrays.copyOfRange(frame, off + OFF_TPA, off + OFF_TPA + 4)));
    }

    /**
     * A parsed ARP payload.
     * <p>
     * NOTE: carries arrays, so the generated {@code equals} and {@code hashCode}
     * use reference identity. Not value-comparable; do not use as a map key.
     *
     * @param sha sender hardware address — authoritative for ARP, but worth
     *            comparing against the {@code sll_addr} the kernel reports, since a
     *            mismatch between frame header and payload is spoofing evidence
     */
    public record ArpView(int oper, MacAddress sha, byte[] spa, MacAddress tha, byte[] tpa) {

        /**
         * True when the sender and target protocol addresses are equal — a host
         * announcing itself.
         * <p>
         * This test takes PRIORITY over the request/reply distinction: a gratuitous
         * ARP may carry either operation, and must be classified as gratuitous
         * rather than as a reply.
         */
        public boolean isGratuitous() {
            return Arrays.equals(spa, tpa);
        }

        public boolean isRequest() {
            return oper == OPER_REQUEST;
        }

        public boolean isReply() {
            return oper == OPER_REPLY;
        }
    }

    private static void requireIpv4(byte[] a, String name) {
        if (a == null || a.length != PLEN_IPV4) {
            throw new IllegalArgumentException(
                    name + " must be 4 bytes, got " + (a == null ? "null" : a.length));
        }
    }

    private static void putShort(byte[] b, int off, int value) {
        b[off] = (byte) (value >>> 8);
        b[off + 1] = (byte) value;
    }

    private static int getShort(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }
}
