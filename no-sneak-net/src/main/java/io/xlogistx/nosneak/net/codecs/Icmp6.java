package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;

import java.util.Arrays;
import java.util.Optional;

/**
 * ICMPv6 echo (RFC 4443) and Neighbor Discovery solicitation/advertisement
 * (RFC 4861).
 * <p>
 * Unlike ICMPv4, the checksum covers an IPv6 pseudo-header, so every builder here
 * needs the source and destination addresses even though neither appears in the
 * message. The one exception is Linux {@code SOCK_RAW}/{@code IPPROTO_ICMPV6},
 * where the kernel computes the checksum itself and computing it here as well is
 * wasted work — use {@link #echoRequestUnchecksummed} on that path.
 * <p>
 * NS and NA carry a hop-limit-255 requirement that lives in the IPv6 header, not
 * here; see {@link Ipv6Header}.
 */
public final class Icmp6 {

    public static final int HEADER_LENGTH = 8;

    public static final int TYPE_ECHO_REQUEST = 128;
    public static final int TYPE_ECHO_REPLY = 129;
    public static final int TYPE_NEIGHBOR_SOLICITATION = 135;
    public static final int TYPE_NEIGHBOR_ADVERTISEMENT = 136;

    /** Option type 1: Source Link-Layer Address. */
    public static final int OPTION_SOURCE_LINK_LAYER = 1;
    /** Option type 2: Target Link-Layer Address. */
    public static final int OPTION_TARGET_LINK_LAYER = 2;

    /** Router flag in the advertisement flag byte. */
    public static final int FLAG_ROUTER = 0x80;
    /** Solicited flag — prefer advertisements carrying it when several match. */
    public static final int FLAG_SOLICITED = 0x40;
    /** Override flag. */
    public static final int FLAG_OVERRIDE = 0x20;

    /** An NS or NA is 24 bytes of message plus an 8-byte link-layer option. */
    private static final int ND_MESSAGE_LENGTH = 24;
    private static final int ND_OPTION_LENGTH = 8;

    private static final int OFF_TYPE = 0;
    private static final int OFF_CODE = 1;
    private static final int OFF_CHECKSUM = 2;
    private static final int OFF_ECHO_ID = 4;
    private static final int OFF_ECHO_SEQ = 6;
    private static final int OFF_ND_FLAGS = 4;
    private static final int OFF_ND_TARGET = 8;

    private Icmp6() {
    }

    /** Echo request with the pseudo-header checksum computed. */
    public static byte[] echoRequest(byte[] src16, byte[] dst16, int id, int seq, byte[] payload) {
        byte[] p = echoRequestUnchecksummed(id, seq, payload);
        putShort(p, OFF_CHECKSUM, InternetChecksum.icmpv6Checksum(src16, dst16, p, 0, p.length));
        return p;
    }

    /**
     * Echo request with the checksum left ZERO, for Linux
     * {@code SOCK_RAW}/{@code IPPROTO_ICMPV6} where the kernel is required to
     * compute it (RFC 3542). Computing it here too would be redundant work that
     * the kernel overwrites.
     */
    public static byte[] echoRequestUnchecksummed(int id, int seq, byte[] payload) {
        byte[] body = payload == null ? new byte[0] : payload;
        byte[] p = new byte[HEADER_LENGTH + body.length];
        p[OFF_TYPE] = (byte) TYPE_ECHO_REQUEST;
        p[OFF_CODE] = 0;
        putShort(p, OFF_ECHO_ID, id & 0xFFFF);
        putShort(p, OFF_ECHO_SEQ, seq & 0xFFFF);
        System.arraycopy(body, 0, p, HEADER_LENGTH, body.length);
        return p;
    }

    /**
     * Builds a Neighbor Solicitation for {@code targetIp16}, carrying our own MAC
     * as the Source Link-Layer Address option.
     * <p>
     * The destination is always the solicited-node multicast address derived from
     * the target, so it is computed here rather than taken as a parameter — that
     * keeps the checksum and the destination from ever disagreeing.
     */
    public static byte[] neighborSolicitation(byte[] src16, byte[] targetIp16, MacAddress srcMac) {
        requireAddress(src16, "src16");
        requireAddress(targetIp16, "targetIp16");
        if (srcMac == null) {
            throw new IllegalArgumentException("srcMac is null");
        }
        byte[] p = new byte[ND_MESSAGE_LENGTH + ND_OPTION_LENGTH];
        p[OFF_TYPE] = (byte) TYPE_NEIGHBOR_SOLICITATION;
        p[OFF_CODE] = 0;
        // bytes 4..7 reserved, stay zero
        System.arraycopy(targetIp16, 0, p, OFF_ND_TARGET, 16);
        p[ND_MESSAGE_LENGTH] = (byte) OPTION_SOURCE_LINK_LAYER;
        p[ND_MESSAGE_LENGTH + 1] = 1; // length in units of 8 bytes
        System.arraycopy(srcMac.bytes(), 0, p, ND_MESSAGE_LENGTH + 2, 6);

        byte[] dst = solicitedNodeMulticast(targetIp16);
        putShort(p, OFF_CHECKSUM, InternetChecksum.icmpv6Checksum(src16, dst, p, 0, p.length));
        return p;
    }

    /** Builds a Neighbor Advertisement — used by tests and responder simulations. */
    public static byte[] neighborAdvertisement(byte[] src16, byte[] dst16, byte[] targetIp16,
                                               MacAddress targetMac, int flags) {
        requireAddress(targetIp16, "targetIp16");
        if (targetMac == null) {
            throw new IllegalArgumentException("targetMac is null");
        }
        byte[] p = new byte[ND_MESSAGE_LENGTH + ND_OPTION_LENGTH];
        p[OFF_TYPE] = (byte) TYPE_NEIGHBOR_ADVERTISEMENT;
        p[OFF_CODE] = 0;
        p[OFF_ND_FLAGS] = (byte) (flags & 0xE0);
        System.arraycopy(targetIp16, 0, p, OFF_ND_TARGET, 16);
        p[ND_MESSAGE_LENGTH] = (byte) OPTION_TARGET_LINK_LAYER;
        p[ND_MESSAGE_LENGTH + 1] = 1;
        System.arraycopy(targetMac.bytes(), 0, p, ND_MESSAGE_LENGTH + 2, 6);

        putShort(p, OFF_CHECKSUM, InternetChecksum.icmpv6Checksum(src16, dst16, p, 0, p.length));
        return p;
    }

    /**
     * The solicited-node multicast address for a target:
     * {@code ff02::1:ffXX:XXXX}, where the low 24 bits come from the target.
     */
    public static byte[] solicitedNodeMulticast(byte[] targetIp16) {
        requireAddress(targetIp16, "targetIp16");
        byte[] a = new byte[16];
        a[0] = (byte) 0xFF;
        a[1] = 0x02;
        a[11] = 0x01;
        a[12] = (byte) 0xFF;
        a[13] = targetIp16[13];
        a[14] = targetIp16[14];
        a[15] = targetIp16[15];
        return a;
    }

    /**
     * The Ethernet destination for a solicited-node multicast:
     * {@code 33:33:ff:XX:XX:XX}, being {@code 33:33} followed by the low 32 bits
     * of the multicast address.
     */
    public static MacAddress solicitedNodeMac(byte[] targetIp16) {
        requireAddress(targetIp16, "targetIp16");
        return new MacAddress(new byte[] {
                0x33, 0x33, (byte) 0xFF, targetIp16[13], targetIp16[14], targetIp16[15]});
    }

    /** The Ethernet destination for any IPv6 multicast address: {@code 33:33} + low 32 bits. */
    public static MacAddress multicastMac(byte[] dst16) {
        requireAddress(dst16, "dst16");
        return new MacAddress(new byte[] {
                0x33, 0x33, dst16[12], dst16[13], dst16[14], dst16[15]});
    }

    /** Parses an echo reply (type 129). Does not verify the checksum — see the class note. */
    public static Optional<EchoView> parseEchoReply(byte[] pkt, int off, int len) {
        if (!headerPresent(pkt, off, len, HEADER_LENGTH, TYPE_ECHO_REPLY)) {
            return Optional.empty();
        }
        return Optional.of(new EchoView(
                getShort(pkt, off + OFF_ECHO_ID),
                getShort(pkt, off + OFF_ECHO_SEQ),
                Arrays.copyOfRange(pkt, off + HEADER_LENGTH, off + len)));
    }

    /** Parses a Neighbor Solicitation (type 135). */
    public static Optional<NsView> parseSolicitation(byte[] pkt, int off, int len) {
        if (!headerPresent(pkt, off, len, ND_MESSAGE_LENGTH, TYPE_NEIGHBOR_SOLICITATION)) {
            return Optional.empty();
        }
        byte[] target = Arrays.copyOfRange(pkt, off + OFF_ND_TARGET, off + OFF_ND_TARGET + 16);
        MacAddress mac = findLinkLayerOption(pkt, off, len, OPTION_SOURCE_LINK_LAYER);
        return Optional.of(new NsView(target, mac));
    }

    /**
     * Parses a Neighbor Advertisement (type 136).
     * <p>
     * The Target Link-Layer Address option may legitimately be absent, in which
     * case {@link NaView#targetMac()} is null and the advertisement carries no new
     * L2 information.
     */
    public static Optional<NaView> parseAdvertisement(byte[] pkt, int off, int len) {
        if (!headerPresent(pkt, off, len, ND_MESSAGE_LENGTH, TYPE_NEIGHBOR_ADVERTISEMENT)) {
            return Optional.empty();
        }
        byte[] target = Arrays.copyOfRange(pkt, off + OFF_ND_TARGET, off + OFF_ND_TARGET + 16);
        MacAddress mac = findLinkLayerOption(pkt, off, len, OPTION_TARGET_LINK_LAYER);
        return Optional.of(new NaView(target, mac, pkt[off + OFF_ND_FLAGS] & 0xFF));
    }

    /** A parsed echo message. Carries an array, so not value-comparable. */
    public record EchoView(int id, int seq, byte[] payload) {
    }

    /** A parsed Neighbor Solicitation. Carries an array, so not value-comparable. */
    public record NsView(byte[] targetIp16, MacAddress sourceMac) {
    }

    /**
     * A parsed Neighbor Advertisement. Carries an array, so not value-comparable.
     *
     * @param targetMac null when the advertisement carried no link-layer option
     */
    public record NaView(byte[] targetIp16, MacAddress targetMac, int flags) {

        public boolean isSolicited() {
            return (flags & FLAG_SOLICITED) != 0;
        }

        public boolean isRouter() {
            return (flags & FLAG_ROUTER) != 0;
        }

        public boolean isOverride() {
            return (flags & FLAG_OVERRIDE) != 0;
        }
    }

    /**
     * Walks the option list looking for a link-layer address of the given type.
     * Options are type-length-value with length counted in 8-byte units; a zero
     * length is illegal and would loop forever, so it terminates the walk.
     */
    private static MacAddress findLinkLayerOption(byte[] pkt, int off, int len, int wantType) {
        int i = off + ND_MESSAGE_LENGTH;
        int end = off + len;
        while (i + 2 <= end) {
            int type = pkt[i] & 0xFF;
            int units = pkt[i + 1] & 0xFF;
            if (units == 0) {
                return null;
            }
            int optionLength = units * 8;
            if (i + optionLength > end) {
                return null;
            }
            if (type == wantType && optionLength >= 8) {
                return new MacAddress(Arrays.copyOfRange(pkt, i + 2, i + 8));
            }
            i += optionLength;
        }
        return null;
    }

    private static boolean headerPresent(byte[] pkt, int off, int len, int minLen, int type) {
        return pkt != null
                && off >= 0
                && len >= minLen
                && off + len <= pkt.length
                && (pkt[off + OFF_TYPE] & 0xFF) == type
                && (pkt[off + OFF_CODE] & 0xFF) == 0;
    }

    private static void requireAddress(byte[] a, String name) {
        if (a == null || a.length != 16) {
            throw new IllegalArgumentException(
                    name + " must be 16 bytes, got " + (a == null ? "null" : a.length));
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
