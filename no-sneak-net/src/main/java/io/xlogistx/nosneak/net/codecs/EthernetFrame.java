package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;

import java.util.Arrays;
import java.util.Optional;

/**
 * The Ethernet II header, and whole-frame assembly.
 * <p>
 * Only the pcap path needs this. On Linux the kernel prepends and strips the
 * header for an {@code AF_PACKET}/{@code SOCK_DGRAM} socket, so no Ethernet
 * header is ever hand-built there — pcap injects at L2 and builds nothing, so
 * everything sent through it is a complete frame.
 * <p>
 * 802.1Q is handled on PARSE but never on build: a tagged frame carries
 * ethertype {@code 0x8100} followed by four bytes of tag, which shifts every
 * subsequent offset. {@link View#payloadOffset()} accounts for that, so a parser
 * built on this cannot silently mis-read a tagged segment. Note the §8.4 BPF
 * filter does not match tagged frames in the first place unless prefixed with
 * {@code vlan}.
 */
public final class EthernetFrame {

    public static final int HEADER_LENGTH = 14;

    /** Extra bytes a single 802.1Q tag inserts. */
    public static final int VLAN_TAG_LENGTH = 4;

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_ARP = 0x0806;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_VLAN = 0x8100;

    /**
     * The shortest legal Ethernet payload. Frames below this are padded on the
     * wire, which is why parsers must trust the length field rather than the
     * buffer size.
     */
    public static final int MIN_PAYLOAD = 46;

    private EthernetFrame() {
    }

    /** Assembles a complete frame. The payload is NOT padded to {@link #MIN_PAYLOAD}. */
    public static byte[] build(MacAddress dst, MacAddress src, int ethertype, byte[] payload) {
        if (dst == null || src == null) {
            throw new IllegalArgumentException("dst and src MAC are required");
        }
        byte[] body = payload == null ? new byte[0] : payload;
        byte[] frame = new byte[HEADER_LENGTH + body.length];
        System.arraycopy(dst.bytes(), 0, frame, 0, 6);
        System.arraycopy(src.bytes(), 0, frame, 6, 6);
        frame[12] = (byte) (ethertype >>> 8);
        frame[13] = (byte) ethertype;
        System.arraycopy(body, 0, frame, HEADER_LENGTH, body.length);
        return frame;
    }

    /**
     * @return empty when the buffer is too short to hold a header
     */
    public static Optional<View> parse(byte[] frame, int off, int len) {
        if (frame == null || off < 0 || len < HEADER_LENGTH || off + len > frame.length) {
            return Optional.empty();
        }
        MacAddress dst = new MacAddress(Arrays.copyOfRange(frame, off, off + 6));
        MacAddress src = new MacAddress(Arrays.copyOfRange(frame, off + 6, off + 12));
        int ethertype = getShort(frame, off + 12);

        int payloadOffset = off + HEADER_LENGTH;
        int vlanId = -1;
        if (ethertype == ETHERTYPE_VLAN) {
            if (len < HEADER_LENGTH + VLAN_TAG_LENGTH) {
                return Optional.empty();
            }
            vlanId = getShort(frame, payloadOffset) & 0x0FFF;
            ethertype = getShort(frame, payloadOffset + 2);
            payloadOffset += VLAN_TAG_LENGTH;
        }
        return Optional.of(new View(dst, src, ethertype, payloadOffset,
                                    off + len - payloadOffset, vlanId));
    }

    /**
     * A parsed header.
     *
     * @param ethertype     the INNER ethertype when the frame was VLAN-tagged
     * @param payloadOffset absolute offset of the payload in the original buffer,
     *                      already past any 802.1Q tag
     * @param vlanId        the VLAN id, or {@code -1} when the frame was untagged
     */
    public record View(MacAddress dst, MacAddress src, int ethertype,
                       int payloadOffset, int payloadLength, int vlanId) {

        public boolean isTagged() {
            return vlanId >= 0;
        }

        public boolean isArp() {
            return ethertype == ETHERTYPE_ARP;
        }

        public boolean isIpv4() {
            return ethertype == ETHERTYPE_IPV4;
        }

        public boolean isIpv6() {
            return ethertype == ETHERTYPE_IPV6;
        }
    }

    private static int getShort(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }
}
