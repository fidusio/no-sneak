package io.xlogistx.nosneak.net.codecs;

import java.util.Arrays;
import java.util.Optional;

/**
 * ICMPv4 echo request and reply, RFC 792. An 8-byte header followed by an opaque
 * payload.
 * <p>
 * We own both the identifier and the checksum on every path that uses this codec
 * — Linux {@code SOCK_RAW} and Windows pcap. The macOS datagram socket is the
 * exception: there the kernel rewrites the identifier and computes the checksum,
 * so correlation matches on sequence alone.
 */
public final class Icmp4Echo {

    public static final int HEADER_LENGTH = 8;

    public static final int TYPE_ECHO_REQUEST = 8;
    public static final int TYPE_ECHO_REPLY = 0;

    private static final int OFF_TYPE = 0;
    private static final int OFF_CODE = 1;
    private static final int OFF_CHECKSUM = 2;
    private static final int OFF_ID = 4;
    private static final int OFF_SEQ = 6;

    private Icmp4Echo() {
    }

    /** Builds an echo request with the checksum computed over header and payload. */
    public static byte[] request(int id, int seq, byte[] payload) {
        return build(TYPE_ECHO_REQUEST, id, seq, payload);
    }

    /** Builds an echo reply. Used by tests and by any responder-side simulation. */
    public static byte[] reply(int id, int seq, byte[] payload) {
        return build(TYPE_ECHO_REPLY, id, seq, payload);
    }

    private static byte[] build(int type, int id, int seq, byte[] payload) {
        byte[] body = payload == null ? new byte[0] : payload;
        byte[] p = new byte[HEADER_LENGTH + body.length];
        p[OFF_TYPE] = (byte) type;
        p[OFF_CODE] = 0;
        // checksum stays zero while it is being computed — RFC 1071 precondition
        putShort(p, OFF_ID, id & 0xFFFF);
        putShort(p, OFF_SEQ, seq & 0xFFFF);
        System.arraycopy(body, 0, p, HEADER_LENGTH, body.length);
        putShort(p, OFF_CHECKSUM, InternetChecksum.checksum(p, 0, p.length));
        return p;
    }

    /**
     * Parses an echo REPLY (type 0). Verifies the checksum and rejects the message
     * on a mismatch, so a corrupted packet can never be correlated to a pending
     * probe.
     *
     * @param pkt the ICMP message, with any IP header already stripped
     * @return empty when too short, not an echo reply, or the checksum is wrong
     */
    public static Optional<EchoView> parseReply(byte[] pkt, int off, int len) {
        return parse(pkt, off, len, TYPE_ECHO_REPLY);
    }

    /** Parses an echo REQUEST (type 8) — the pcap path captures its own sends. */
    public static Optional<EchoView> parseRequest(byte[] pkt, int off, int len) {
        return parse(pkt, off, len, TYPE_ECHO_REQUEST);
    }

    private static Optional<EchoView> parse(byte[] pkt, int off, int len, int expectedType) {
        if (pkt == null || len < HEADER_LENGTH || off < 0 || off + len > pkt.length) {
            return Optional.empty();
        }
        if ((pkt[off + OFF_TYPE] & 0xFF) != expectedType || (pkt[off + OFF_CODE] & 0xFF) != 0) {
            return Optional.empty();
        }
        if (!InternetChecksum.verify(pkt, off, len)) {
            return Optional.empty();
        }
        return Optional.of(new EchoView(
                getShort(pkt, off + OFF_ID),
                getShort(pkt, off + OFF_SEQ),
                Arrays.copyOfRange(pkt, off + HEADER_LENGTH, off + len)));
    }

    /**
     * A parsed echo message.
     * <p>
     * NOTE: carries an array, so it is not value-comparable.
     */
    public record EchoView(int id, int seq, byte[] payload) {
    }

    private static void putShort(byte[] b, int off, int value) {
        b[off] = (byte) (value >>> 8);
        b[off + 1] = (byte) value;
    }

    private static int getShort(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }
}
