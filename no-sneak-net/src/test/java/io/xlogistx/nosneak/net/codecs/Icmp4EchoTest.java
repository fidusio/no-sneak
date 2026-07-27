package io.xlogistx.nosneak.net.codecs;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ICMPv4 echo build/parse round-trips and wire-layout checks. */
public class Icmp4EchoTest {

    private static final byte[] PAYLOAD = "no-sneak".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void requestMatchesWireLayout() {
        byte[] p = Icmp4Echo.request(0xABCD, 7, PAYLOAD);

        assertEquals(Icmp4Echo.HEADER_LENGTH + PAYLOAD.length, p.length);
        assertEquals(Icmp4Echo.TYPE_ECHO_REQUEST, p[0] & 0xFF, "type");
        assertEquals(0, p[1] & 0xFF, "code");
        assertEquals(0xAB, p[4] & 0xFF, "id high");
        assertEquals(0xCD, p[5] & 0xFF, "id low");
        assertEquals(0x00, p[6] & 0xFF, "seq high");
        assertEquals(0x07, p[7] & 0xFF, "seq low");
        assertArrayEquals(PAYLOAD, java.util.Arrays.copyOfRange(p, 8, p.length));
    }

    /** The built checksum must be correct by the receiver's own test. */
    @Test
    public void requestCarriesValidChecksum() {
        byte[] p = Icmp4Echo.request(0x1234, 1, PAYLOAD);
        assertTrue(InternetChecksum.verify(p, 0, p.length));
    }

    @Test
    public void replyRoundTrips() {
        byte[] p = Icmp4Echo.reply(0x1234, 42, PAYLOAD);
        Icmp4Echo.EchoView v = Icmp4Echo.parseReply(p, 0, p.length).orElseThrow();

        assertEquals(0x1234, v.id());
        assertEquals(42, v.seq());
        assertArrayEquals(PAYLOAD, v.payload());
    }

    @Test
    public void requestRoundTrips() {
        byte[] p = Icmp4Echo.request(0x00FF, 65535, PAYLOAD);
        Icmp4Echo.EchoView v = Icmp4Echo.parseRequest(p, 0, p.length).orElseThrow();

        assertEquals(0x00FF, v.id());
        assertEquals(65535, v.seq(), "sequence must survive the top of the 16-bit range");
    }

    /** Identifier and sequence are unsigned 16-bit; values above 0x7FFF must not sign-extend. */
    @Test
    public void handlesHighBitIdentifierAndSequence() {
        byte[] p = Icmp4Echo.request(0xFFFF, 0xFFFE, PAYLOAD);
        Icmp4Echo.EchoView v = Icmp4Echo.parseRequest(p, 0, p.length).orElseThrow();
        assertEquals(0xFFFF, v.id());
        assertEquals(0xFFFE, v.seq());
    }

    @Test
    public void inputIsMaskedTo16Bits() {
        byte[] wide = Icmp4Echo.request(0x1ABCD, 0x10007, PAYLOAD);
        byte[] narrow = Icmp4Echo.request(0xABCD, 7, PAYLOAD);
        assertArrayEquals(narrow, wide);
    }

    /** A reply parser must not accept a request, or correlation would match our own sends. */
    @Test
    public void parseReplyRejectsRequestType() {
        byte[] req = Icmp4Echo.request(1, 1, PAYLOAD);
        assertEquals(Optional.empty(), Icmp4Echo.parseReply(req, 0, req.length));
    }

    /** A corrupted reply must never reach the correlation map. */
    @Test
    public void parseRejectsBadChecksum() {
        byte[] p = Icmp4Echo.reply(0x1234, 1, PAYLOAD);
        p[p.length - 1] ^= 0xFF;
        assertEquals(Optional.empty(), Icmp4Echo.parseReply(p, 0, p.length));
    }

    @Test
    public void parseRejectsShortBuffer() {
        byte[] p = Icmp4Echo.reply(1, 1, PAYLOAD);
        assertEquals(Optional.empty(), Icmp4Echo.parseReply(p, 0, 7));
    }

    @Test
    public void parseRejectsNull() {
        assertEquals(Optional.empty(), Icmp4Echo.parseReply(null, 0, 8));
    }

    /**
     * On Linux SOCK_RAW the IPv4 header arrives ahead of the ICMP message, so the
     * parser must work from an offset.
     */
    @Test
    public void parseHonoursOffsetPastAnIpHeader() {
        byte[] icmp = Icmp4Echo.reply(0x2222, 3, PAYLOAD);
        byte[] framed = new byte[20 + icmp.length];
        System.arraycopy(icmp, 0, framed, 20, icmp.length);

        Icmp4Echo.EchoView v = Icmp4Echo.parseReply(framed, 20, icmp.length).orElseThrow();
        assertEquals(0x2222, v.id());
        assertEquals(3, v.seq());
    }

    @Test
    public void emptyPayloadIsLegal() {
        byte[] p = Icmp4Echo.request(1, 1, null);
        assertEquals(Icmp4Echo.HEADER_LENGTH, p.length);
        assertTrue(InternetChecksum.verify(p, 0, p.length));

        byte[] reply = Icmp4Echo.reply(1, 1, new byte[0]);
        assertEquals(0, Icmp4Echo.parseReply(reply, 0, reply.length).orElseThrow().payload().length);
    }

    /** An odd-length payload exercises the checksum's trailing-byte pad. */
    @Test
    public void oddLengthPayloadChecksums() {
        byte[] p = Icmp4Echo.request(9, 9, new byte[] {1, 2, 3});
        assertEquals(11, p.length);
        assertTrue(InternetChecksum.verify(p, 0, p.length));
    }
}
