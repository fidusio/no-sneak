package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ARP build/parse round-trips, wire-layout checks, and gratuitous classification. */
public class ArpPacketTest {

    private static final MacAddress OUR_MAC = MacAddress.parse("aa:bb:cc:dd:ee:ff");
    private static final MacAddress THEIR_MAC = MacAddress.parse("11:22:33:44:55:66");
    private static final byte[] OUR_IP = {(byte) 192, (byte) 168, 1, 10};
    private static final byte[] THEIR_IP = {(byte) 192, (byte) 168, 1, 20};

    @Test
    public void requestIsExactly28Bytes() {
        assertEquals(ArpPacket.LENGTH, ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP).length);
    }

    /** Field-by-field against the RFC 826 layout, so an offset slip cannot hide. */
    @Test
    public void requestMatchesWireLayout() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);
        assertEquals("0001", HexFormat.of().formatHex(p, 0, 2), "htype");
        assertEquals("0800", HexFormat.of().formatHex(p, 2, 4), "ptype");
        assertEquals(6, p[4], "hlen");
        assertEquals(4, p[5], "plen");
        assertEquals("0001", HexFormat.of().formatHex(p, 6, 8), "oper=request");
        assertArrayEquals(OUR_MAC.bytes(), Arrays.copyOfRange(p, 8, 14), "sha");
        assertArrayEquals(OUR_IP, Arrays.copyOfRange(p, 14, 18), "spa");
        assertArrayEquals(new byte[6], Arrays.copyOfRange(p, 18, 24), "tha must be zero");
        assertArrayEquals(THEIR_IP, Arrays.copyOfRange(p, 24, 28), "tpa");
    }

    @Test
    public void requestRoundTrips() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);
        ArpPacket.ArpView v = ArpPacket.parse(p, 0, p.length).orElseThrow();

        assertTrue(v.isRequest());
        assertFalse(v.isReply());
        assertEquals(OUR_MAC, v.sha());
        assertArrayEquals(OUR_IP, v.spa());
        assertTrue(v.tha().isZero());
        assertArrayEquals(THEIR_IP, v.tpa());
        assertFalse(v.isGratuitous());
    }

    @Test
    public void replyRoundTrips() {
        byte[] p = ArpPacket.reply(THEIR_MAC, THEIR_IP, OUR_MAC, OUR_IP);
        ArpPacket.ArpView v = ArpPacket.parse(p, 0, p.length).orElseThrow();

        assertTrue(v.isReply());
        assertEquals(ArpPacket.OPER_REPLY, v.oper());
        assertEquals(THEIR_MAC, v.sha());
        assertArrayEquals(THEIR_IP, v.spa());
        assertEquals(OUR_MAC, v.tha());
        assertFalse(v.isGratuitous());
    }

    /**
     * A gratuitous ARP has SPA == TPA. That test takes priority over the
     * request/reply distinction, so it must hold for BOTH operations — a
     * classifier that only checks replies would miss the announcement form.
     */
    @Test
    public void gratuitousIsDetectedForBothOperations() {
        byte[] asRequest = ArpPacket.request(OUR_MAC, OUR_IP, OUR_IP);
        assertTrue(ArpPacket.parse(asRequest, 0, asRequest.length).orElseThrow().isGratuitous());

        byte[] asReply = ArpPacket.reply(OUR_MAC, OUR_IP, MacAddress.BROADCAST, OUR_IP);
        ArpPacket.ArpView v = ArpPacket.parse(asReply, 0, asReply.length).orElseThrow();
        assertTrue(v.isGratuitous());
        assertTrue(v.isReply(), "still a reply by operation, but gratuitous wins for classification");
    }

    @Test
    public void parseHonoursOffset() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);
        byte[] framed = new byte[14 + p.length];
        System.arraycopy(p, 0, framed, 14, p.length);

        assertTrue(ArpPacket.parse(framed, 14, p.length).isPresent());
        assertEquals(Optional.empty(), ArpPacket.parse(framed, 0, framed.length),
                     "reading from the Ethernet header must not parse as ARP");
    }

    @Test
    public void parseRejectsShortFrame() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);
        assertEquals(Optional.empty(), ArpPacket.parse(p, 0, ArpPacket.LENGTH - 1));
    }

    @Test
    public void parseRejectsNonEthernetOrNonIpv4() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);

        byte[] badHtype = p.clone();
        badHtype[1] = 0x06;
        assertEquals(Optional.empty(), ArpPacket.parse(badHtype, 0, badHtype.length));

        byte[] badPtype = p.clone();
        badPtype[3] = (byte) 0xDD;
        assertEquals(Optional.empty(), ArpPacket.parse(badPtype, 0, badPtype.length));

        byte[] badHlen = p.clone();
        badHlen[4] = 8;
        assertEquals(Optional.empty(), ArpPacket.parse(badHlen, 0, badHlen.length));
    }

    @Test
    public void parseRejectsNull() {
        assertEquals(Optional.empty(), ArpPacket.parse(null, 0, 28));
    }

    @Test
    public void buildRejectsBadArguments() {
        assertThrows(IllegalArgumentException.class,
                     () -> ArpPacket.request(null, OUR_IP, THEIR_IP));
        assertThrows(IllegalArgumentException.class,
                     () -> ArpPacket.request(OUR_MAC, new byte[3], THEIR_IP));
        assertThrows(IllegalArgumentException.class,
                     () -> ArpPacket.request(OUR_MAC, OUR_IP, null));
    }

    /** Longer buffers are tolerated: Ethernet pads short frames to 60 bytes. */
    @Test
    public void parseToleratesTrailingPadding() {
        byte[] p = ArpPacket.request(OUR_MAC, OUR_IP, THEIR_IP);
        byte[] padded = Arrays.copyOf(p, 46);
        ArpPacket.ArpView v = ArpPacket.parse(padded, 0, padded.length).orElseThrow();
        assertArrayEquals(THEIR_IP, v.tpa());
    }
}
