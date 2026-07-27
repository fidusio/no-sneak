package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two codecs the pcap path needs because injection at L2 means building the
 * whole packet: {@link EthernetFrame} and {@link Ipv4Header}.
 */
public class FrameCodecTest {

    private static final MacAddress DST = MacAddress.parse("11:22:33:44:55:66");
    private static final MacAddress SRC = MacAddress.parse("aa:bb:cc:dd:ee:ff");
    private static final byte[] IP_SRC = InetAddress.ofLiteral("10.0.0.61").getAddress();
    private static final byte[] IP_DST = InetAddress.ofLiteral("10.0.0.1").getAddress();

    // ---- Ethernet ----

    @Test
    public void ethernetRoundTrips() {
        byte[] payload = {1, 2, 3, 4};
        byte[] frame = EthernetFrame.build(DST, SRC, EthernetFrame.ETHERTYPE_ARP, payload);

        assertEquals(EthernetFrame.HEADER_LENGTH + payload.length, frame.length);
        EthernetFrame.View v = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();

        assertEquals(DST, v.dst());
        assertEquals(SRC, v.src());
        assertTrue(v.isArp());
        assertFalse(v.isTagged());
        assertEquals(EthernetFrame.HEADER_LENGTH, v.payloadOffset());
        assertEquals(payload.length, v.payloadLength());
        assertArrayEquals(payload,
                java.util.Arrays.copyOfRange(frame, v.payloadOffset(),
                        v.payloadOffset() + v.payloadLength()));
    }

    @Test
    public void ethertypeIsBigEndianOnTheWire() {
        byte[] frame = EthernetFrame.build(DST, SRC, EthernetFrame.ETHERTYPE_IPV6, new byte[0]);
        assertEquals(0x86, frame[12] & 0xFF);
        assertEquals(0xDD, frame[13] & 0xFF);
    }

    /**
     * An 802.1Q tag shifts every subsequent offset by four bytes. A parser that
     * ignored it would read the tag as the payload and mis-decode every frame on
     * a tagged segment.
     */
    @Test
    public void vlanTagIsUnwrappedAndShiftsThePayload() {
        byte[] inner = {9, 9, 9, 9};
        byte[] tagged = new byte[EthernetFrame.HEADER_LENGTH + 4 + inner.length];
        System.arraycopy(DST.bytes(), 0, tagged, 0, 6);
        System.arraycopy(SRC.bytes(), 0, tagged, 6, 6);
        tagged[12] = (byte) 0x81;
        tagged[13] = 0x00;
        tagged[14] = 0x00;
        tagged[15] = 0x64;                       // VLAN id 100
        tagged[16] = 0x08;
        tagged[17] = 0x06;                       // inner ethertype = ARP
        System.arraycopy(inner, 0, tagged, 18, inner.length);

        EthernetFrame.View v = EthernetFrame.parse(tagged, 0, tagged.length).orElseThrow();
        assertTrue(v.isTagged());
        assertEquals(100, v.vlanId());
        assertTrue(v.isArp(), "the INNER ethertype must be reported");
        assertEquals(18, v.payloadOffset(), "payload starts past the 4-byte tag");
        assertEquals(inner.length, v.payloadLength());
    }

    @Test
    public void ethernetParseRejectsShortAndNull() {
        assertEquals(Optional.empty(), EthernetFrame.parse(new byte[13], 0, 13));
        assertEquals(Optional.empty(), EthernetFrame.parse(null, 0, 14));
    }

    @Test
    public void ethernetBuildRejectsMissingMacs() {
        assertThrows(IllegalArgumentException.class,
                     () -> EthernetFrame.build(null, SRC, 0x0800, new byte[0]));
    }

    /** A whole ARP frame, the exact shape §8.4 sends. */
    @Test
    public void arpOverEthernetComposes() {
        byte[] arp = ArpPacket.request(SRC, IP_SRC, IP_DST);
        byte[] frame = EthernetFrame.build(MacAddress.BROADCAST, SRC,
                                           EthernetFrame.ETHERTYPE_ARP, arp);

        assertEquals(14 + 28, frame.length);
        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();
        assertTrue(eth.dst().isBroadcast());

        ArpPacket.ArpView view = ArpPacket.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                         .orElseThrow();
        assertArrayEquals(IP_DST, view.tpa());
    }

    // ---- IPv4 ----

    @Test
    public void ipv4RoundTrips() {
        byte[] h = Ipv4Header.forIcmp(IP_SRC, IP_DST, 0x1234, 40);
        assertEquals(Ipv4Header.LENGTH, h.length);

        Ipv4Header.View v = Ipv4Header.parse(h, 0, h.length).orElseThrow();
        assertArrayEquals(IP_SRC, v.src4());
        assertArrayEquals(IP_DST, v.dst4());
        assertTrue(v.isIcmp());
        assertEquals(Ipv4Header.DEFAULT_TTL, v.ttl());
        assertEquals(20, v.headerLength());
        assertEquals(60, v.totalLength(), "total length includes the header");
        assertEquals(40, v.payloadLength());
    }

    /** The header checksum must satisfy the receiver's own verification. */
    @Test
    public void headerChecksumVerifies() {
        byte[] h = Ipv4Header.forIcmp(IP_SRC, IP_DST, 1, 8);
        assertTrue(InternetChecksum.verify(h, 0, Ipv4Header.LENGTH));
    }

    /** A corrupted header must be rejected, not silently accepted. */
    @Test
    public void parseRejectsBadChecksum() {
        byte[] h = Ipv4Header.forIcmp(IP_SRC, IP_DST, 1, 8);
        h[8] ^= 0xFF;   // change the TTL without fixing the checksum
        assertEquals(Optional.empty(), Ipv4Header.parse(h, 0, h.length));
    }

    @Test
    public void ttlAtOffsetEight() {
        byte[] h = Ipv4Header.build(IP_SRC, IP_DST, Ipv4Header.PROTOCOL_ICMP, 42, 1, 0);
        assertEquals(42, h[8] & 0xFF, "TTL must sit at offset 8, where SOCK_RAW readers look");
    }

    @Test
    public void versionAndIhlNibbles() {
        byte[] h = Ipv4Header.forIcmp(IP_SRC, IP_DST, 1, 0);
        assertEquals(4, (h[0] & 0xFF) >>> 4, "version");
        assertEquals(5, h[0] & 0x0F, "IHL in 32-bit words");
    }

    @Test
    public void parseRejectsWrongVersionAndShortBuffer() {
        byte[] h = Ipv4Header.forIcmp(IP_SRC, IP_DST, 1, 0);
        assertEquals(Optional.empty(), Ipv4Header.parse(h, 0, 19));

        byte[] v6ish = h.clone();
        v6ish[0] = 0x60;
        assertEquals(Optional.empty(), Ipv4Header.parse(v6ish, 0, v6ish.length));
    }

    @Test
    public void buildRejectsOutOfRange() {
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv4Header.build(new byte[3], IP_DST, 1, 64, 0, 0));
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv4Header.build(IP_SRC, IP_DST, 1, 256, 0, 0));
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv4Header.build(IP_SRC, IP_DST, 1, 64, 0, 0x10000));
    }

    /** The whole crafted echo: Ethernet + IPv4 + ICMP, as §8.4 sends it. */
    @Test
    public void fullIcmpEchoFrameComposesAndParsesBack() {
        byte[] icmp = Icmp4Echo.request(0xABCD, 1, new byte[] {1, 2, 3, 4});
        byte[] ip = Ipv4Header.forIcmp(IP_SRC, IP_DST, 0x4242, icmp.length);

        byte[] payload = new byte[ip.length + icmp.length];
        System.arraycopy(ip, 0, payload, 0, ip.length);
        System.arraycopy(icmp, 0, payload, ip.length, icmp.length);
        byte[] frame = EthernetFrame.build(DST, SRC, EthernetFrame.ETHERTYPE_IPV4, payload);

        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();
        assertTrue(eth.isIpv4());

        Ipv4Header.View v4 = Ipv4Header.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                       .orElseThrow();
        assertTrue(v4.isIcmp());

        Icmp4Echo.EchoView echo = Icmp4Echo.parseRequest(
                frame, eth.payloadOffset() + v4.headerLength(), v4.payloadLength()).orElseThrow();
        assertEquals(0xABCD, echo.id());
        assertEquals(1, echo.seq());
        assertArrayEquals(new byte[] {1, 2, 3, 4}, echo.payload());
    }
}
