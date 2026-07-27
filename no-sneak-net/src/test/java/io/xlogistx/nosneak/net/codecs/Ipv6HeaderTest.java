package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IPv6 header round-trips, and the RFC 4861 hop-limit-255 rule in both its accept
 * and reject directions — the check whose absence would silently break all IPv6
 * resolution.
 */
public class Ipv6HeaderTest {

    private static byte[] addr(String literal) {
        return InetAddress.ofLiteral(literal).getAddress();
    }

    private static final byte[] SRC = addr("fe80::1");
    private static final byte[] DST = addr("fe80::2");

    @Test
    public void buildMatchesWireLayout() {
        byte[] h = Ipv6Header.build(SRC, DST, Ipv6Header.NEXT_HEADER_ICMPV6, 64, 0x1234);

        assertEquals(Ipv6Header.LENGTH, h.length);
        assertEquals(6, (h[0] & 0xFF) >>> 4, "version nibble");
        assertEquals(0x12, h[4] & 0xFF, "payload length high");
        assertEquals(0x34, h[5] & 0xFF, "payload length low");
        assertEquals(58, h[6] & 0xFF, "next header");
        assertEquals(64, h[7] & 0xFF, "hop limit");
        assertArrayEquals(SRC, java.util.Arrays.copyOfRange(h, 8, 24));
        assertArrayEquals(DST, java.util.Arrays.copyOfRange(h, 24, 40));
    }

    @Test
    public void roundTrips() {
        byte[] h = Ipv6Header.build(SRC, DST, 58, 255, 32);
        Ipv6Header.View v = Ipv6Header.parse(h, 0, h.length).orElseThrow();

        assertArrayEquals(SRC, v.src16());
        assertArrayEquals(DST, v.dst16());
        assertEquals(58, v.nextHeader());
        assertEquals(255, v.hopLimit());
        assertEquals(32, v.payloadLength());
    }

    /** The convenience builder must not be capable of producing a wrong hop limit. */
    @Test
    public void neighborDiscoveryBuilderPinsHopLimitTo255() {
        byte[] h = Ipv6Header.forNeighborDiscovery(SRC, DST, 32);
        Ipv6Header.View v = Ipv6Header.parse(h, 0, h.length).orElseThrow();

        assertEquals(255, v.hopLimit());
        assertEquals(Ipv6Header.NEXT_HEADER_ICMPV6, v.nextHeader());
        assertTrue(Ipv6Header.isValidNeighborDiscovery(v));
    }

    /** ACCEPT case: exactly 255 with next header 58. */
    @Test
    public void acceptsHopLimit255() {
        byte[] ns = Icmp6.neighborSolicitation(SRC, addr("fe80::2"),
                                               MacAddress.parse("aa:bb:cc:dd:ee:ff"));
        byte[] h = Ipv6Header.forNeighborDiscovery(SRC, Icmp6.solicitedNodeMulticast(addr("fe80::2")),
                                                   ns.length);
        assertTrue(Ipv6Header.isValidNeighborDiscovery(
                Ipv6Header.parse(h, 0, h.length).orElseThrow()));
    }

    /**
     * REJECT cases. Anything other than 255 has crossed a router and must be
     * discarded — 254 is the one that matters, since a single hop is exactly what
     * an off-link attacker produces.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 63, 64, 128, 254})
    public void rejectsAnyHopLimitOtherThan255(int hopLimit) {
        byte[] h = Ipv6Header.build(SRC, DST, Ipv6Header.NEXT_HEADER_ICMPV6, hopLimit, 32);
        assertFalse(Ipv6Header.isValidNeighborDiscovery(
                Ipv6Header.parse(h, 0, h.length).orElseThrow()));
    }

    /** A hop limit of 255 on a non-ICMPv6 payload is not Neighbor Discovery either. */
    @Test
    public void rejectsWrongNextHeaderEvenAt255() {
        byte[] h = Ipv6Header.build(SRC, DST, 17, 255, 32);
        assertFalse(Ipv6Header.isValidNeighborDiscovery(
                Ipv6Header.parse(h, 0, h.length).orElseThrow()));
    }

    @Test
    public void rejectsNullView() {
        assertFalse(Ipv6Header.isValidNeighborDiscovery(null));
    }

    @Test
    public void parseRejectsShortBufferAndWrongVersion() {
        byte[] h = Ipv6Header.build(SRC, DST, 58, 255, 0);
        assertEquals(Optional.empty(), Ipv6Header.parse(h, 0, Ipv6Header.LENGTH - 1));
        assertEquals(Optional.empty(), Ipv6Header.parse(null, 0, 40));

        byte[] v4ish = h.clone();
        v4ish[0] = 0x45;
        assertEquals(Optional.empty(), Ipv6Header.parse(v4ish, 0, v4ish.length));
    }

    @Test
    public void parseHonoursOffsetPastAnEthernetHeader() {
        byte[] h = Ipv6Header.build(SRC, DST, 58, 255, 8);
        byte[] framed = new byte[14 + h.length];
        System.arraycopy(h, 0, framed, 14, h.length);

        Ipv6Header.View v = Ipv6Header.parse(framed, 14, h.length).orElseThrow();
        assertEquals(255, v.hopLimit());
    }

    @Test
    public void buildRejectsOutOfRangeArguments() {
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv6Header.build(new byte[4], DST, 58, 255, 0));
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv6Header.build(SRC, DST, 58, 256, 0));
        assertThrows(IllegalArgumentException.class,
                     () -> Ipv6Header.build(SRC, DST, 58, 255, 0x10000));
    }
}
