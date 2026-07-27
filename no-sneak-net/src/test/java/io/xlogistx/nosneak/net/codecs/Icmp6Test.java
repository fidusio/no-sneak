package io.xlogistx.nosneak.net.codecs;

import io.xlogistx.nosneak.net.common.MacAddress;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ICMPv6 echo and Neighbor Discovery round-trips, plus the multicast derivations. */
public class Icmp6Test {

    private static byte[] addr(String literal) {
        return InetAddress.ofLiteral(literal).getAddress();
    }

    private static final byte[] SRC = addr("fe80::1");
    private static final byte[] TARGET = addr("fe80::2:3456:789a");
    private static final MacAddress OUR_MAC = MacAddress.parse("aa:bb:cc:dd:ee:ff");
    private static final MacAddress THEIR_MAC = MacAddress.parse("11:22:33:44:55:66");

    // ---- echo ----

    @Test
    public void echoRequestMatchesWireLayout() {
        byte[] p = Icmp6.echoRequest(SRC, TARGET, 0xABCD, 7, new byte[] {1, 2, 3, 4});
        assertEquals(Icmp6.TYPE_ECHO_REQUEST, p[0] & 0xFF);
        assertEquals(0, p[1] & 0xFF);
        assertEquals(0xABCD, ((p[4] & 0xFF) << 8) | (p[5] & 0xFF));
        assertEquals(7, ((p[6] & 0xFF) << 8) | (p[7] & 0xFF));
    }

    /** The checksum must satisfy the receiver's pseudo-header verification. */
    @Test
    public void echoRequestChecksumVerifies() {
        byte[] p = Icmp6.echoRequest(SRC, TARGET, 1, 1, new byte[] {9});
        assertEquals(0, InternetChecksum.icmpv6Checksum(SRC, TARGET, p, 0, p.length));
    }

    /**
     * The Linux raw path leaves the checksum zero because the kernel is required
     * to compute it. The two builders must otherwise produce identical bytes.
     */
    @Test
    public void unchecksummedVariantDiffersOnlyInTheChecksumField() {
        byte[] withCk = Icmp6.echoRequest(SRC, TARGET, 5, 6, new byte[] {7});
        byte[] without = Icmp6.echoRequestUnchecksummed(5, 6, new byte[] {7});

        assertEquals(0, without[2] & 0xFF);
        assertEquals(0, without[3] & 0xFF);
        assertFalse((withCk[2] & 0xFF) == 0 && (withCk[3] & 0xFF) == 0,
                    "the checksummed variant must actually set the field");

        byte[] zeroed = withCk.clone();
        zeroed[2] = 0;
        zeroed[3] = 0;
        assertArrayEquals(without, zeroed);
    }

    @Test
    public void echoReplyRoundTrips() {
        byte[] p = Icmp6.echoRequest(SRC, TARGET, 0x1234, 42, new byte[] {1, 2});
        p[0] = (byte) Icmp6.TYPE_ECHO_REPLY;

        Icmp6.EchoView v = Icmp6.parseEchoReply(p, 0, p.length).orElseThrow();
        assertEquals(0x1234, v.id());
        assertEquals(42, v.seq());
        assertArrayEquals(new byte[] {1, 2}, v.payload());
    }

    @Test
    public void parseEchoReplyRejectsRequest() {
        byte[] p = Icmp6.echoRequest(SRC, TARGET, 1, 1, new byte[0]);
        assertEquals(Optional.empty(), Icmp6.parseEchoReply(p, 0, p.length));
    }

    // ---- solicited-node derivations ----

    /**
     * RFC 4861: the solicited-node address is ff02::1:ff00:0/104 with the low 24
     * bits of the target appended.
     */
    @Test
    public void solicitedNodeMulticastVector() {
        // fe80::2:3456:789a is fe80:0000:0000:0000:0000:0002:3456:789a, so the
        // low 24 bits are the last three bytes: 56 78 9a.
        byte[] m = Icmp6.solicitedNodeMulticast(TARGET);
        assertEquals("ff0200000000000000000001ff56789a", HexFormat.of().formatHex(m));
        assertArrayEquals(addr("ff02::1:ff56:789a"), m);
    }

    /** The Ethernet mapping is 33:33 followed by the low 32 bits of the multicast address. */
    @Test
    public void solicitedNodeMacVector() {
        assertEquals(MacAddress.parse("33:33:ff:56:78:9a"), Icmp6.solicitedNodeMac(TARGET));
    }

    /** The generic multicast mapping, used for ff02::1 all-nodes. */
    @Test
    public void allNodesMulticastMac() {
        assertEquals(MacAddress.parse("33:33:00:00:00:01"), Icmp6.multicastMac(addr("ff02::1")));
    }

    /** Only the low 24 bits matter: two targets sharing them share a solicited-node address. */
    @Test
    public void solicitedNodeIgnoresHighBits() {
        assertArrayEquals(Icmp6.solicitedNodeMulticast(addr("fe80::1:2:3456:789a")),
                          Icmp6.solicitedNodeMulticast(addr("2001:db8::9:9:3456:789a")));
    }

    @Test
    public void derivationsRejectWrongLength() {
        assertThrows(IllegalArgumentException.class,
                     () -> Icmp6.solicitedNodeMulticast(new byte[4]));
        assertThrows(IllegalArgumentException.class, () -> Icmp6.solicitedNodeMac(null));
    }

    // ---- neighbor discovery ----

    @Test
    public void neighborSolicitationRoundTrips() {
        byte[] p = Icmp6.neighborSolicitation(SRC, TARGET, OUR_MAC);

        assertEquals(32, p.length, "24-byte message plus one 8-byte option");
        assertEquals(Icmp6.TYPE_NEIGHBOR_SOLICITATION, p[0] & 0xFF);
        assertEquals(0, p[4] | p[5] | p[6] | p[7], "reserved must be zero");
        assertEquals(Icmp6.OPTION_SOURCE_LINK_LAYER, p[24] & 0xFF);
        assertEquals(1, p[25] & 0xFF, "option length is in 8-byte units");

        Icmp6.NsView v = Icmp6.parseSolicitation(p, 0, p.length).orElseThrow();
        assertArrayEquals(TARGET, v.targetIp16());
        assertEquals(OUR_MAC, v.sourceMac());
    }

    /**
     * The solicitation checksum must be computed against the solicited-node
     * multicast destination it will actually be sent to — not against the target
     * address. Verifying with the right destination is the only way to catch a
     * builder that used the wrong one.
     */
    @Test
    public void solicitationChecksumUsesSolicitedNodeDestination() {
        byte[] p = Icmp6.neighborSolicitation(SRC, TARGET, OUR_MAC);
        byte[] dst = Icmp6.solicitedNodeMulticast(TARGET);

        assertEquals(0, InternetChecksum.icmpv6Checksum(SRC, dst, p, 0, p.length));
        assertFalse(InternetChecksum.icmpv6Checksum(SRC, TARGET, p, 0, p.length) == 0,
                    "must not have been checksummed against the target address");
    }

    @Test
    public void neighborAdvertisementRoundTrips() {
        byte[] p = Icmp6.neighborAdvertisement(TARGET, SRC, TARGET, THEIR_MAC,
                                               Icmp6.FLAG_SOLICITED | Icmp6.FLAG_OVERRIDE);
        Icmp6.NaView v = Icmp6.parseAdvertisement(p, 0, p.length).orElseThrow();

        assertArrayEquals(TARGET, v.targetIp16());
        assertEquals(THEIR_MAC, v.targetMac());
        assertTrue(v.isSolicited());
        assertTrue(v.isOverride());
        assertFalse(v.isRouter());
    }

    @Test
    public void advertisementFlagsDecodeIndependently() {
        byte[] router = Icmp6.neighborAdvertisement(TARGET, SRC, TARGET, THEIR_MAC,
                                                    Icmp6.FLAG_ROUTER);
        Icmp6.NaView v = Icmp6.parseAdvertisement(router, 0, router.length).orElseThrow();
        assertTrue(v.isRouter());
        assertFalse(v.isSolicited());
        assertFalse(v.isOverride());
    }

    /** The option is optional; its absence must yield a null MAC, not an exception. */
    @Test
    public void advertisementWithoutLinkLayerOption() {
        byte[] full = Icmp6.neighborAdvertisement(TARGET, SRC, TARGET, THEIR_MAC,
                                                  Icmp6.FLAG_SOLICITED);
        byte[] bare = Arrays.copyOf(full, 24);

        Icmp6.NaView v = Icmp6.parseAdvertisement(bare, 0, bare.length).orElseThrow();
        assertArrayEquals(TARGET, v.targetIp16());
        assertNull(v.targetMac());
    }

    /**
     * A zero option length would advance the walk by nothing and spin forever.
     * Malformed input must terminate, not hang.
     */
    @Test
    public void zeroLengthOptionDoesNotLoopForever() {
        byte[] p = Icmp6.neighborAdvertisement(TARGET, SRC, TARGET, THEIR_MAC, 0);
        p[25] = 0;
        Icmp6.NaView v = Icmp6.parseAdvertisement(p, 0, p.length).orElseThrow();
        assertNull(v.targetMac());
    }

    /** An option claiming more bytes than are present must not read past the end. */
    @Test
    public void overlongOptionIsRejected() {
        byte[] p = Icmp6.neighborAdvertisement(TARGET, SRC, TARGET, THEIR_MAC, 0);
        p[25] = 9;
        assertNull(Icmp6.parseAdvertisement(p, 0, p.length).orElseThrow().targetMac());
    }

    @Test
    public void parsersRejectWrongTypeAndShortBuffers() {
        byte[] ns = Icmp6.neighborSolicitation(SRC, TARGET, OUR_MAC);
        assertEquals(Optional.empty(), Icmp6.parseAdvertisement(ns, 0, ns.length));
        assertEquals(Optional.empty(), Icmp6.parseSolicitation(ns, 0, 23));
        assertEquals(Optional.empty(), Icmp6.parseSolicitation(null, 0, 32));
    }

    @Test
    public void buildersRejectBadArguments() {
        assertThrows(IllegalArgumentException.class,
                     () -> Icmp6.neighborSolicitation(new byte[4], TARGET, OUR_MAC));
        assertThrows(IllegalArgumentException.class,
                     () -> Icmp6.neighborSolicitation(SRC, TARGET, null));
    }
}
