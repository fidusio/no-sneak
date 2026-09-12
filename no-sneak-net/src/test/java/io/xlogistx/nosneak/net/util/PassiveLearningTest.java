package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservationKind;
import io.xlogistx.nosneak.net.common.ResolveSource;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The guards on passive learning, and the provenance a sighting earns — one static for
 * every backend (§13.23).
 * <p>
 * These matter more than a missed sighting would: {@code resolve()} serves the
 * cache, so a wrongly-learned entry is REPORTED as a {@code CACHE_HIT} rather than
 * merely wasting a frame. The off-link case is the one that would do real damage —
 * a remote host's frames arrive bearing the router's MAC.
 */
public class PassiveLearningTest {

    private static final MacAddress SENDER = MacAddress.parse("94:e6:ba:4d:66:1b");
    private static final MacAddress OWN = MacAddress.parse("b0:7b:25:82:64:45");

    private static final InetAddress OWN_V4 = InetAddress.ofLiteral("10.0.0.61");
    private static final InetAddress OWN_LINK_LOCAL = InetAddress.ofLiteral("fe80::1c2b:3d4e:5f60:7182");
    private static final InetAddress OWN_GLOBAL = InetAddress.ofLiteral("2001:db8:1::61");

    /** Dual-stack: 10.0.0.61/24, fe80::…/64, 2001:db8:1::61/64. */
    private static final NicBinding BINDING = new NicBinding(
            "eth0", "eth0", 4, OWN,
            List.of(new NicBinding.LocalAddress(OWN_V4, 24)),
            List.of(new NicBinding.LocalAddress(OWN_LINK_LOCAL, 64),
                    new NicBinding.LocalAddress(OWN_GLOBAL, 64)),
            1500);

    /** The same interface with no IPv6 address at all. */
    private static final NicBinding BINDING_V4_ONLY = new NicBinding(
            "eth0", "eth0", 4, OWN,
            List.of(new NicBinding.LocalAddress(OWN_V4, 24)),
            List.of(), 1500);

    private static boolean learnable(String ip, MacAddress mac) {
        return PassiveLearning.learnable(BINDING, InetAddress.ofLiteral(ip), mac);
    }

    private static byte[] v4(String ip) {
        return InetAddress.ofLiteral(ip).getAddress();
    }

    // ---- the six original cases ----

    @Test
    public void anOnLinkSenderIsLearned() {
        assertTrue(learnable("10.0.0.108", SENDER));
        assertTrue(learnable("10.0.0.1", SENDER), "the gateway is a neighbour like any other");
    }

    /**
     * The one that would produce a WRONG answer rather than a missing one: an
     * off-link source's frames carry the router's MAC, so learning them would claim
     * a remote host lives at the gateway's address.
     */
    @Test
    public void anOffLinkSenderIsNeverLearned() {
        assertFalse(learnable("8.8.8.8", SENDER));
        assertFalse(learnable("10.0.1.5", SENDER), "outside the /24 is outside the segment");
    }

    @Test
    public void ourOwnAddressIsNotANeighbour() {
        assertFalse(learnable("10.0.0.61", SENDER));
    }

    @Test
    public void addressesThatBelongToNobodyAreSkipped() {
        assertFalse(learnable("0.0.0.0", SENDER), "a DHCP discover has no source address yet");
        assertFalse(learnable("224.0.0.251", SENDER), "mDNS is a group, not a host");
    }

    /** A sent frame can never legitimately carry these as its SOURCE address. */
    @Test
    public void unusableSourceMacsAreSkipped() {
        assertFalse(learnable("10.0.0.108", MacAddress.parse("00:00:00:00:00:00")));
        assertFalse(learnable("10.0.0.108", MacAddress.BROADCAST));
        assertFalse(learnable("10.0.0.108", MacAddress.parse("01:00:5e:00:00:fb")),
                    "a multicast source MAC is invalid; the check also covers broadcast");
        assertFalse(learnable("10.0.0.108", null));
        assertFalse(PassiveLearning.learnable(BINDING, null, SENDER));
    }

    /**
     * A randomised (locally-administered) MAC is a normal phone or laptop, not a
     * malformed frame — two of the hosts this found on a live segment had one.
     */
    @Test
    public void locallyAdministeredMacsAreLearnedLikeAnyOther() {
        assertTrue(learnable("10.0.0.234", MacAddress.parse("1a:aa:b4:c0:bc:f5")));
        assertTrue(learnable("10.0.0.74", MacAddress.parse("66:29:98:60:2b:5e")));
    }

    // ---- the ARP-path cases the guard never covered before §13.23 ----

    /**
     * RFC 5227: every DHCP client joining the segment sends ARP probes with a zero
     * sender address and a valid sender MAC. Cached, a second prober would bump that
     * entry's conflict counter — the field the fingerprinting layer reads as spoofing.
     */
    @Test
    public void anRfc5227ProbeSenderIsNeverLearned() {
        assertFalse(learnable("0.0.0.0", SENDER));
    }

    @Test
    public void theUnspecifiedIpv6AddressIsNeverLearned() {
        assertFalse(learnable("::", SENDER), "duplicate address detection solicits from ::");
    }

    /** Our own injected frames come back on a pcap capture; they are not a peer. */
    @Test
    public void ourOwnMacIsNeverANeighbour() {
        assertFalse(learnable("10.0.0.108", OWN));
    }

    @Test
    public void multicastGroupsAreNeverASource() {
        assertFalse(learnable("224.0.0.251", SENDER));
        assertFalse(learnable("ff02::fb", SENDER));
        assertFalse(learnable("ff02::1", SENDER));
    }

    // ---- IPv6 on-link rules ----

    @Test
    public void aLinkLocalIpv6NeighbourIsLearned() {
        assertTrue(learnable("fe80::aaaa", SENDER));
    }

    @Test
    public void aLinkLocalSenderWithoutALocalIpv6AddressIsNotOnLink() {
        assertFalse(PassiveLearning.learnable(BINDING_V4_ONLY, InetAddress.ofLiteral("fe80::aaaa"), SENDER),
                    "no local v6 address means no v6 prefix to be on-link with");
    }

    @Test
    public void aGlobalIpv6NeighbourOnOurPrefixIsLearned() {
        assertTrue(learnable("2001:db8:1::5", SENDER));
    }

    /** The router-MAC hazard applies to v6 exactly as to v4. */
    @Test
    public void anOffPrefixIpv6SenderIsNeverLearned() {
        assertFalse(learnable("2001:db8:2::5", SENDER));
    }

    @Test
    public void ourOwnIpv6AddressIsNotANeighbour() {
        assertFalse(learnable("fe80::1c2b:3d4e:5f60:7182", SENDER));
        assertFalse(learnable("2001:db8:1::61", SENDER));
    }

    /**
     * Deliberate: a routed binding has no 169.254/16 prefix, so an APIPA sender is
     * off-link by the same rule as any other foreign subnet sharing the wire. Its MAC
     * is real, but {@code resolve()} would refuse the address as off-link anyway, so
     * caching it buys nothing and would report a CACHE_HIT for an address the backend
     * otherwise declines.
     */
    @Test
    public void anApipaSenderIsOffLinkForARoutedBinding() {
        assertFalse(learnable("169.254.10.20", SENDER));
    }

    // ---- provenance ----

    private static ArpPacket.ArpView reply(String sender, String target) {
        byte[] p = ArpPacket.reply(SENDER, v4(sender), OWN, v4(target));
        return ArpPacket.parse(p, 0, p.length).orElseThrow();
    }

    private static ArpPacket.ArpView request(String sender, String target) {
        byte[] p = ArpPacket.request(SENDER, v4(sender), v4(target));
        return ArpPacket.parse(p, 0, p.length).orElseThrow();
    }

    @Test
    public void aReplyToOurSolicitationIsActiveArp() {
        assertEquals(ResolveSource.ACTIVE_ARP,
                     PassiveLearning.arpProvenance(reply("10.0.0.108", "10.0.0.61"), true));
    }

    /** The OS stack's own ARP traffic is visible on pcap; we did not ask, so it is a sighting. */
    @Test
    public void anUnsolicitedReplyIsPassive() {
        assertEquals(ResolveSource.PASSIVE,
                     PassiveLearning.arpProvenance(reply("10.0.0.108", "10.0.0.61"), false));
    }

    /** §4.2 lets a request satisfy a pending resolve; the label must say how it was learned. */
    @Test
    public void aRequestSatisfyingAPendingResolveIsPassive() {
        assertEquals(ResolveSource.PASSIVE,
                     PassiveLearning.arpProvenance(request("10.0.0.108", "10.0.0.1"), true));
    }

    /** Gratuitous takes priority over the reply opcode (the §5.2 classification rule). */
    @Test
    public void aGratuitousReplyIsPassiveEvenWhenPending() {
        ArpPacket.ArpView gratuitous = reply("10.0.0.108", "10.0.0.108");
        assertTrue(gratuitous.isGratuitous());
        assertEquals(ResolveSource.PASSIVE, PassiveLearning.arpProvenance(gratuitous, true));
    }

    @Test
    public void arpKindMatchesTheCodecClassification() {
        assertEquals(ObservationKind.ARP_REPLY, PassiveLearning.arpKind(reply("10.0.0.108", "10.0.0.61")));
        assertEquals(ObservationKind.ARP_REQUEST, PassiveLearning.arpKind(request("10.0.0.108", "10.0.0.1")));
        assertEquals(ObservationKind.GRATUITOUS_ARP, PassiveLearning.arpKind(request("10.0.0.108", "10.0.0.108")));
    }

    private static Icmp6.NaView advertisement(int flags) {
        byte[] target = InetAddress.ofLiteral("fe80::aaaa").getAddress();
        byte[] p = Icmp6.neighborAdvertisement(target, OWN_LINK_LOCAL.getAddress(), target, SENDER, flags);
        return Icmp6.parseAdvertisement(p, 0, p.length).orElseThrow();
    }

    @Test
    public void aSolicitedAdvertisementForAPendingTargetIsActiveNdp() {
        assertEquals(ResolveSource.ACTIVE_NDP,
                     PassiveLearning.ndpProvenance(advertisement(Icmp6.FLAG_SOLICITED), true));
    }

    /** An unsolicited NA is the IPv6 gratuitous announcement. */
    @Test
    public void anUnsolicitedAdvertisementIsPassive() {
        assertEquals(ResolveSource.PASSIVE, PassiveLearning.ndpProvenance(advertisement(0), true));
        assertEquals(ResolveSource.PASSIVE,
                     PassiveLearning.ndpProvenance(advertisement(Icmp6.FLAG_SOLICITED), false));
    }
}
