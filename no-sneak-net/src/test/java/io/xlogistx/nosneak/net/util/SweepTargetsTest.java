package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Which addresses a sweep may probe. The rule only ever REMOVES addresses: the
 * interface's own network/broadcast, plus the range's own edges when the interface
 * cannot vouch for them (off-link, or wider than the interface's prefix). §13.21 S12.
 */
public class SweepTargetsTest {

    private static final MacAddress MAC = MacAddress.parse("b0:7b:25:82:64:45");

    private static InetAddress ip(String s) {
        return InetAddress.ofLiteral(s);
    }

    private static NicBinding.LocalAddress local(String addr, int prefix) {
        return new NicBinding.LocalAddress(ip(addr), prefix);
    }

    private static NicBinding binding(List<NicBinding.LocalAddress> v4, List<NicBinding.LocalAddress> v6) {
        return new NicBinding("eth0", "eth0", 1, MAC, v4, v6, 1500);
    }

    private static final NicBinding LAN = binding(List.of(local("10.0.0.61", 24)), List.of());

    private static List<InetAddress> probeable(NicBinding b, String cidr) {
        return SweepTargets.probeable(b, CidrRange.parse(cidr));
    }

    @Test
    public void onLinkRangeEqualToInterfaceSkipsItsOwnEdges() {
        List<InetAddress> t = probeable(LAN, "10.0.0.0/24");
        assertEquals(254, t.size());
        assertFalse(t.contains(ip("10.0.0.0")));
        assertFalse(t.contains(ip("10.0.0.255")));
        assertTrue(t.contains(ip("10.0.0.1")));
        assertTrue(t.contains(ip("10.0.0.254")));
    }

    /** A sub-range inside the interface's prefix keeps its edges: they are ordinary hosts. */
    @Test
    public void subRangeInsideInterfaceKeepsItsEdges() {
        List<InetAddress> slash29 = probeable(LAN, "10.0.0.8/29");
        assertEquals(8, slash29.size());
        assertTrue(slash29.contains(ip("10.0.0.8")));
        assertTrue(slash29.contains(ip("10.0.0.15")));

        List<InetAddress> low = probeable(LAN, "10.0.0.0/25");
        assertEquals(127, low.size(), "drops only 10.0.0.0, the interface's network address");
        assertTrue(low.contains(ip("10.0.0.127")));

        List<InetAddress> high = probeable(LAN, "10.0.0.128/25");
        assertEquals(127, high.size(), "drops only 10.0.0.255, the interface's broadcast");
        assertTrue(high.contains(ip("10.0.0.128")));
    }

    /** The S12 case: a routed range's own .0 and .255 must not be echoed through the gateway. */
    @Test
    public void offLinkRangeSkipsItsOwnNetworkAndBroadcast() {
        List<InetAddress> t = probeable(LAN, "10.1.0.0/24");
        assertEquals(254, t.size());
        assertFalse(t.contains(ip("10.1.0.0")));
        assertFalse(t.contains(ip("10.1.0.255")));
        assertTrue(t.contains(ip("10.1.0.1")));
    }

    /** Wider than the NIC: the outer edges go, but the remote half's own subnetting is unknowable. */
    @Test
    public void rangeWiderThanInterfaceSkipsItsOuterEdges() {
        List<InetAddress> t = probeable(LAN, "10.0.0.0/23");
        assertEquals(509, t.size());
        assertFalse(t.contains(ip("10.0.0.0")), "range network address");
        assertFalse(t.contains(ip("10.0.0.255")), "the interface's own broadcast");
        assertFalse(t.contains(ip("10.0.1.255")), "range last address");
        assertTrue(t.contains(ip("10.0.1.0")), "not an edge of anything we can see");
    }

    @Test
    public void slash31AndSlash32AreNeverTrimmed() {
        assertEquals(2, probeable(LAN, "10.1.0.0/31").size());
        assertEquals(1, probeable(LAN, "10.1.0.7/32").size());
        assertEquals(2, probeable(LAN, "10.0.0.4/31").size());
        assertEquals(1, probeable(LAN, "10.0.0.5/32").size());
    }

    @Test
    public void offLinkSlash30LosesTwo() {
        assertEquals(List.of(ip("10.1.0.1"), ip("10.1.0.2")), probeable(LAN, "10.1.0.0/30"));
    }

    @Test
    public void ipv6RangesAreNeverTrimmed() {
        NicBinding v6 = binding(List.of(), List.of(local("fe80::1", 64)));
        assertEquals(4, probeable(v6, "2001:db8::/126").size());
        assertEquals(4, probeable(v6, "fe80::/126").size());
        assertEquals(4, probeable(LAN, "fe80::/126").size());
    }

    @Test
    public void secondSubnetOnTheSameNicIsOnLink() {
        NicBinding two = binding(List.of(local("10.0.0.61", 24), local("192.168.56.1", 24)), List.of());
        List<InetAddress> t = probeable(two, "192.168.56.0/24");
        assertEquals(254, t.size());
        assertFalse(t.contains(ip("192.168.56.0")));
        assertFalse(t.contains(ip("192.168.56.255")));
        assertTrue(probeable(two, "192.168.56.0/25").contains(ip("192.168.56.127")),
                   "inside the second subnet, the sub-range edge is an ordinary host");
    }

    @Test
    public void interfaceWithNoIpv4TreatsEveryV4RangeAsOffLink() {
        NicBinding v6only = binding(List.of(), List.of(local("fe80::1", 64)));
        List<InetAddress> t = probeable(v6only, "10.0.0.0/24");
        assertEquals(254, t.size());
        assertFalse(t.contains(ip("10.0.0.0")));
        assertFalse(t.contains(ip("10.0.0.255")));
    }

    @Test
    public void predicatesAgreeWithProbeable() {
        CidrRange offLink = CidrRange.parse("10.1.0.0/24");
        assertTrue(SweepTargets.isRangeEdge(offLink, ip("10.1.0.0")));
        assertTrue(SweepTargets.isRangeEdge(offLink, ip("10.1.0.255")));
        assertFalse(SweepTargets.isRangeEdge(offLink, ip("10.1.0.1")));
        assertFalse(SweepTargets.coversWholeRange(LAN, offLink));
        assertTrue(SweepTargets.coversWholeRange(LAN, CidrRange.parse("10.0.0.8/29")));
        assertFalse(SweepTargets.coversWholeRange(LAN, CidrRange.parse("10.0.0.0/23")));
        assertTrue(SweepTargets.mustSkip(LAN, offLink, ip("10.1.0.255")));
        assertFalse(SweepTargets.mustSkip(LAN, CidrRange.parse("10.0.0.8/29"), ip("10.0.0.15")));
    }
}
