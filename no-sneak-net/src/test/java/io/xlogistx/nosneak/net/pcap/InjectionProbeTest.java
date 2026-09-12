package io.xlogistx.nosneak.net.pcap;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.EthernetFrame;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.codecs.Ipv6Header;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The open()-time injection probe, parsed back with the module's own codecs. */
public class InjectionProbeTest {

    private static final MacAddress OWN = MacAddress.parse("b0:7b:25:82:64:45");
    private static final InetAddress V4 = InetAddress.ofLiteral("10.0.0.61");
    private static final InetAddress LINK_LOCAL = InetAddress.ofLiteral("fe80::1c2b:3d4e:5f60:7182");
    private static final InetAddress GLOBAL = InetAddress.ofLiteral("2001:db8:1::61");

    private static NicBinding binding(MacAddress mac, List<NicBinding.LocalAddress> v4,
                                      List<NicBinding.LocalAddress> v6) {
        return new NicBinding("eth0", "eth0", 4, mac, v4, v6, 1500);
    }

    private static NicBinding.LocalAddress local(InetAddress a, int prefix) {
        return new NicBinding.LocalAddress(a, prefix);
    }

    @Test
    public void dualStackProbesWithArpForOurOwnAddress() {
        byte[] frame = InjectionProbe.frameFor(binding(OWN,
                List.of(local(V4, 24)), List.of(local(LINK_LOCAL, 64))));

        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();
        assertEquals(EthernetFrame.ETHERTYPE_ARP, eth.ethertype());
        assertEquals(MacAddress.BROADCAST, eth.dst());
        assertEquals(OWN, eth.src());

        ArpPacket.ArpView arp = ArpPacket.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                         .orElseThrow();
        assertTrue(arp.isGratuitous(), "sender == target: nobody else owns it, nobody answers");
        assertEquals(OWN, arp.sha());
        assertArrayEquals(V4.getAddress(), arp.spa());
        assertArrayEquals(V4.getAddress(), arp.tpa());
    }

    @Test
    public void ipv6OnlyProbesWithAnNsForOurOwnAddress() {
        byte[] frame = InjectionProbe.frameFor(binding(OWN, List.of(),
                List.of(local(GLOBAL, 64), local(LINK_LOCAL, 64))));

        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();
        assertEquals(EthernetFrame.ETHERTYPE_IPV6, eth.ethertype());
        assertEquals(OWN, eth.src());
        assertEquals(Icmp6.solicitedNodeMac(LINK_LOCAL.getAddress()), eth.dst());

        Ipv6Header.View ip = Ipv6Header.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                       .orElseThrow();
        assertTrue(Ipv6Header.isValidNeighborDiscovery(ip), "hop limit 255, next header ICMPv6");
        assertArrayEquals(LINK_LOCAL.getAddress(), ip.src16(), "NOT DAD-shaped: the source is us, not ::");
        assertArrayEquals(Icmp6.solicitedNodeMulticast(LINK_LOCAL.getAddress()), ip.dst16());

        int nsOff = eth.payloadOffset() + 40;
        Icmp6.NsView ns = Icmp6.parseSolicitation(frame, nsOff, frame.length - nsOff).orElseThrow();
        assertArrayEquals(LINK_LOCAL.getAddress(), ns.targetIp16(), "solicits our own address");
        assertEquals(OWN, ns.sourceMac(), "SLLAO is our true MAC");
    }

    @Test
    public void linkLocalIsPreferredAsTheNsSource() {
        byte[] frame = InjectionProbe.frameFor(binding(OWN, List.of(),
                List.of(local(GLOBAL, 64), local(LINK_LOCAL, 64))));
        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElseThrow();
        Ipv6Header.View ip = Ipv6Header.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                       .orElseThrow();
        assertArrayEquals(LINK_LOCAL.getAddress(), ip.src16());

        byte[] globalOnly = InjectionProbe.frameFor(binding(OWN, List.of(), List.of(local(GLOBAL, 64))));
        EthernetFrame.View eth2 = EthernetFrame.parse(globalOnly, 0, globalOnly.length).orElseThrow();
        Ipv6Header.View ip2 = Ipv6Header.parse(globalOnly, eth2.payloadOffset(), eth2.payloadLength())
                                        .orElseThrow();
        assertArrayEquals(GLOBAL.getAddress(), ip2.src16(), "a global address serves when it is all there is");
    }

    @Test
    public void noHardwareAddressMeansNoProbe() {
        assertNull(InjectionProbe.frameFor(binding(null, List.of(local(V4, 24)), List.of())));
    }

    @Test
    public void noAddressesMeansNoProbe() {
        assertNull(InjectionProbe.frameFor(binding(OWN, List.of(), List.of())));
    }
}
