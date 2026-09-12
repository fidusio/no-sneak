package io.xlogistx.nosneak.net.pcap;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.EthernetFrame;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.codecs.Ipv6Header;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;

import java.util.Optional;

/**
 * The one frame a pcap backend injects at {@code open()} to learn whether the driver
 * accepts injection at all ({@code pcap_sendpacket} is driver-dependent and commonly
 * refused on wireless adapters, §8.6).
 * <p>
 * Injection is a property of the DRIVER, not of an address family — so one frame of
 * whichever family the binding has answers the question, and {@code activeArp} /
 * {@code activeNdp} then gate on whether the binding holds an address of that family
 * (§13.23-B, M7). Before this, the probe was IPv4-only and an IPv6-only interface could
 * never do NDP.
 * <p>
 * Both shapes are the least remarkable thing a host can say about itself:
 * <ul>
 *   <li>IPv4: a broadcast ARP request for our OWN address, sender == target — what
 *       duplicate address detection does. Nobody else owns the target, so nobody answers.</li>
 *   <li>IPv6: a Neighbor Solicitation FROM our own address FOR our own address, to its
 *       solicited-node group, with our MAC as the source link-layer option. Deliberately
 *       NOT DAD-shaped (source {@code ::}): a node that saw a DAD solicitation for an
 *       address it also holds would multicast a defending advertisement, and whether our
 *       own stack sees a BPF/Npcap-injected frame is driver-dependent. Recipients of
 *       this shape at most cache our (true) address.</li>
 * </ul>
 * The frame is sent and never expected back — the reader drops our own source MAC
 * before demultiplexing (§13.23-A).
 */
public final class InjectionProbe {

    private InjectionProbe() {
    }

    /**
     * @return the frame to inject, or {@code null} when the binding has no hardware
     *         address or no address of either family to originate from
     */
    public static byte[] frameFor(NicBinding binding) {
        if (!binding.supportsLayer2()) {
            return null;
        }
        MacAddress own = binding.hardwareAddress();

        Optional<NicBinding.LocalAddress> v4 = binding.ipv4().stream().findFirst();
        if (v4.isPresent()) {
            byte[] ip = v4.get().address().getAddress();
            return EthernetFrame.build(MacAddress.BROADCAST, own, EthernetFrame.ETHERTYPE_ARP,
                                       ArpPacket.request(own, ip, ip));
        }

        // Link-local first: every IPv6 interface has one, and it is the address NDP
        // itself runs on. A global address works too when that is all there is.
        Optional<NicBinding.LocalAddress> v6 = binding.ipv6().stream()
                .filter(a -> a.address().isLinkLocalAddress())
                .findFirst()
                .or(() -> binding.ipv6().stream().findFirst());
        if (v6.isEmpty()) {
            return null;
        }
        byte[] ip = v6.get().address().getAddress();
        byte[] ns = Icmp6.neighborSolicitation(ip, ip, own);
        byte[] dst = Icmp6.solicitedNodeMulticast(ip);
        byte[] header = Ipv6Header.forNeighborDiscovery(ip, dst, ns.length);
        byte[] payload = new byte[header.length + ns.length];
        System.arraycopy(header, 0, payload, 0, header.length);
        System.arraycopy(ns, 0, payload, header.length, ns.length);
        return EthernetFrame.build(Icmp6.solicitedNodeMac(ip), own, EthernetFrame.ETHERTYPE_IPV6,
                                   payload);
    }
}
