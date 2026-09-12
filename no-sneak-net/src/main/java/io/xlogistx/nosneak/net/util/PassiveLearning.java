package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservationKind;
import io.xlogistx.nosneak.net.common.ResolveSource;

import java.net.InetAddress;

/**
 * The one guard on passive learning, and the one decision on what a sighting is worth.
 * <p>
 * Every backend learns IP-to-MAC bindings from frames it did not solicit — ordinary IPv4
 * and IPv6 traffic, ARP requests, neighbour solicitations. Three copies of the guard had
 * drifted apart (one lacked the multicast clause), and the ARP path never had a guard at
 * all, so an RFC 5227 probe from {@code 0.0.0.0} became a neighbour, a second prober
 * bumped that entry's conflict counter, and the Windows backend cached its own injection
 * probe as a peer. This class is the single place those rules live (§13.23).
 * <p>
 * The guards matter more than a missed sighting would: {@code resolve()} serves the
 * cache, so a wrongly-learned entry is REPORTED as a {@code CACHE_HIT} rather than merely
 * wasting a frame. The decisive clause is ON-LINK: an off-link sender's frames arrive
 * bearing the ROUTER's MAC, so learning them would claim a remote host lives at the
 * gateway's address. ARP and NDP are link-local by definition — only on-link senders own
 * the MAC that carried them.
 * <p>
 * Pure: no state, no I/O, safe on any thread.
 */
public final class PassiveLearning {

    private PassiveLearning() {
    }

    /**
     * Whether a frame's sender may be cached as a neighbour.
     * <ul>
     *   <li>A zero, multicast or broadcast source MAC is invalid in a sent frame.</li>
     *   <li>Our own MAC is never a neighbour: pcap captures our own injected frames, and
     *       learning from them would record our MAC against every address we probe.</li>
     *   <li>{@code 0.0.0.0} and {@code ::} belong to nobody (DHCP discover, RFC 5227 ARP
     *       probes, duplicate address detection), and a multicast group is not a host.</li>
     *   <li>Off-link senders carry the router's MAC — the wrong-answer case.</li>
     *   <li>Our own address never belongs to a neighbour.</li>
     * </ul>
     *
     * @param binding     the interface the frame arrived on
     * @param source      the sender's IP as the frame claims it; may be null
     * @param frameSource the MAC the frame arrived from; may be null
     */
    public static boolean learnable(NicBinding binding, InetAddress source, MacAddress frameSource) {
        return frameSource != null
               && !frameSource.isZero()
               && !frameSource.isMulticast()
               && !frameSource.equals(binding.hardwareAddress())
               && source != null
               && !source.isAnyLocalAddress()
               && !source.isMulticastAddress()
               && binding.isOnLink(source)
               && !binding.isLocalAddress(source);
    }

    /**
     * The provenance an ARP sighting earns.
     * <p>
     * {@code ACTIVE_ARP} means "answered OUR solicitation": a genuine, non-gratuitous reply
     * while this backend has a resolve in flight for the sender. Everything else — a request,
     * a gratuitous announcement, a reply to someone else's question — is {@code PASSIVE},
     * "observed on the segment, unsolicited". §4.2 lets any of them complete a pending
     * resolve; this is what keeps the label honest when they do.
     *
     * @param solicited whether a resolve for {@code arp.spa()} is pending on this backend
     */
    public static ResolveSource arpProvenance(ArpPacket.ArpView arp, boolean solicited) {
        return solicited && arp.isReply() && !arp.isGratuitous()
                ? ResolveSource.ACTIVE_ARP : ResolveSource.PASSIVE;
    }

    /**
     * The NDP twin of {@link #arpProvenance}: {@code ACTIVE_NDP} only for an advertisement
     * carrying the Solicited flag while a resolve for its target is pending; an unsolicited
     * advertisement is the IPv6 gratuitous case and is {@code PASSIVE}.
     */
    public static ResolveSource ndpProvenance(Icmp6.NaView na, boolean solicited) {
        return solicited && na.isSolicited() ? ResolveSource.ACTIVE_NDP : ResolveSource.PASSIVE;
    }

    /** The observer-facing classification of an ARP frame, identical on every backend. */
    public static ObservationKind arpKind(ArpPacket.ArpView arp) {
        return arp.isGratuitous() ? ObservationKind.GRATUITOUS_ARP
                : arp.isReply() ? ObservationKind.ARP_REPLY : ObservationKind.ARP_REQUEST;
    }
}
