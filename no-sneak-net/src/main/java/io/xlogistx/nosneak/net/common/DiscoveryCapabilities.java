package io.xlogistx.nosneak.net.common;

/**
 * What the running backend can actually do. Returned by BOTH public interfaces:
 * on an {@link ICMPPing} only the ICMP, TTL, off-link and raw-evidence fields are
 * meaningful; on a {@link HostDiscovery} the ARP, NDP and passive fields are, and
 * the ICMP fields report whether a pinger is wired in.
 * <p>
 * Constant for the lifetime of the object — {@link HostDiscoveryFactory}
 * finishes all wiring before publishing, so this never changes under a caller —
 * with ONE exception (§13.23-B): a backend whose reader thread has died reports the
 * capabilities that thread served as {@code false} from then on, and every operation
 * that would have needed it fails at once with the reader's cause of death rather than
 * timing out at full budget.
 * <p>
 * The point of this record is honest degradation: macOS genuinely cannot report a TTL
 * or raw evidence from its {@link HostDiscovery} half, and the API must say so rather
 * than silently returning empty results.
 *
 * @param passiveObservation all three: Linux via AF_PACKET (promiscuous on the first
 *                           {@code observe()}), Windows and macOS via NON-promiscuous
 *                           pcap capture (broadcast, multicast and traffic addressed to
 *                           us). Neither pcap backend upgrades to promiscuous at runtime:
 *                           promiscuity is fixed at activation, and {@code observe()}
 *                           only adds a subscriber
 * @param rawEvidence        full received packet bytes are available — Linux IPv4 and
 *                           Windows yes; macOS NO ({@code PingProbe.rawReply} is the only
 *                           delivery path and the datagram ICMP socket fills it empty)
 * @param ttlAvailable       Linux IPv4 and Windows yes, otherwise NO. Exists so the
 *                           fingerprinting layer can distinguish "this host is far away"
 *                           from "this backend cannot tell you"
 * @param offLinkIcmp        false on Windows v1, true on Linux and macOS where the kernel routes
 */
public record DiscoveryCapabilities(
        boolean icmpV4,
        boolean icmpV6,
        boolean activeArp,
        boolean activeNdp,
        boolean passiveObservation,
        boolean rawEvidence,
        boolean ttlAvailable,
        boolean offLinkIcmp,
        Backend backend) {

    public enum Backend { LINUX_NATIVE, MACOS_NATIVE, WINDOWS_PCAP }

    /** True when either ICMP family is available. */
    public boolean anyIcmp() {
        return icmpV4 || icmpV6;
    }

    /** True when active L2 resolution is available in either family. */
    public boolean anyLayer2() {
        return activeArp || activeNdp;
    }
}
