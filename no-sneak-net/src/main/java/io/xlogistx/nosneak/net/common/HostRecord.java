package io.xlogistx.nosneak.net.common;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * A discovered host, emitted by {@link HostDiscovery#sweep},
 * {@link HostDiscovery#discoverIpv6Segment}, and {@link HostDiscovery#resolve}.
 * <p>
 * {@code icmpAlive} and {@code mac.isPresent()} are INDEPENDENT facts. A host
 * that answers ARP but not ICMP is alive and must be reported. Downstream
 * consumers should treat {@code mac.isPresent() || icmpAlive} as "host exists".
 *
 * @param rtt           empty when the host was not pinged, or did not reply
 * @param ttlOrHopLimit {@link PingProbe#TTL_UNAVAILABLE} when the backend cannot report one
 * @param hopCount      derived from the TTL; populate ONLY when
 *                      {@link DiscoveryCapabilities#ttlAvailable()} is set
 */
public record HostRecord(
        InetAddress ip,
        Optional<MacAddress> mac,
        boolean icmpAlive,
        Optional<Duration> rtt,
        int ttlOrHopLimit,
        Optional<Integer> hopCount,
        ResolveSource macSource,
        Instant observedAt) {

    public HostRecord {
        if (mac == null) {
            mac = Optional.empty();
        }
        if (rtt == null) {
            rtt = Optional.empty();
        }
        if (hopCount == null) {
            hopCount = Optional.empty();
        }
    }

    /**
     * The "host exists" predicate: a resolved MAC OR an ICMP reply. Answering ARP
     * is sufficient — do not require {@code icmpAlive}.
     */
    public boolean alive() {
        return mac.isPresent() || icmpAlive;
    }
}
