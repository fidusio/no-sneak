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

    /**
     * The one way a sweep turns its two probes into a record, shared by every backend
     * (§13.23-C; it replaced three copies that disagreed).
     * <p>
     * {@code icmpAlive} is {@link PingResult#observedOnWire()}, NOT
     * {@link PingResult#reachable()}: our own address answers from local configuration
     * without a packet, so it is alive but did not answer ICMP. The RTT is published
     * only when {@link PingResult#measured()} — a clock actually ran — otherwise the
     * local answer would print {@code 0.000 ms} as if it were a measurement (§13.18).
     *
     * @return empty when neither probe found the host, so the caller reports nothing
     */
    public static Optional<HostRecord> fromProbes(InetAddress target, ResolveResult resolved,
                                                  PingResult pinged, Instant observedAt) {
        boolean haveMac = resolved.resolved();
        boolean answeredIcmp = pinged.observedOnWire();
        if (!haveMac && !answeredIcmp) {
            return Optional.empty();
        }
        int ttl = pinged.probes().stream().filter(PingProbe::hasTtl)
                        .mapToInt(PingProbe::ttlOrHopLimit).findFirst()
                        .orElse(PingProbe.TTL_UNAVAILABLE);
        return Optional.of(new HostRecord(
                target, resolved.mac(), answeredIcmp,
                pinged.measured() ? Optional.of(pinged.avgRtt()) : Optional.empty(),
                ttl, ttl > 0 ? io.xlogistx.nosneak.net.codecs.TtlDistance.hopCount(ttl)
                             : Optional.empty(),
                haveMac ? resolved.source() : null, observedAt));
    }
}
