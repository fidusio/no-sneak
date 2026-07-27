package io.xlogistx.nosneak.net.common;

import java.net.InetAddress;
import java.time.Instant;

/**
 * A neighbour seen on the segment without us having solicited it. Delivered to
 * subscribers registered through {@link HostDiscovery#observe}.
 */
public record ObservedNeighbor(
        InetAddress ip,
        MacAddress mac,
        ObservationKind kind,
        Instant seenAt) {
}
