package io.xlogistx.nosneak.net.common;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;

/**
 * Result of an ARP or NDP resolution.
 * <p>
 * A successful resolve is proof the host is alive, independently of ICMP — on a
 * switched segment a host must answer ARP to function at all, whether or not it
 * answers a ping.
 *
 * @param source  meaningful only when {@code outcome == RESOLVED}
 * @param elapsed wall time for the whole call including retransmissions. On the
 *                macOS backend this measures the neighbor-table poll loop rather
 *                than a solicitation round trip, because there is no solicitation
 *                to time
 */
public record ResolveResult(
        InetAddress target,
        Optional<MacAddress> mac,
        ResolveOutcome outcome,
        ResolveSource source,
        Duration elapsed) {

    public ResolveResult {
        if (mac == null) {
            mac = Optional.empty();
        }
    }

    /** True when a MAC was obtained. */
    public boolean resolved() {
        return outcome == ResolveOutcome.RESOLVED && mac.isPresent();
    }

    public static ResolveResult resolved(InetAddress target, MacAddress mac,
                                         ResolveSource source, Duration elapsed) {
        return new ResolveResult(target, Optional.of(mac), ResolveOutcome.RESOLVED, source, elapsed);
    }

    public static ResolveResult notResolved(InetAddress target, ResolveOutcome outcome,
                                            Duration elapsed) {
        return new ResolveResult(target, Optional.empty(), outcome, null, elapsed);
    }
}
