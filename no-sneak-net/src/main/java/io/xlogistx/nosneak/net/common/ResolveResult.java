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
 * @param elapsed wall time for the whole call including retransmissions
 * @param detail  the native explanation behind a non-RESOLVED outcome — pcap's text for a
 *                refused injection, the errno name for a failed {@code sendto}, the reader's
 *                cause of death — or empty. The module has no logger, so this is the only
 *                place that text can reach a caller (§4.7). Never set on a RESOLVED result
 */
public record ResolveResult(
        InetAddress target,
        Optional<MacAddress> mac,
        ResolveOutcome outcome,
        ResolveSource source,
        Duration elapsed,
        Optional<String> detail) {

    public ResolveResult {
        if (mac == null) {
            mac = Optional.empty();
        }
        if (detail == null) {
            detail = Optional.empty();
        }
    }

    /** True when a MAC was obtained. */
    public boolean resolved() {
        return outcome == ResolveOutcome.RESOLVED && mac.isPresent();
    }

    public static ResolveResult resolved(InetAddress target, MacAddress mac,
                                         ResolveSource source, Duration elapsed) {
        return new ResolveResult(target, Optional.of(mac), ResolveOutcome.RESOLVED, source, elapsed,
                                 Optional.empty());
    }

    public static ResolveResult notResolved(InetAddress target, ResolveOutcome outcome,
                                            Duration elapsed) {
        return notResolved(target, outcome, elapsed, null);
    }

    /**
     * @param detail why, in the words of the layer that failed; {@code null} when there is
     *               nothing more to say than the outcome itself
     */
    public static ResolveResult notResolved(InetAddress target, ResolveOutcome outcome,
                                            Duration elapsed, String detail) {
        return new ResolveResult(target, Optional.empty(), outcome, null, elapsed,
                                 Optional.ofNullable(detail));
    }
}
