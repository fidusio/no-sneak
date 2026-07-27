package io.xlogistx.nosneak.net.common;

import java.time.Duration;

/**
 * Totals for one completed sweep.
 *
 * @param total       addresses probed
 * @param alive       hosts with a resolved MAC OR an ICMP reply — see {@link HostRecord#alive()}
 * @param macsResolved hosts that answered ARP or NDP
 * @param icmpAlive   hosts that answered ICMP; with no pinger wired in this is always zero
 */
public record SweepSummary(
        int total,
        int alive,
        int macsResolved,
        int icmpAlive,
        Duration elapsed) {
}
