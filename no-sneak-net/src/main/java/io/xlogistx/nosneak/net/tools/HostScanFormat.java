package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservedNeighbor;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.SweepSummary;

import java.time.Duration;

/**
 * Renders discovery results as text.
 * <p>
 * Split out of {@link HostScan} so the desktop application shows exactly what the
 * CLI shows: a Swing log pane appending {@link #ping(PingResult)} and a terminal
 * running {@code hostscan ping} produce identical output, which is what makes a
 * screenshot in a bug report comparable to a paste from a shell.
 * <p>
 * Every method returns a string and prints nothing. Multi-line blocks carry no
 * trailing newline.
 */
public final class HostScanFormat {

    private HostScanFormat() {
    }

    /** Capability flags as a compact word list, e.g. {@code "icmp arp ttl [WINDOWS_PCAP]"}. */
    public static String capabilities(DiscoveryCapabilities c) {
        StringBuilder sb = new StringBuilder();
        if (c.icmpV4()) sb.append("icmp ");
        if (c.icmpV6()) sb.append("icmp6 ");
        if (c.activeArp()) sb.append("arp ");
        if (c.activeNdp()) sb.append("ndp ");
        if (c.passiveObservation()) sb.append("passive ");
        if (c.ttlAvailable()) sb.append("ttl ");
        if (c.offLinkIcmp()) sb.append("off-link ");
        return sb.append('[').append(c.backend()).append(']').toString();
    }

    /** One bound interface: the header line, its addresses, and the backend device. */
    public static String nic(HostDiscovery h) {
        NicBinding b = h.binding();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-16s %-8d %-19s %s",
                                b.javaName(), b.ifIndex(),
                                b.hardwareAddress() == null ? "-" : b.hardwareAddress().toString(),
                                capabilities(h.capabilities())));
        for (NicBinding.LocalAddress a : b.ipv4()) {
            sb.append(String.format("%n    %s/%d", a.address().getHostAddress(), a.prefixLength()));
        }
        for (NicBinding.LocalAddress a : b.ipv6()) {
            sb.append(String.format("%n    %s/%d", a.address().getHostAddress(), a.prefixLength()));
        }
        return sb.append(String.format("%n    device: %s", b.backendDeviceName())).toString();
    }

    /** Column header matching {@link #nic(HostDiscovery)}. */
    public static String nicHeader() {
        return String.format("%-16s %-8s %-19s %s", "INTERFACE", "IFINDEX", "MAC", "CAPABILITIES");
    }

    /**
     * A full ping report: the per-probe lines, the loss line, and the RTT summary
     * when anything replied.
     */
    public static String ping(PingResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("PING ").append(r.target().getHostAddress())
          .append("  ").append(r.sent()).append(" probes, pipelined");
        for (PingProbe p : r.probes()) {
            sb.append(String.format("%n  seq=%-6d %s", p.sequence(), probe(p)));
        }
        sb.append(String.format("%n%n%d sent, %d received, %.1f%% loss",
                                r.sent(), r.received(), r.lossPercent()));
        if (r.reachable()) {
            sb.append(String.format("%nrtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms",
                                    millis(r.minRtt()), millis(r.avgRtt()),
                                    millis(r.maxRtt()), millis(r.stdDevRtt())));
        }
        r.error().ifPresent(e -> sb.append(String.format("%nerror: %s", e)));
        return sb.toString();
    }

    /** One probe, without the {@code seq=} prefix. */
    public static String probe(PingProbe p) {
        if (!p.replied()) {
            return "no reply (" + p.error().map(Enum::name).orElse("?") + ")";
        }
        return String.format("rtt=%.3f ms  ttl=%s%s",
                             millis(p.rtt()),
                             p.hasTtl() ? String.valueOf(p.ttlOrHopLimit()) : "n/a",
                             p.neighborResolutionPending() ? "  (includes L2 resolution)" : "");
    }

    /** Ping condensed to a single line — for a results table rather than a log. */
    public static String pingLine(PingResult r) {
        return String.format("%-39s %d/%d received%s",
                             r.target().getHostAddress(), r.received(), r.sent(),
                             r.reachable() ? String.format(", avg %.3f ms", millis(r.avgRtt())) : "");
    }

    public static String resolve(ResolveResult r) {
        return String.format("%-39s %-19s %-14s %s",
                             r.target().getHostAddress(),
                             r.mac().map(Object::toString).orElse("-"),
                             r.outcome(),
                             r.elapsed().toMillis() + " ms via " + r.source());
    }

    /** One swept host: address, MAC, what proved it alive, and the RTT if any. */
    public static String host(HostRecord h) {
        return String.format("  %-39s %-19s %-8s %s",
                             h.ip().getHostAddress(),
                             h.mac().map(Object::toString).orElse("-"),
                             h.icmpAlive() ? "icmp" : "arp",
                             h.rtt().map(d -> String.format("%.3f ms", millis(d))).orElse(""));
    }

    public static String neighbor(ObservedNeighbor n) {
        return String.format("  %-39s %-19s %s",
                             n.ip().getHostAddress(), n.mac(), n.kind());
    }

    public static String sweep(SweepSummary s) {
        return String.format("%d probed, %d alive (%d by MAC, %d by ICMP) in %d ms",
                             s.total(), s.alive(), s.macsResolved(), s.icmpAlive(),
                             s.elapsed().toMillis());
    }

    private static double millis(Duration d) {
        return d == null ? 0.0 : d.toNanos() / 1e6;
    }
}
