package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.HostDiscoveryFactory;
import io.xlogistx.nosneak.net.common.ICMPPing;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Command-line front end for the host-discovery subsystem — the easiest way to
 * see it working.
 *
 * <pre>
 *   hostscan list                     # interfaces, backend devices, capabilities
 *   hostscan resolve 10.0.0.1         # ARP/NDP - the MAC, and where it came from
 *   hostscan ping    10.0.0.1 [n]     # ICMP echo, pipelined
 *   hostscan sweep   10.0.0.0/24      # ARP + ICMP across a range
 * </pre>
 *
 * Runs on any platform whose backend is built; today that is Windows (Npcap) and
 * Linux (untested). Every command opens the full wiring through
 * {@link HostDiscoveryFactory} and closes it again, so it exercises the same path
 * an embedding application would.
 * <p>
 * EXCEPT that {@code ping} and {@code list} fall back to
 * {@link HostDiscoveryFactory#openIcmpOnly()} when the layer-2 backend will not
 * open. ICMP does not need L2 on a platform where the kernel routes, and on macOS
 * the L2 half is gated behind the §7.3 ABI probe — so demanding the full wiring
 * made every command fail on a platform where ping works perfectly.
 */
public final class HostScan {
    public static final String VERSION ="host-scan-1.0.1";

    private HostScan() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        System.out.println("Current version:" + VERSION);
        String command = args[0].toLowerCase(java.util.Locale.ROOT);
        try {
            switch (command) {
                case "list" -> list();
                case "resolve" -> resolve(require(args, 1, "an IP address or hostname"));
                case "ping" -> ping(require(args, 1, "an IP address or hostname"),
                                    args.length > 2 ? Integer.parseInt(args[2]) : 4);
                case "sweep" -> sweep(require(args, 1, "a CIDR range"));
                default -> {
                    System.err.println("Unknown command: " + command);
                    usage();
                    System.exit(2);
                }
            }
        } catch (Exception e) {
            System.err.println("\nFAILED: " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("  cause: " + e.getCause());
            }
            shutdownSharedPools();
            System.exit(1);
        }
        shutdownSharedPools();
    }

    /**
     * Shuts down zoxweb's process-wide pools so the JVM can exit.
     * <p>
     * Their threads are NOT daemons, so without this the process hangs after the
     * work is done. This is legitimate ONLY because {@code HostScan} is the whole
     * application and therefore owns the process. A LIBRARY must never do this —
     * closing a {@code Discovery} deliberately leaves the executors alone, since
     * they are shared with the rest of no-sneak (§4.3).
     */
    private static void shutdownSharedPools() {
        try {
            org.zoxweb.server.task.TaskUtil.close();
        } catch (RuntimeException ignored) {
            // exiting anyway
        }
    }

    private static void list() throws Exception {
        List<NetworkInterface> nics = HostDiscoveryFactory.usableInterfaces();
        if (nics.isEmpty()) {
            System.out.println("No usable interfaces (up, addressed, non-loopback).");
            return;
        }
        HostDiscoveryFactory.Discovery opened;
        try {
            opened = HostDiscoveryFactory.open(nics);
        } catch (DiscoveryException e) {
            System.out.println("Layer-2 backend unavailable on this platform:");
            System.out.println("  " + e.getMessage());
            System.out.println();
            listIcmpOnly(nics);
            return;
        }
        try (var discovery = opened) {
            System.out.printf("%-16s %-10s %-19s %s%n",
                              "INTERFACE", "IFINDEX", "MAC", "CAPABILITIES");
            for (HostDiscovery h : discovery.perInterface()) {
                DiscoveryCapabilities c = h.capabilities();
                System.out.printf("%-16s %-10d %-19s %s%n",
                        h.binding().javaName(),
                        h.binding().ifIndex(),
                        String.valueOf(h.binding().hardwareAddress()),
                        summarise(c));
                for (var a : h.binding().ipv4()) {
                    System.out.println("    " + a.address().getHostAddress()
                                       + "/" + a.prefixLength());
                }
                System.out.println("    device: " + h.binding().backendDeviceName());
            }
            System.out.println("\npinger: " + discovery.ping().getClass().getSimpleName()
                    + (discovery.perInterface().contains(discovery.ping())
                            ? " (same object as a backend - normal on Windows)" : ""));
        }
    }

    /**
     * What {@code list} can still say when only ICMP is available: the interfaces
     * as java.net sees them, and the pinger's real capabilities. Everything here
     * comes from {@code NetworkInterface}, so it needs no backend at all.
     */
    private static void listIcmpOnly(List<NetworkInterface> nics) throws Exception {
        System.out.printf("%-16s %-10s %s%n", "INTERFACE", "IFINDEX", "MAC");
        for (NetworkInterface nif : nics) {
            byte[] mac = nif.getHardwareAddress();
            System.out.printf("%-16s %-10d %s%n", nif.getName(), nif.getIndex(),
                              mac == null ? "-" : new MacAddress(mac).toString());
            for (var a : nif.getInterfaceAddresses()) {
                System.out.println("    " + a.getAddress().getHostAddress()
                                   + "/" + a.getNetworkPrefixLength());
            }
        }
        try (ICMPPing p = HostDiscoveryFactory.openIcmpOnly()) {
            System.out.println("\npinger: " + p.getClass().getSimpleName());
            System.out.println("    " + summarise(p.capabilities()));
        }
    }

    private static void resolve(String target) throws Exception {
        InetAddress ip = InetAddress.getByName(target);
        if (!ip.getHostAddress().equals(target)) {
            System.out.println(target + " resolved to " + ip.getHostAddress());
        }
        try (var discovery = HostDiscoveryFactory.open(HostDiscoveryFactory.usableInterfaces())) {
            HostDiscovery via = discovery.forTarget(ip).orElseThrow(() -> new IllegalStateException(
                    ip.getHostAddress() + " is not on any local subnet. ARP and NDP are "
                    + "link-local protocols by definition - there is no such thing as the MAC "
                    + "of a host beyond the local segment; what you would get is the router's."));
            System.out.println("via " + via.binding().javaName());

            ResolveResult r = via.resolve(ip, Duration.ofSeconds(3)).get(15, TimeUnit.SECONDS);
            System.out.println("outcome : " + r.outcome());
            System.out.println("mac     : " + r.mac().map(Object::toString).orElse("-"));
            System.out.println("source  : " + r.source());
            System.out.println("elapsed : " + r.elapsed().toMillis() + " ms");
        }
    }

    private static void ping(String target, int count) throws Exception {
        // getByName, not ofLiteral: a CLI should accept a hostname. ofLiteral
        // refuses to do DNS, which is the right default for CidrRange and the
        // cache but wrong here.
        InetAddress ip = InetAddress.getByName(target);
        if (!ip.getHostAddress().equals(target)) {
            System.out.println(target + " resolved to " + ip.getHostAddress());
        }
        HostDiscoveryFactory.Discovery discovery = null;
        ICMPPing pinger;
        try {
            discovery = HostDiscoveryFactory.open(HostDiscoveryFactory.usableInterfaces());
            pinger = discovery.ping();
            warnIfOffLinkUnsupported(discovery, ip);
        } catch (DiscoveryException e) {
            // The L2 backend is unavailable, but ICMP does not depend on it
            // wherever the kernel routes. This is the macOS path until §7.3.
            System.out.println("note: layer-2 backend unavailable, pinging ICMP-only");
            System.out.println("      " + e.getMessage());
            pinger = HostDiscoveryFactory.openIcmpOnly();
        }
        try {
            PingResult p = pinger.ping(ip, count, Duration.ofSeconds(2))
                                 .get(30, TimeUnit.SECONDS);
            System.out.println("PING " + target + "  " + count + " probes, pipelined");
            for (PingProbe probe : p.probes()) {
                System.out.printf("  seq=%-6d %s%n", probe.sequence(),
                        probe.replied()
                                ? String.format("rtt=%.3f ms  ttl=%s", micros(probe) / 1000.0,
                                        probe.hasTtl() ? probe.ttlOrHopLimit() : "n/a")
                                : "no reply (" + probe.error().map(Enum::name).orElse("?") + ")");
            }
            System.out.printf("%n%d sent, %d received, %.1f%% loss%n",
                              p.sent(), p.received(), p.lossPercent());
            if (p.reachable()) {
                System.out.printf("rtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms%n",
                        p.minRtt().toNanos() / 1e6, p.avgRtt().toNanos() / 1e6,
                        p.maxRtt().toNanos() / 1e6, p.stdDevRtt().toNanos() / 1e6);
            }
        } finally {
            // Closing the Discovery closes the pinger it owns; a standalone
            // pinger owns itself.
            if (discovery != null) {
                discovery.close();
            } else {
                pinger.close();
            }
        }
    }

    private static void sweep(String cidr) throws Exception {
        CidrRange range = CidrRange.parse(cidr);
        try (var discovery = HostDiscoveryFactory.open(HostDiscoveryFactory.usableInterfaces())) {
            HostDiscovery via = discovery.forTarget(range.networkAddress())
                    .orElse(discovery.perInterface().get(0));
            System.out.println("sweeping " + range + " via " + via.binding().javaName() + "\n");

            SweepSummary s = via.sweep(range, SweepOptions.defaults(), HostScan::printHost)
                                .get(10, TimeUnit.MINUTES);
            System.out.printf("%n%d probed, %d alive (%d by MAC, %d by ICMP) in %d ms%n",
                    s.total(), s.alive(), s.macsResolved(), s.icmpAlive(), s.elapsed().toMillis());
        }
    }

    /**
     * Explains an unreachable off-link target BEFORE sending probes that cannot
     * possibly arrive, rather than leaving the user with a bare
     * {@code NETWORK_UNREACHABLE}.
     * <p>
     * This is not a defect: pcap injects at layer 2 and bypasses OS routing, so an
     * off-link destination needs the default gateway's MAC, which needs its IP,
     * which needs an {@code iphlpapi} binding — explicitly out of scope for v1
     * (§1, §8.4). Linux and macOS send through the kernel, which routes normally,
     * so off-link works there.
     */
    private static void warnIfOffLinkUnsupported(HostDiscoveryFactory.Discovery discovery,
                                                 InetAddress ip) {
        if (discovery.ping().capabilities().offLinkIcmp()) {
            return;
        }
        boolean onLink = discovery.perInterface().stream()
                                  .anyMatch(h -> h.binding().isOnLink(ip));
        if (onLink) {
            return;
        }
        System.out.println("""
                NOTE: %s is not on any local subnet, and this backend (%s) cannot
                      reach off-link targets - it injects at layer 2 and bypasses
                      routing, so it would need the gateway's MAC to get there.
                      Expect NETWORK_UNREACHABLE. Only on-link addresses work here;
                      Linux and macOS route through the kernel and do not have this
                      limit.
                """.formatted(ip.getHostAddress(),
                              discovery.ping().capabilities().backend()));
    }

    private static synchronized void printHost(HostRecord h) {
        System.out.printf("  %-16s %-19s %-8s %s%n",
                h.ip().getHostAddress(),
                h.mac().map(Object::toString).orElse("-"),
                h.icmpAlive() ? "icmp" : "arp",
                h.rtt().map(d -> String.format("%.3f ms", d.toNanos() / 1e6)).orElse(""));
    }

    private static long micros(PingProbe p) {
        return p.rtt() == null ? 0 : p.rtt().toNanos() / 1000;
    }

    private static String summarise(DiscoveryCapabilities c) {
        StringBuilder sb = new StringBuilder();
        if (c.icmpV4()) sb.append("icmp ");
        if (c.activeArp()) sb.append("arp ");
        if (c.activeNdp()) sb.append("ndp ");
        if (c.passiveObservation()) sb.append("passive ");
        if (c.ttlAvailable()) sb.append("ttl ");
        if (c.offLinkIcmp()) sb.append("off-link ");
        sb.append('[').append(c.backend()).append(']');
        return sb.toString();
    }

    private static String require(String[] args, int index, String what) {
        if (args.length <= index) {
            throw new IllegalArgumentException("Expected " + what);
        }
        return args[index];
    }

    private static void usage() {
        System.out.println("""
                no-sneak host discovery

                  hostscan list                  interfaces, devices, capabilities
                  hostscan resolve <ip>          ARP/NDP lookup
                  hostscan ping    <ip> [count]  ICMP echo (default 4, pipelined)
                  hostscan sweep   <cidr>        ARP + ICMP across a range

                Windows needs Npcap installed (https://npcap.com/).
                Linux needs root.""");
    }
}
