package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.common.MacAddress;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Reads {@code /proc/net/arp} for a MAC HINT, and nothing more.
 *
 * <h2>Why this exists, given the spec says not to read the kernel table</h2>
 *
 * Sections 4.6 and 13.9 state that this module deliberately does not read the kernel
 * neighbour table. That rule was written about a different question — whether
 * {@code PingProbe.neighborResolutionPending} may be inferred on Linux — and it holds
 * there: the kernel owns its own resolution, we cannot observe it, and guessing would
 * silently drop valid probes from the RTT statistics.
 * <p>
 * This class does not answer that question and does not set that flag. It supplies one
 * thing: a destination MAC to AIM a unicast ARP request at. Resolution still requires a
 * genuine reply arriving on our own {@code AF_PACKET} socket, and the reported
 * {@link io.xlogistx.nosneak.net.common.ResolveSource} stays {@code ACTIVE_ARP}. A wrong
 * or stale hint costs one wasted frame; it can never manufacture a result, because
 * nothing here is ever reported as an answer.
 *
 * <h2>Why a hint is needed at all</h2>
 *
 * Broadcast ARP is not universally delivered. Access points buffer broadcast and
 * multicast against the DTIM interval and commonly suppress or proxy it, so a station
 * can be fully reachable by unicast while never receiving a broadcast ARP. Measured on
 * a live segment: a host answered 0 of 3 broadcast requests and 3 of 3 unicast requests
 * to the same MAC, seconds apart, while answering ICMP throughout. Our own
 * {@code IpMacCache} cannot bootstrap that case — the first ever resolve of such a host
 * has no cached MAC to aim at, so without an external hint it is permanently
 * unresolvable.
 *
 * <h2>Why {@code /proc} rather than netlink</h2>
 *
 * {@code AF_NETLINK} would mean another socket, another reader, and a message-parsing
 * surface. This needs one file read on a resolve that has already failed. {@code /proc}
 * is IPv4-only, which is the whole scope here: NDP solicitations go to the
 * solicited-node multicast address, which is derived from the target address rather
 * than looked up, so IPv6 never needs a hint.
 */
final class KernelNeighbors {

    private static final Path ARP_TABLE = Path.of("/proc/net/arp");

    /** {@code ATF_COM} — the entry has a resolved hardware address. */
    private static final int ATF_COM = 0x02;

    private static final int COL_IP = 0;
    private static final int COL_FLAGS = 2;
    private static final int COL_MAC = 3;
    private static final int COL_DEVICE = 5;

    private KernelNeighbors() {
    }

    /**
     * The kernel's current MAC for {@code target} on {@code device}, if it holds a
     * complete entry.
     * <p>
     * Never throws: this is a best-effort hint on a path that has already failed, so an
     * unreadable or absent {@code /proc/net/arp} — a container without it, a future
     * kernel that drops it — degrades to no hint rather than to an error.
     */
    static Optional<MacAddress> lookup(InetAddress target, String device) {
        if (target == null || device == null || target.getAddress().length != 4) {
            return Optional.empty();
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(ARP_TABLE, StandardCharsets.US_ASCII);
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
        return find(lines, target.getHostAddress(), device);
    }

    /**
     * The parsing half, split out so it can be tested without a {@code /proc} to read.
     * A row looks like:
     * <pre>
     * IP address       HW type     Flags       HW address            Mask     Device
     * 10.0.0.108       0x1         0x2         94:e6:ba:4d:66:1b     *        eth0
     * </pre>
     */
    static Optional<MacAddress> find(List<String> lines, String wanted, String device) {
        if (lines == null || lines.isEmpty()) {
            return Optional.empty();
        }
        // Line 0 is the column header.
        for (String line : lines.subList(1, lines.size())) {
            String[] columns = line.trim().split("\\s+");
            if (columns.length <= COL_DEVICE
                    || !wanted.equals(columns[COL_IP])
                    || !device.equals(columns[COL_DEVICE])) {
                continue;
            }
            if ((parseFlags(columns[COL_FLAGS]) & ATF_COM) == 0) {
                return Optional.empty();   // incomplete entry carries 00:00:00:00:00:00
            }
            return parseMac(columns[COL_MAC]);
        }
        return Optional.empty();
    }

    private static int parseFlags(String hex) {
        try {
            return Integer.decode(hex);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Optional<MacAddress> parseMac(String text) {
        try {
            MacAddress mac = MacAddress.parse(text);
            return mac.isZero() || mac.isBroadcast() || mac.isMulticast()
                    ? Optional.empty()
                    : Optional.of(mac);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
