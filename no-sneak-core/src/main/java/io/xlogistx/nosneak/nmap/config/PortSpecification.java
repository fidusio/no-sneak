package io.xlogistx.nosneak.nmap.config;

import org.zoxweb.shared.data.Range;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Handles port specification parsing similar to nmap's -p option.
 * Supports:
 * - Single ports: 80
 * - Ranges: 1-1024
 * - Lists: 22,80,443
 * - Combined: 22,80,100-200,443,8000-9000
 * - Top ports: --top-ports 100
 */
public class PortSpecification {

    // Top 100 TCP ports based on nmap's frequency data
    private static final int[] TOP_100_PORTS = {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
        10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
        5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
        544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
        6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37
    };

    // Top 20 UDP ports
    private static final int[] TOP_20_UDP_PORTS = {
        53, 67, 68, 69, 123, 137, 138, 161, 162, 500,
        514, 520, 631, 1434, 1900, 4500, 5353, 49152, 49153, 49154
    };

    private final Set<Integer> tcpPorts;
    private final Set<Integer> udpPorts;

    private PortSpecification(Set<Integer> tcpPorts, Set<Integer> udpPorts) {
        this.tcpPorts = Collections.unmodifiableSet(new TreeSet<>(tcpPorts));
        this.udpPorts = Collections.unmodifiableSet(new TreeSet<>(udpPorts));
    }

    public Set<Integer> getTcpPorts() {
        return tcpPorts;
    }

    public Set<Integer> getUdpPorts() {
        return udpPorts;
    }

    public List<Integer> getTcpPortList() {
        return new ArrayList<>(tcpPorts);
    }

    public List<Integer> getUdpPortList() {
        return new ArrayList<>(udpPorts);
    }

    public int getTotalPortCount() {
        return tcpPorts.size() + udpPorts.size();
    }

    public boolean isEmpty() {
        return tcpPorts.isEmpty() && udpPorts.isEmpty();
    }

    /**
     * Parse port specification string.
     * Examples:
     * - "80" -> port 80
     * - "22,80,443" -> ports 22, 80, 443
     * - "1-1024" -> ports 1 through 1024
     * - "22,80,100-200" -> combined
     * - "T:22,80,U:53,161" -> TCP 22,80 and UDP 53,161
     */
    public static PortSpecification parse(String spec) {
        if (spec == null || spec.trim().isEmpty()) {
            return defaultPorts();
        }

        Set<Integer> tcp = new TreeSet<>();
        Set<Integer> udp = new TreeSet<>();

        String normalized = spec.replaceAll("\\s+", "");

        // Check for protocol prefixes
        if (normalized.contains("T:") || normalized.contains("U:")) {
            parseWithProtocol(normalized, tcp, udp);
        } else {
            // Default to TCP
            tcp.addAll(parsePortList(normalized));
        }

        return new PortSpecification(tcp, udp);
    }

    private static void parseWithProtocol(String spec, Set<Integer> tcp, Set<Integer> udp) {
        String[] parts = spec.split(",");
        Set<Integer> currentSet = tcp; // default to TCP

        StringBuilder currentPorts = new StringBuilder();

        for (String part : parts) {
            if (part.startsWith("T:")) {
                // Flush previous
                if (currentPorts.length() > 0) {
                    currentSet.addAll(parsePortList(currentPorts.toString()));
                    currentPorts = new StringBuilder();
                }
                currentSet = tcp;
                currentPorts.append(part.substring(2));
            } else if (part.startsWith("U:")) {
                // Flush previous
                if (currentPorts.length() > 0) {
                    currentSet.addAll(parsePortList(currentPorts.toString()));
                    currentPorts = new StringBuilder();
                }
                currentSet = udp;
                currentPorts.append(part.substring(2));
            } else {
                if (currentPorts.length() > 0) {
                    currentPorts.append(",");
                }
                currentPorts.append(part);
            }
        }

        // Flush remaining
        if (currentPorts.length() > 0) {
            currentSet.addAll(parsePortList(currentPorts.toString()));
        }
    }

    private static Set<Integer> parsePortList(String spec) {
        Set<Integer> ports = new TreeSet<>();

        if (spec == null || spec.isEmpty()) {
            return ports;
        }

        String[] parts = spec.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;

            if (part.contains("-")) {
                // Range
                String[] range = part.split("-");
                if (range.length == 2) {
                    int start = Integer.parseInt(range[0].trim());
                    int end = Integer.parseInt(range[1].trim());
                    for (int p = start; p <= end && p <= 65535; p++) {
                        if (p > 0) ports.add(p);
                    }
                }
            } else {
                // Single port
                int port = Integer.parseInt(part);
                if (port > 0 && port <= 65535) {
                    ports.add(port);
                }
            }
        }

        return ports;
    }

    /**
     * Create specification from Range object (existing zoxweb pattern)
     */
    public static PortSpecification fromRange(Range<Integer> range) {
        Set<Integer> ports = IntStream.range(range.getStart(), range.getEnd() + 1)
            .boxed()
            .collect(Collectors.toSet());
        return new PortSpecification(ports, Collections.emptySet());
    }

    /**
     * Get top N ports for TCP scanning
     */
    public static PortSpecification topPorts(int count) {
        Set<Integer> ports = new TreeSet<>();
        for (int i = 0; i < Math.min(count, TOP_100_PORTS.length); i++) {
            ports.add(TOP_100_PORTS[i]);
        }
        return new PortSpecification(ports, Collections.emptySet());
    }

    /**
     * Get top N UDP ports
     */
    public static PortSpecification topUdpPorts(int count) {
        Set<Integer> ports = new TreeSet<>();
        for (int i = 0; i < Math.min(count, TOP_20_UDP_PORTS.length); i++) {
            ports.add(TOP_20_UDP_PORTS[i]);
        }
        return new PortSpecification(Collections.emptySet(), ports);
    }

    /**
     * Default port specification (ports 1-1024)
     */
    public static PortSpecification defaultPorts() {
        Set<Integer> ports = IntStream.rangeClosed(1, 1024)
            .boxed()
            .collect(Collectors.toSet());
        return new PortSpecification(ports, Collections.emptySet());
    }

    /**
     * All ports (1-65535)
     */
    public static PortSpecification allPorts() {
        Set<Integer> ports = IntStream.rangeClosed(1, 65535)
            .boxed()
            .collect(Collectors.toSet());
        return new PortSpecification(ports, Collections.emptySet());
    }

    /**
     * Builder for custom port specifications
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final Set<Integer> tcp = new TreeSet<>();
        private final Set<Integer> udp = new TreeSet<>();

        public Builder addTcpPort(int port) {
            if (port > 0 && port <= 65535) {
                tcp.add(port);
            }
            return this;
        }

        public Builder addTcpRange(int start, int end) {
            for (int p = start; p <= end && p <= 65535; p++) {
                if (p > 0) tcp.add(p);
            }
            return this;
        }

        public Builder addUdpPort(int port) {
            if (port > 0 && port <= 65535) {
                udp.add(port);
            }
            return this;
        }

        public Builder addUdpRange(int start, int end) {
            for (int p = start; p <= end && p <= 65535; p++) {
                if (p > 0) udp.add(p);
            }
            return this;
        }

        public PortSpecification build() {
            return new PortSpecification(tcp, udp);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (!tcpPorts.isEmpty()) {
            sb.append("TCP:").append(formatPortSet(tcpPorts));
        }
        if (!udpPorts.isEmpty()) {
            if (sb.length() > 0) sb.append(" ");
            sb.append("UDP:").append(formatPortSet(udpPorts));
        }
        return sb.toString();
    }

    private String formatPortSet(Set<Integer> ports) {
        if (ports.size() <= 10) {
            return ports.toString();
        }
        return "[" + ports.size() + " ports]";
    }
}
