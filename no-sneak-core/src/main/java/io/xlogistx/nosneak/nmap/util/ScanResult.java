package io.xlogistx.nosneak.nmap.util;

import io.xlogistx.nosneak.nmap.os.OSFingerprint;

import java.net.InetAddress;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Result of scanning a single host.
 */
public class ScanResult {

    private final String target;           // Original target specification
    private final String ipAddress;        // Resolved IP address
    private final String hostname;         // Resolved hostname (if available)
    private final boolean hostUp;          // Host discovery result
    private final String hostUpReason;     // How we determined host is up
    private final String macAddress;       // MAC address (from ARP, if available)
    private final long startTimeMs;
    private final long endTimeMs;
    private final List<PortResult> portResults;
    private final OSFingerprint osFingerprint;
    private final Map<String, Object> extraInfo;

    private ScanResult(Builder builder) {
        this.target = builder.target;
        this.ipAddress = builder.ipAddress;
        this.hostname = builder.hostname;
        this.hostUp = builder.hostUp;
        this.hostUpReason = builder.hostUpReason;
        this.macAddress = builder.macAddress;
        this.startTimeMs = builder.startTimeMs;
        this.endTimeMs = builder.endTimeMs;
        this.portResults = Collections.unmodifiableList(new ArrayList<>(builder.portResults));
        this.osFingerprint = builder.osFingerprint;
        this.extraInfo = builder.extraInfo != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.extraInfo))
            : Collections.emptyMap();
    }

    // Getters
    public String getTarget() { return target; }
    public String getIpAddress() { return ipAddress; }
    public String getHostname() { return hostname; }
    public boolean isHostUp() { return hostUp; }
    public String getHostUpReason() { return hostUpReason; }
    public String getMacAddress() { return macAddress; }
    public long getStartTimeMs() { return startTimeMs; }
    public long getEndTimeMs() { return endTimeMs; }
    public List<PortResult> getPortResults() { return portResults; }
    public OSFingerprint getOsFingerprint() { return osFingerprint; }
    public Map<String, Object> getExtraInfo() { return extraInfo; }

    /**
     * Get scan duration in milliseconds
     */
    public long getDurationMs() {
        return endTimeMs - startTimeMs;
    }

    /**
     * Get all open ports
     */
    public List<PortResult> getOpenPorts() {
        return portResults.stream()
            .filter(PortResult::isOpen)
            .collect(Collectors.toList());
    }

    /**
     * Get all closed ports
     */
    public List<PortResult> getClosedPorts() {
        return portResults.stream()
            .filter(PortResult::isClosed)
            .collect(Collectors.toList());
    }

    /**
     * Get all filtered ports
     */
    public List<PortResult> getFilteredPorts() {
        return portResults.stream()
            .filter(PortResult::isFiltered)
            .collect(Collectors.toList());
    }

    /**
     * Get count of open ports
     */
    public int getOpenPortCount() {
        return (int) portResults.stream().filter(PortResult::isOpen).count();
    }

    /**
     * Get count of closed ports
     */
    public int getClosedPortCount() {
        return (int) portResults.stream().filter(PortResult::isClosed).count();
    }

    /**
     * Get count of filtered ports
     */
    public int getFilteredPortCount() {
        return (int) portResults.stream().filter(PortResult::isFiltered).count();
    }

    /**
     * Get total ports scanned
     */
    public int getTotalPortCount() {
        return portResults.size();
    }

    /**
     * Find port result by port number
     */
    public Optional<PortResult> getPort(int port) {
        return portResults.stream()
            .filter(p -> p.getPort() == port)
            .findFirst();
    }

    /**
     * Find port result by port number and protocol
     */
    public Optional<PortResult> getPort(int port, String protocol) {
        return portResults.stream()
            .filter(p -> p.getPort() == port && p.getProtocol().equals(protocol))
            .findFirst();
    }

    /**
     * Get ports with detected services
     */
    public List<PortResult> getPortsWithServices() {
        return portResults.stream()
            .filter(PortResult::hasService)
            .collect(Collectors.toList());
    }

    /**
     * Create a result for a host that is down
     */
    public static ScanResult hostDown(String target, String ipAddress) {
        return builder(target)
            .ipAddress(ipAddress)
            .hostUp(false)
            .hostUpReason("no-response")
            .build();
    }

    public static Builder builder(String target) {
        return new Builder(target);
    }

    public static class Builder {
        private final String target;
        private String ipAddress;
        private String hostname;
        private boolean hostUp = true;
        private String hostUpReason = "user-set";
        private String macAddress;
        private long startTimeMs = System.currentTimeMillis();
        private long endTimeMs = System.currentTimeMillis();
        private List<PortResult> portResults = new ArrayList<>();
        private OSFingerprint osFingerprint;
        private Map<String, Object> extraInfo;

        public Builder(String target) {
            this.target = target;
        }

        public Builder ipAddress(String ip) {
            this.ipAddress = ip;
            return this;
        }

        public Builder hostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        public Builder hostUp(boolean up) {
            this.hostUp = up;
            return this;
        }

        public Builder hostUpReason(String reason) {
            this.hostUpReason = reason;
            return this;
        }

        public Builder macAddress(String macAddress) {
            this.macAddress = macAddress;
            return this;
        }

        public Builder startTime(long ms) {
            this.startTimeMs = ms;
            return this;
        }

        public Builder endTime(long ms) {
            this.endTimeMs = ms;
            return this;
        }

        public Builder addPortResult(PortResult result) {
            this.portResults.add(result);
            return this;
        }

        public Builder portResults(List<PortResult> results) {
            this.portResults = new ArrayList<>(results);
            return this;
        }

        public Builder osFingerprint(OSFingerprint fingerprint) {
            this.osFingerprint = fingerprint;
            return this;
        }

        public Builder extraInfo(String key, Object value) {
            if (this.extraInfo == null) {
                this.extraInfo = new HashMap<>();
            }
            this.extraInfo.put(key, value);
            return this;
        }

        public Builder resolveAddress() {
            try {
                InetAddress addr = InetAddress.getByName(target);
                this.ipAddress = addr.getHostAddress();
                if (!target.equals(ipAddress)) {
                    this.hostname = addr.getHostName();
                }
            } catch (Exception e) {
                // Leave unresolved
            }
            return this;
        }

        public ScanResult build() {
            return new ScanResult(this);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan result for ").append(target);
        if (ipAddress != null && !ipAddress.equals(target)) {
            sb.append(" (").append(ipAddress).append(")");
        }
        sb.append("\n");

        if (!hostUp) {
            sb.append("Host is down");
            return sb.toString();
        }

        sb.append("Host is up");
        if (hostUpReason != null) {
            sb.append(" (").append(hostUpReason).append(")");
        }
        sb.append("\n");

        int open = getOpenPortCount();
        int closed = getClosedPortCount();
        int filtered = getFilteredPortCount();

        sb.append("Ports: ").append(open).append(" open, ");
        sb.append(closed).append(" closed, ");
        sb.append(filtered).append(" filtered\n");

        if (open > 0) {
            sb.append("\nOpen ports:\n");
            for (PortResult port : getOpenPorts()) {
                sb.append("  ").append(port).append("\n");
            }
        }

        if (osFingerprint != null) {
            sb.append("\nOS: ").append(osFingerprint).append("\n");
        }

        return sb.toString();
    }
}
