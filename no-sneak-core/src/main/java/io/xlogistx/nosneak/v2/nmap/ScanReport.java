package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.result.ProbeResult;

import java.util.ArrayList;
import java.util.List;

/**
 * Result of a staged {@link NMapScanner} run: run-level metadata plus one {@link HostReport} per
 * target (up/down, discovery reason, MAC, OS guess) and, for live hosts, the per-port scan +
 * optional probe identification. Embeddable — the output formatters render this model.
 */
public final class ScanReport {

    public volatile long startTimeMs;
    public volatile long endTimeMs;
    public volatile String commandLine;
    public volatile NMapConfig config;
    public final List<String> warnings = new ArrayList<>();
    public final List<HostReport> hosts = new ArrayList<>();

    public int hostsUp() {
        int n = 0;
        for (HostReport h : hosts) if (h.up) n++;
        return n;
    }

    public long durationMs() {
        return endTimeMs >= startTimeMs ? endTimeMs - startTimeMs : 0;
    }

    public static final class HostReport {
        public final String host;
        public volatile String ip;
        public volatile String hostname;
        public volatile boolean up;
        public volatile String reason;    // syn-ack / conn-refused / arp-reply / icmp-echo
        public volatile String mac;
        public volatile long latencyMs = -1;
        public volatile String osGuess;   // best-effort OS from open ports/services
        public volatile int osAccuracy;   // 0..100
        public final List<PortReport> ports = new ArrayList<>();

        public HostReport(String host) {
            this.host = host;
        }

        public List<PortReport> openPorts() {
            List<PortReport> out = new ArrayList<>();
            for (PortReport p : ports) {
                if (p.state != null && p.state.isPotentiallyOpen()) out.add(p);
            }
            return out;
        }

        public int countState(PortState s) {
            int n = 0;
            for (PortReport p : ports) if (p.state == s) n++;
            return n;
        }
    }

    public static final class PortReport {
        public final int port;
        public volatile String protocol = "tcp";
        public volatile PortState state;
        public volatile String reason;    // syn-ack / conn-refused / no-response / udp-response
        public volatile long rttMs = -1;
        public volatile int ttl = -1;
        public volatile String banner;
        public volatile ProbeResult probe; // service/version/TLS identification if probed

        public PortReport(int port, PortState state) {
            this.port = port;
            this.state = state;
        }

        /** Best available service name: from the probe identification, else the well-known table. */
        public String serviceName() {
            if (probe != null && probe.isComplete() && probe.getService() != null) {
                return probe.getService();
            }
            return WellKnownPorts.name(port, protocol);
        }
    }
}
