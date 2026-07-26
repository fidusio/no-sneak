package io.xlogistx.nosneak.v2.nmap;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for a staged {@link NMapScanner} run — the embeddable knob-set behind the CLI.
 * Fluent setters; sensible "regular nmap" defaults (discover the range, port-scan live hosts,
 * no service/probe scan unless asked, no rate limit).
 */
public final class NMapConfig {

    /** Targets: hostnames, IPs, CIDR ({@code 10.0.0.0/24}), or ranges ({@code 10.0.0.1-50}). */
    public final List<String> targets = new ArrayList<>();

    /** Ports to scan on each live host; {@code null} → {@link NMap#DEFAULT_PORTS}. */
    public int[] ports;

    /** Stage 0: host discovery. When false, every target is treated as up. */
    public boolean discovery = true;
    /** Discovery via TCP-connect ping (up if a discovery port connects or is refused). */
    public boolean discoveryTcp = true;
    /** Discovery via ICMP echo ({@code InetAddress.isReachable}, best-effort; often blocked). */
    public boolean discoveryIcmp = true;
    /** Ports used for TCP-ping discovery; {@code null} → a small common subset. */
    public int[] discoveryPorts;

    /** Stage 2: run the probe engine on open ports to identify service/version/TLS/PQC. */
    public boolean probeScan = false;
    /** Probe subset by name; {@code null}/empty → all bundled probes. */
    public final List<String> probeNames = new ArrayList<>();

    /** Rate limit: max simultaneously-open connections ({@code <=0} = unlimited). */
    public int maxInFlight = 0;
    /** Rate limit: max new connections per second ({@code <=0} = unpaced). */
    public int maxPerSec = 0;

    /** Per-connection timeout (seconds). */
    public int timeoutSec = 5;

    public NMapConfig target(String t) { if (t != null && !t.isEmpty()) targets.add(t); return this; }
    public NMapConfig ports(int[] p) { this.ports = p; return this; }
    public NMapConfig discovery(boolean b) { this.discovery = b; return this; }
    public NMapConfig discoveryIcmp(boolean b) { this.discoveryIcmp = b; return this; }
    public NMapConfig probeScan(boolean b) { this.probeScan = b; return this; }
    public NMapConfig probe(String name) { if (name != null && !name.isEmpty()) probeNames.add(name); return this; }
    public NMapConfig rate(int maxInFlight, int maxPerSec) { this.maxInFlight = maxInFlight; this.maxPerSec = maxPerSec; return this; }
    public NMapConfig timeoutInSec(int s) { this.timeoutSec = s > 0 ? s : 5; return this; }
}
