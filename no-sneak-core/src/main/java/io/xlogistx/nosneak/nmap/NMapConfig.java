package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.model.ProbeDefinition;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for a staged {@link NMapScanner} run — the embeddable knob-set behind the CLI.
 * Fluent setters; sensible "regular nmap" defaults (discover the range, port-scan live hosts,
 * no service/probe scan unless asked, and a <b>bounded</b> connection rate).
 * <p>
 * The rate limits are safety properties, not tuning knobs (repo root {@code CLAUDE.md},
 * <i>Operating scope</i>): an unbounded default let a {@code /24 × 20 ports} scan open roughly
 * five thousand connections at once. The defaults now match the discovery layer's
 * {@code SweepOptions.defaults()} — 256 in flight, 2000 new connections per second — and
 * {@code 0} still means "unlimited" when an operator sets it deliberately.
 */
public final class NMapConfig {

    /** Default concurrent-connection cap; same figure as {@code SweepOptions.defaults()}. */
    public static final int DEFAULT_MAX_IN_FLIGHT = 256;
    /** Default new-connections-per-second cap; same figure as {@code SweepOptions.defaults()}. */
    public static final int DEFAULT_MAX_PER_SEC = 2000;
    /** Default per-connection timeout in seconds. */
    public static final int DEFAULT_TIMEOUT_SEC = 5;

    /** Targets: hostnames, IPs, CIDR ({@code 10.0.0.0/24}), or ranges ({@code 10.0.0.1-50}). */
    public final List<String> targets = new ArrayList<>();

    /** TCP ports to scan on each live host; {@code null} → {@link NMap#DEFAULT_PORTS}. */
    public int[] ports;

    /**
     * UDP ports to probe on each live host: the {@code U:} half of {@code -p}, or nmap's top-20
     * UDP ports when {@code -sU} is given without one. {@code null}/empty → no UDP stage. Each
     * port gets one datagram (a protocol-legal request for DNS and NTP, empty otherwise), one
     * retransmit, and is reported {@code open} on a reply, {@code closed} on ICMP
     * port-unreachable, {@code open|filtered} on silence — see {@link UdpScanCallback}.
     */
    public int[] udpPorts;

    /**
     * {@code -sU}: scan UDP ports. Without {@code T:} ports (or {@code --top-ports}) alongside it
     * the scan is UDP-only, as in nmap; without {@code U:} ports it uses
     * {@link WellKnownPorts#TOP_20_UDP}.
     */
    public boolean udpScan = false;

    /**
     * {@code --open}: the caller wants only open (or open|filtered) ports in the report. The
     * scanner still probes every requested port — this is a rendering preference — and the
     * formatters are expected to honour it; a formatter that does not yet is a rendering gap,
     * not a scanning one.
     */
    public boolean openOnly = false;

    /** Stage 0: host discovery. When false, every target is treated as up. */
    public boolean discovery = true;
    /** Discovery via TCP-connect ping (up if a discovery port connects or is refused). */
    public boolean discoveryTcp = true;
    /** Discovery via real ICMP echo (no-sneak-net); needs a privileged/Npcap-capable session. */
    public boolean discoveryIcmp = true;
    /**
     * Discovery via ARP/NDP for on-link targets (no-sneak-net layer 2). Also fills in
     * {@link ScanReport.HostReport#mac}. A host that answers ARP but not ICMP is still alive.
     */
    public boolean discoveryArp = true;
    /** Echo requests per ICMP discovery probe; pipelined, so more probes cost no extra wall time. */
    public int icmpProbes = 2;
    /** Ports used for TCP-ping discovery; {@code null} → a small common subset. */
    public int[] discoveryPorts;

    /** Stage 2: run the probe engine on open ports to identify service/version/TLS/PQC. */
    public boolean probeScan = false;
    /** Probe subset by name; {@code null}/empty → every probe in the catalog. */
    public final List<String> probeNames = new ArrayList<>();
    /** Definitions to scan with alongside the bundled ones; they join the catalog {@link #probeNames} resolves against. */
    public final List<ProbeDefinition> extraProbes = new ArrayList<>();

    /** Rate limit: max simultaneously-open connections ({@code <=0} = unlimited). Default 256. */
    public int maxInFlight = DEFAULT_MAX_IN_FLIGHT;
    /** Rate limit: max new connections per second ({@code <=0} = unpaced). Default 2000. */
    public int maxPerSec = DEFAULT_MAX_PER_SEC;

    /** Per-connection timeout (seconds). */
    public int timeoutSec = DEFAULT_TIMEOUT_SEC;

    /**
     * {@code -v} / {@code --verbose}: a rendering preference, like {@link #openOnly}. The Normal
     * formatter then prints a run header (start time, command line) and a per-host line saying
     * how many TCP/UDP ports were scanned. Warnings are printed regardless — a degraded
     * discovery mode or a cancelled scan must never be hidden behind a flag.
     */
    public boolean verbose = false;

    /**
     * When the reverse lookup (PTR) that fills {@link ScanReport.HostReport#hostname} runs.
     * nmap's flags: {@code -n} never, {@code -R} every target including down ones; the default
     * is live hosts only. The lookup is a non-blocking datagram unit through the scan gate.
     */
    public enum ReverseDns { NEVER, UP_HOSTS, ALL }

    /** See {@link ReverseDns}; default {@link ReverseDns#UP_HOSTS}. */
    public ReverseDns reverseDns = ReverseDns.UP_HOSTS;

    /**
     * {@code --dns-servers <ip>}: the resolver the PTR queries go to, as an IP literal. {@code
     * null} → the system resolver's first entry, falling back to {@code 8.8.8.8}.
     */
    public String dnsServer;

    /** PTR query timeout in milliseconds; each lookup is one datagram unit with this deadline. */
    public long dnsTimeoutMs = ReverseDnsCallback.DEFAULT_TIMEOUT_MS;

    /**
     * nmap-style timing templates, mapped onto the three knobs above. {@code T3} is the
     * default. Lower templates are for fragile or monitored segments; higher ones are for
     * lab networks you own. Nothing here changes <i>what</i> is sent, only how fast.
     * <pre>
     *   template   in-flight   per-second   timeout
     *   T0            1            1          15 s
     *   T1            4           10          15 s
     *   T2           16           50          10 s
     *   T3          256         2000           5 s   (default)
     *   T4          512         5000           3 s
     *   T5         1024        10000           2 s
     * </pre>
     */
    public enum Timing {
        T0(1, 1, 15), T1(4, 10, 15), T2(16, 50, 10),
        T3(DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_PER_SEC, DEFAULT_TIMEOUT_SEC),
        T4(512, 5000, 3), T5(1024, 10000, 2);

        public final int maxInFlight;
        public final int maxPerSec;
        public final int timeoutSec;

        Timing(int maxInFlight, int maxPerSec, int timeoutSec) {
            this.maxInFlight = maxInFlight;
            this.maxPerSec = maxPerSec;
            this.timeoutSec = timeoutSec;
        }
    }

    public NMapConfig target(String t) { if (t != null && !t.isEmpty()) targets.add(t); return this; }
    public NMapConfig ports(int[] p) { this.ports = p; return this; }
    public NMapConfig udpPorts(int[] p) { this.udpPorts = p; return this; }
    public NMapConfig udpScan(boolean b) { this.udpScan = b; return this; }
    public NMapConfig openOnly(boolean b) { this.openOnly = b; return this; }
    public NMapConfig discovery(boolean b) { this.discovery = b; return this; }
    public NMapConfig discoveryTcp(boolean b) { this.discoveryTcp = b; return this; }
    public NMapConfig discoveryIcmp(boolean b) { this.discoveryIcmp = b; return this; }
    public NMapConfig discoveryArp(boolean b) { this.discoveryArp = b; return this; }
    public NMapConfig icmpProbes(int n) { this.icmpProbes = n > 0 ? n : 1; return this; }
    public NMapConfig probeScan(boolean b) { this.probeScan = b; return this; }
    public NMapConfig probe(String name) { if (name != null && !name.isEmpty()) probeNames.add(name); return this; }
    public NMapConfig extraProbe(ProbeDefinition d) { if (d != null) extraProbes.add(d); return this; }
    public NMapConfig rate(int maxInFlight, int maxPerSec) { this.maxInFlight = maxInFlight; this.maxPerSec = maxPerSec; return this; }
    public NMapConfig timeoutInSec(int s) { this.timeoutSec = s > 0 ? s : DEFAULT_TIMEOUT_SEC; return this; }
    public NMapConfig verbose(boolean b) { this.verbose = b; return this; }
    public NMapConfig reverseDns(ReverseDns mode) { if (mode != null) this.reverseDns = mode; return this; }
    public NMapConfig dnsServer(String ip) { this.dnsServer = ip != null && !ip.isEmpty() ? ip : null; return this; }
    public NMapConfig dnsTimeoutMs(long ms) { this.dnsTimeoutMs = ms > 0 ? ms : ReverseDnsCallback.DEFAULT_TIMEOUT_MS; return this; }

    /** Applies a {@link Timing} template to the three rate knobs; later explicit flags override. */
    public NMapConfig timing(Timing t) {
        if (t != null) {
            this.maxInFlight = t.maxInFlight;
            this.maxPerSec = t.maxPerSec;
            this.timeoutSec = t.timeoutSec;
        }
        return this;
    }
}
