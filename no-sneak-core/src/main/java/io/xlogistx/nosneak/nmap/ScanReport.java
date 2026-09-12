package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.grade.Grade;
import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVDouble;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;
import org.zoxweb.shared.util.NVInt;
import org.zoxweb.shared.util.NVLong;
import org.zoxweb.shared.util.NVStringList;
import java.util.Map;
import io.xlogistx.nosneak.result.ProbeResult;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Result of a staged {@link NMapScanner} run: run-level metadata plus one {@link HostReport} per
 * target (up/down, discovery reason, MAC, reverse-DNS name, per-host timing) and, for live
 * hosts, the per-port scan + optional probe identification. Embeddable — the output formatters
 * render this model.
 * <p>
 * There is no OS guess and no per-port TTL here, on purpose: OS fingerprinting is refused by
 * policy ({@code -O} is rejected at parse time) and a connect scan has no TTL source, so the
 * fields that once existed for them were never assigned and have been removed.
 */
public final class ScanReport {

    /** What the XML and grepable renderers name as the scanner. */
    public static final String SCANNER = "nosneak";
    /** The scanner version those renderers emit. */
    public static final String VERSION = "2.0";

    /** nmap's own timestamp shape ({@code Fri Sep 12 09:35:51 2026}), in the local zone. */
    private static final DateTimeFormatter NMAP_TIME =
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.US);

    public volatile long startTimeMs;
    public volatile long endTimeMs;
    public volatile String commandLine;
    public volatile NMapConfig config;
    /**
     * True when the scan was stopped before every stage finished ({@code ScanHandle.cancel()},
     * Ctrl-C, or the caller's wait budget). The report then holds whatever had completed; ports
     * that were never probed carry reason {@code cancelled}, and a warning states the counts.
     */
    public volatile boolean cancelled;
    public final List<String> warnings = new ArrayList<>();
    public final List<HostReport> hosts = new ArrayList<>();

    /**
     * The report as an {@link NVGenericMap}: the ONE declared shape every JSON consumer sees —
     * the {@code -oJ} file, the app's stored report, and what the assistant reads. Rendered by
     * {@code GSONUtil.toJSONGenericMap}, never by hand.
     * <p>
     * Absent facts are absent keys, never {@code null} and never {@code -1}. Each port carries the
     * probe summary the old writer flattened (version, TLS state, PQC, validity, trust, grade)
     * <em>and</em> the full {@code ProbeResult} map under {@code probe}, so nothing recorded is
     * lost on the way out. Hidden port states ({@code --open}, or the collapse past
     * {@link RenderSelection#COLLAPSE_THRESHOLD}) are reported under {@code notShown} so a
     * consumer can tell "no closed ports" from "closed ports were not listed".
     * <p>
     * Times appear twice: as epoch milliseconds ({@code startTimeMs}, {@code durationMs}) for
     * arithmetic and as ISO-8601 UTC strings ({@code startTime}, {@code endTime}) plus
     * {@code durationSec} for reading.
     */
    public NVGenericMap toNVGenericMap() {
        NVGenericMap m = new NVGenericMap("ScanReport");
        m.add("scanner", "XNMap");
        m.add(new NVLong("startTimeMs", startTimeMs));
        m.add("startTime", isoTime(startTimeMs));
        m.add("endTime", isoTime(endTimeMs));
        m.add(new NVLong("durationMs", durationMs()));
        m.add(new NVDouble("durationSec", durationMs() / 1000.0));
        m.add(new NVInt("targets", hosts.size()));
        m.add(new NVInt("up", hostsUp()));
        m.add(new NVInt("hostsDown", hostsDown()));
        if (commandLine != null) {
            m.add("command", commandLine);
        }
        m.add(new NVBoolean("cancelled", cancelled));
        if (!warnings.isEmpty()) {
            m.add(new NVStringList("warnings", new ArrayList<>(warnings)));
        }
        NVGenericMapList list = new NVGenericMapList("hosts");
        for (HostReport h : hosts) {
            list.add(h.toNVGenericMap(config));
        }
        m.add(list);
        return m;
    }

    public int hostsUp() {
        int n = 0;
        for (HostReport h : hosts) if (h.up) n++;
        return n;
    }

    public int hostsDown() {
        return hosts.size() - hostsUp();
    }

    public long durationMs() {
        return endTimeMs >= startTimeMs ? endTimeMs - startTimeMs : 0;
    }

    /** The run's duration in seconds, as nmap prints it ({@code 2.50}). */
    public double durationSec() {
        return durationMs() / 1000.0;
    }

    /** ISO-8601 in UTC ({@code 2026-09-12T16:35:51Z}); zone-independent, so a stored report reads the same everywhere. */
    public static String isoTime(long epochMs) {
        return Instant.ofEpochMilli(epochMs).toString();
    }

    /** nmap's {@code startstr}/{@code timestr} shape in the local zone ({@code Fri Sep 12 09:35:51 2026}). */
    public static String nmapTime(long epochMs) {
        return NMAP_TIME.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()));
    }

    /**
     * nmap's closing summary: {@code NoSneak done at <time>; N IP addresses (M hosts up) scanned
     * in X.XX seconds}. Shared by the XML {@code finished summary} and the grepable footer.
     */
    public String summary() {
        int total = hosts.size();
        int up = hostsUp();
        return "NoSneak done at " + nmapTime(endTimeMs) + "; " + total + " IP address"
                + (total == 1 ? "" : "es") + " (" + up + " host" + (up == 1 ? "" : "s")
                + " up) scanned in " + String.format(Locale.US, "%.2f", durationSec()) + " seconds";
    }

    public static final class HostReport {
        public final String host;
        public volatile String ip;
        /** Reverse-DNS (PTR) name, when the lookup ran and answered; see {@link ReverseDnsCallback}. */
        public volatile String hostname;
        public volatile boolean up;
        public volatile String reason;    // tcp-ping / conn-refused / arp-reply / icmp-echo / no-response
        public volatile String mac;
        public volatile long latencyMs = -1;
        /** When this host's first scan unit was launched (epoch ms); {@code 0} until then. */
        public volatile long startTimeMs;
        /** When the last stage that touched this host finished (epoch ms); {@code 0} until then. */
        public volatile long endTimeMs;
        public final List<PortReport> ports = new ArrayList<>();

        public HostReport(String host) {
            this.host = host;
        }

        /** See {@link ScanReport#toNVGenericMap()}; {@code cfg} decides which ports are listed. */
        public NVGenericMap toNVGenericMap(NMapConfig cfg) {
            NVGenericMap m = new NVGenericMap("HostReport");
            m.add("host", host);
            if (ip != null) m.add("ip", ip);
            if (hostname != null) m.add("hostname", hostname);
            m.add(new NVBoolean("up", up));
            if (reason != null) m.add("reason", reason);
            if (mac != null) m.add("mac", mac);
            if (latencyMs >= 0) m.add(new NVLong("latencyMs", latencyMs));
            if (startTimeMs > 0) m.add("startTime", isoTime(startTimeMs));
            if (endTimeMs > 0) m.add("endTime", isoTime(endTimeMs));
            NVGenericMap stats = new NVGenericMap("portStats");
            stats.add(new NVInt("open", countState(PortState.OPEN)));
            stats.add(new NVInt("closed", countState(PortState.CLOSED)));
            stats.add(new NVInt("filtered", countState(PortState.FILTERED)));
            m.add(stats);
            RenderSelection sel = portsToRender(cfg);
            if (!sel.hidden.isEmpty()) {
                NVGenericMap hidden = new NVGenericMap("notShown");
                for (Map.Entry<PortState, Integer> e : sel.hidden.entrySet()) {
                    hidden.add(new NVInt(e.getKey().label(), e.getValue()));
                }
                m.add(hidden);
            }
            NVGenericMapList list = new NVGenericMapList("ports");
            for (PortReport p : sel.shown) {
                list.add(p.toNVGenericMap());
            }
            m.add(list);
            return m;
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

        /** Ports of one protocol ({@code "tcp"}/{@code "udp"}) recorded for this host. */
        public int countProtocol(String protocol) {
            int n = 0;
            for (PortReport p : ports) if (protocol.equalsIgnoreCase(p.protocol)) n++;
            return n;
        }

        /**
         * What a renderer should list for this host, and what it should collapse into a
         * "not shown" count. ONE rule for all five formatters, so {@code --open} and the
         * collapse threshold cannot drift between them.
         * <p>
         * With {@link NMapConfig#openOnly} every port that is not potentially open is hidden.
         * Without it, nmap's habit is followed: a state is listed port by port while it has at
         * most {@link RenderSelection#COLLAPSE_THRESHOLD} entries — that is where the per-port
         * {@code reason} earns its keep (a refused port and a routed-away port look the same as
         * a count) — and collapsed into a count once it has more. Potentially-open states are
         * never collapsed.
         *
         * @param cfg may be null (a hand-built report); treated as {@code openOnly == false}
         */
        public RenderSelection portsToRender(NMapConfig cfg) {
            return RenderSelection.of(this, cfg != null && cfg.openOnly);
        }
    }

    /** The ports a renderer lists for one host, plus per-state counts of what it hides. */
    public static final class RenderSelection {
        /** A non-open state with more ports than this is reported as a count, not listed. */
        public static final int COLLAPSE_THRESHOLD = 10;

        public final List<PortReport> shown;
        /** Hidden ports by state, in {@link PortState} declaration order; never contains zeros. */
        public final java.util.Map<PortState, Integer> hidden;

        private RenderSelection(List<PortReport> shown, java.util.Map<PortState, Integer> hidden) {
            this.shown = shown;
            this.hidden = hidden;
        }

        static RenderSelection of(HostReport h, boolean openOnly) {
            java.util.EnumMap<PortState, Integer> counts = new java.util.EnumMap<>(PortState.class);
            for (PortReport p : h.ports) {
                PortState s = p.state == null ? PortState.UNKNOWN : p.state;
                counts.merge(s, 1, Integer::sum);
            }
            java.util.EnumMap<PortState, Integer> hidden = new java.util.EnumMap<>(PortState.class);
            List<PortReport> shown = new ArrayList<>();
            for (PortReport p : h.ports) {
                PortState s = p.state == null ? PortState.UNKNOWN : p.state;
                boolean hide = !s.isPotentiallyOpen()
                        && (openOnly || counts.get(s) > COLLAPSE_THRESHOLD);
                if (hide) {
                    hidden.merge(s, 1, Integer::sum);
                } else {
                    shown.add(p);
                }
            }
            return new RenderSelection(shown, hidden);
        }

        public int hiddenCount() {
            int n = 0;
            for (int v : hidden.values()) n += v;
            return n;
        }

        public int hidden(PortState s) {
            return hidden.getOrDefault(s, 0);
        }

        /**
         * The counts as text, {@code "15 closed, 2 filtered"}. Closed and filtered are always
         * both named (the shape every earlier report used); any other hidden state is appended.
         * Null when nothing is hidden.
         */
        public String notShown() {
            if (hidden.isEmpty()) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(hidden(PortState.CLOSED)).append(" closed, ")
              .append(hidden(PortState.FILTERED)).append(" filtered");
            for (java.util.Map.Entry<PortState, Integer> e : hidden.entrySet()) {
                if (e.getKey() != PortState.CLOSED && e.getKey() != PortState.FILTERED) {
                    sb.append(", ").append(e.getValue()).append(' ').append(e.getKey().label());
                }
            }
            return sb.toString();
        }
    }

    public static final class PortReport {
        public final int port;
        public volatile String protocol = "tcp";
        public volatile PortState state;
        public volatile String reason;    // connected / conn-refused / no-response / udp-response
        public volatile long rttMs = -1;
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

        /** See {@link ScanReport#toNVGenericMap()}. */
        public NVGenericMap toNVGenericMap() {
            NVGenericMap m = new NVGenericMap("PortReport");
            m.add(new NVInt("port", port));
            m.add("protocol", protocol);
            m.add("state", state.label());
            if (reason != null) m.add("reason", reason);
            if (rttMs >= 0) m.add(new NVLong("rttMs", rttMs));
            String service = serviceName();
            if (service != null) m.add("service", service);
            if (banner != null && !banner.isEmpty()) m.add("banner", banner);
            ProbeResult pr = probe;
            if (pr != null && pr.isComplete()) {
                if (pr.getServiceVersion() != null) m.add("version", pr.getServiceVersion());
                if (pr.getTlsState() != ProbeResult.TlsState.NONE) {
                    m.add("tls", pr.getTlsState().name());
                    m.add("pqc", String.valueOf(pr.getPqcStatus()));
                    if (pr.getCertValidity() != null) m.add("certValidity", pr.getCertValidity());
                    if (pr.getCertChainTrust() != null) m.add("certChainTrust", pr.getCertChainTrust());
                    m.add("grade", Grade.of(pr).toString());
                }
                NVGenericMap full = pr.toNVGenericMap();
                full.setName("probe");
                m.add(full);
            }
            return m;
        }
    }
}
