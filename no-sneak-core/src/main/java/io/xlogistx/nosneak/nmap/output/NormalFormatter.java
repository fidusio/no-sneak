package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.grade.Grade;
import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.nmap.ScanReport.RenderSelection;
import io.xlogistx.nosneak.result.ProbeResult;

/**
 * nmap-style human-readable console output.
 * <p>
 * Every listed port carries its {@code reason} (why the scanner decided the state — {@code
 * connected}, {@code conn-refused}, {@code reset}, {@code no-route}, {@code timeout}, {@code
 * error:<Class>}) and, when measured, the connect round-trip time. Which ports are listed and
 * which are collapsed into "Not shown" is {@link HostReport#portsToRender}'s decision, shared by
 * every formatter, so {@code --open} means the same thing in all of them.
 * <p>
 * A down host is printed as one line, {@code Host <target> is down (<reason>)}, so a report over
 * a range says what happened to every target rather than only the live ones. Warnings are always
 * printed; {@code -v} adds a run header (start time and command line) and, per live host, how
 * many TCP and UDP ports were scanned.
 */
public final class NormalFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.NORMAL;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        boolean verbose = r.config != null && r.config.verbose;
        if (verbose) {
            sb.append("Starting NoSneak ").append(ScanReport.VERSION).append(" at ")
              .append(ScanReport.nmapTime(r.startTimeMs));
            if (r.commandLine != null) sb.append(" as: ").append(r.commandLine);
            sb.append('\n');
        }
        sb.append("NMap scan report - ").append(r.hosts.size()).append(" target(s), ")
          .append(r.hostsUp()).append(" up");
        if (r.durationMs() > 0) sb.append(", ").append(r.durationMs() / 1000.0).append("s");
        sb.append('\n');
        for (HostReport h : r.hosts) {
            if (!h.up) {
                sb.append('\n').append("Host ").append(h.host);
                if (h.ip != null && !h.ip.equals(h.host)) sb.append(" (").append(h.ip).append(')');
                sb.append(" is down");
                if (h.reason != null) sb.append(" (").append(h.reason).append(')');
                sb.append('\n');
                continue;
            }
            sb.append('\n').append("Host ").append(h.host);
            if (h.ip != null && !h.ip.equals(h.host)) sb.append(" (").append(h.ip).append(')');
            sb.append(" is up");
            if (h.latencyMs >= 0) sb.append(" (").append(h.latencyMs / 1000.0).append("s latency)");
            if (h.reason != null) sb.append(" [").append(h.reason).append(']');
            sb.append('\n');
            if (h.hostname != null) sb.append("  Hostname: ").append(h.hostname).append('\n');
            if (h.mac != null) sb.append("  MAC Address: ").append(h.mac).append('\n');
            if (verbose) {
                sb.append("  Scanned: ").append(h.countProtocol("tcp")).append(" tcp, ")
                  .append(h.countProtocol("udp")).append(" udp port(s)\n");
            }

            RenderSelection sel = h.portsToRender(r.config);
            String notShown = sel.notShown();
            if (notShown != null) {
                sb.append("  Not shown: ").append(notShown).append('\n');
            }
            if (!sel.shown.isEmpty()) {
                sb.append(String.format("  %-10s %-9s %-14s %-8s %s%n",
                        "PORT", "STATE", "REASON", "RTT", "SERVICE / VERSION / TLS"));
                for (PortReport p : sel.shown) {
                    sb.append(String.format("  %-10s %-9s %-14s %-8s %s%n",
                            p.port + "/" + p.protocol, p.state.label(),
                            p.reason == null ? "" : p.reason, rtt(p), service(p)));
                }
            }
        }
        for (String w : r.warnings) {
            sb.append("Warning: ").append(w).append('\n');
        }
        sb.append('\n').append(summary(r)).append('\n');
        return sb.toString();
    }

    /** {@code "25 ms"}, or empty when the port never connected (a connect scan measures nothing else). */
    static String rtt(PortReport p) {
        return p.rttMs >= 0 ? p.rttMs + " ms" : "";
    }

    /** Closing stats line: what was scanned, what answered, and how long it took. */
    static String summary(ScanReport r) {
        int openPorts = 0;
        int hostsWithOpen = 0;
        int macs = 0;
        for (HostReport h : r.hosts) {
            int open = h.openPorts().size();
            openPorts += open;
            if (open > 0) {
                hostsWithOpen++;
            }
            if (h.mac != null) {
                macs++;
            }
        }
        StringBuilder sb = new StringBuilder("NMap done: ");
        sb.append(r.hosts.size()).append(" target(s) scanned, ")
          .append(r.hostsUp()).append(" host(s) up");
        if (macs > 0) {
            sb.append(" (").append(macs).append(" with MAC)");
        }
        if (openPorts > 0) {
            sb.append(", ").append(openPorts).append(" open port(s) on ")
              .append(hostsWithOpen).append(" host(s)");
        }
        sb.append(" in ").append(String.format("%.2f", r.durationMs() / 1000.0)).append(" seconds");
        return sb.toString();
    }

    static String service(PortReport p) {
        StringBuilder sb = new StringBuilder(p.serviceName());
        ProbeResult pr = p.probe;
        if (pr != null && pr.isComplete()) {
            String ver = pr.getServiceVersion();
            if (ver != null && !ver.isEmpty()) sb.append("  ").append(ver);
            if (pr.getTlsState() != ProbeResult.TlsState.NONE) {
                sb.append("  [").append(pr.getTlsState()).append(" pqc=").append(pr.getPqcStatus());
                if (pr.getCertValidity() != null) sb.append(" cert=").append(pr.getCertValidity());
                if (pr.getCertChainTrust() != null) sb.append('/').append(pr.getCertChainTrust());
                sb.append(' ').append(Grade.of(pr)).append(']');
            }
        } else if (p.banner != null && !p.banner.isEmpty()) {
            sb.append("  ").append(p.banner.replaceAll("[\\r\\n]+", " ").trim());
        }
        return sb.toString();
    }
}
