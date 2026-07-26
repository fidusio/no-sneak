package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.grade.Grade;
import io.xlogistx.nosneak.v2.nmap.PortState;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.result.ProbeResult;

import java.util.List;

/** nmap-style human-readable console output. */
public final class NormalFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.NORMAL;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("XNMap scan report - ").append(r.hosts.size()).append(" target(s), ")
          .append(r.hostsUp()).append(" up");
        if (r.durationMs() > 0) sb.append(", ").append(r.durationMs() / 1000.0).append("s");
        sb.append('\n');
        for (HostReport h : r.hosts) {
            if (!h.up) {
                continue;
            }
            sb.append('\n').append("Host ").append(h.host);
            if (h.ip != null && !h.ip.equals(h.host)) sb.append(" (").append(h.ip).append(')');
            sb.append(" is up");
            if (h.latencyMs >= 0) sb.append(" (").append(h.latencyMs / 1000.0).append("s latency)");
            if (h.reason != null) sb.append(" [").append(h.reason).append(']');
            sb.append('\n');
            if (h.mac != null) sb.append("  MAC Address: ").append(h.mac).append('\n');

            List<PortReport> open = h.openPorts();
            int closed = h.countState(PortState.CLOSED);
            int filtered = h.countState(PortState.FILTERED);
            if (closed + filtered > 0) {
                sb.append("  Not shown: ").append(closed).append(" closed, ")
                  .append(filtered).append(" filtered\n");
            }
            if (!open.isEmpty()) {
                sb.append(String.format("  %-10s %-9s %s%n", "PORT", "STATE", "SERVICE / VERSION / TLS"));
                for (PortReport p : open) {
                    sb.append(String.format("  %-10s %-9s %s%n",
                            p.port + "/" + p.protocol, p.state.label(), service(p)));
                }
            }
            if (h.osGuess != null) {
                sb.append("  OS guess: ").append(h.osGuess);
                if (h.osAccuracy > 0) sb.append(" (").append(h.osAccuracy).append("%)");
                sb.append('\n');
            }
        }
        for (String w : r.warnings) {
            sb.append("Warning: ").append(w).append('\n');
        }
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
