package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.nmap.ScanReport.RenderSelection;

import java.util.Locale;

/**
 * nmap grepable (.gnmap) — a header comment, one line per host, a footer comment.
 * <p>
 * {@code Host: <ip> (<hostname>)} carries the reverse-DNS name when one was found and empty
 * parentheses otherwise, exactly as nmap does, so a {@code cut -d' ' -f2} stays stable. Port
 * fields are {@code port/state/proto/reason/rtt//service//}: nmap's {@code owner} slot carries
 * the reason and its {@code rpc} slot the round-trip time ({@code 25ms}, or empty when the port
 * never connected), so an existing {@code cut -d/} on the first three fields and on the service
 * still works. {@code Ignored State} follows {@link HostReport#portsToRender}, the same collapse
 * rule as every other format.
 */
public final class GrepableFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.GREPABLE;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Nmap-compatible scan initiated ").append(ScanReport.nmapTime(r.startTimeMs));
        if (r.commandLine != null) sb.append(" as: ").append(r.commandLine);
        sb.append('\n');
        for (HostReport h : r.hosts) {
            sb.append("Host: ").append(h.ip != null ? h.ip : h.host)
              .append(" (").append(h.hostname != null ? h.hostname : "").append(')');
            if (!h.up) {
                sb.append("\tStatus: Down\n");
                continue;
            }
            sb.append("\tStatus: Up");
            sb.append("\tPorts: ");
            RenderSelection sel = h.portsToRender(r.config);
            boolean first = true;
            for (PortReport p : sel.shown) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(p.port).append('/').append(p.state.label()).append('/').append(p.protocol)
                  .append('/').append(p.reason == null ? "" : p.reason)
                  .append('/').append(p.rttMs >= 0 ? p.rttMs + "ms" : "")
                  .append("//").append(p.serviceName()).append("//");
            }
            String notShown = sel.notShown();
            sb.append("\tIgnored State: ").append(notShown == null ? "0 closed, 0 filtered" : notShown);
            if (h.mac != null) sb.append("\tMAC: ").append(h.mac);
            sb.append('\n');
        }
        int total = r.hosts.size();
        int up = r.hostsUp();
        sb.append("# NoSneak done at ").append(ScanReport.nmapTime(r.endTimeMs))
          .append(" -- ").append(total).append(" IP address").append(total == 1 ? "" : "es")
          .append(" (").append(up).append(" host").append(up == 1 ? "" : "s")
          .append(" up) scanned in ").append(String.format(Locale.US, "%.2f", r.durationSec()))
          .append(" seconds\n");
        return sb.toString();
    }
}
