package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.PortState;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;

/** nmap grepable (.gnmap) — one line per host. */
public final class GrepableFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.GREPABLE;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        for (HostReport h : r.hosts) {
            if (!h.up) {
                sb.append("Host: ").append(h.host).append("\tStatus: Down\n");
                continue;
            }
            sb.append("Host: ").append(h.ip != null ? h.ip : h.host);
            if (h.hostname != null) sb.append(" (").append(h.hostname).append(')');
            sb.append("\tStatus: Up");
            sb.append("\tPorts: ");
            boolean first = true;
            for (PortReport p : h.openPorts()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(p.port).append('/').append(p.state.label()).append('/').append(p.protocol)
                  .append("//").append(p.serviceName()).append("//");
            }
            int closed = h.countState(PortState.CLOSED);
            int filtered = h.countState(PortState.FILTERED);
            sb.append("\tIgnored State: ").append(closed).append(" closed, ").append(filtered).append(" filtered");
            if (h.osGuess != null) sb.append("\tOS: ").append(h.osGuess);
            if (h.mac != null) sb.append("\tMAC: ").append(h.mac);
            sb.append('\n');
        }
        return sb.toString();
    }
}
