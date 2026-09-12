package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.RenderSelection;

/**
 * nmap grepable (.gnmap) — one line per host.
 * <p>
 * Port fields are {@code port/state/proto/reason/rtt//service//}: nmap's {@code owner} slot
 * carries the reason and its {@code rpc} slot the round-trip time ({@code 25ms}, or empty when
 * the port never connected), so an existing {@code cut -d/} on the first three fields and on the
 * service still works. {@code Ignored State} follows {@link HostReport#portsToRender}, the same
 * collapse rule as every other format.
 */
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
            if (h.osGuess != null) sb.append("\tOS: ").append(h.osGuess);
            if (h.mac != null) sb.append("\tMAC: ").append(h.mac);
            sb.append('\n');
        }
        return sb.toString();
    }
}
