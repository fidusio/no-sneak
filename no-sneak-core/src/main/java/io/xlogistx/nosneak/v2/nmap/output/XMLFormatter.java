package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.PortState;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.RenderSelection;
import io.xlogistx.nosneak.v2.result.ProbeResult;

import java.util.Map;

/**
 * nmap-compatible XML output.
 * <p>
 * {@code <state state="..." reason="..."/>} is nmap's own shape. Two additions nmap does not
 * have: a {@code rttms} attribute on {@code <port>} when the connect round-trip was measured
 * (nmap keeps RTT at host level only), and {@code <extraports>} for every state collapsed into a
 * count, which nmap does emit and readers such as ndiff expect.
 */
public final class XMLFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.XML;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<nmaprun scanner=\"XNMap\" start=\"").append(r.startTimeMs / 1000)
          .append("\" args=\"").append(esc(r.commandLine)).append("\">\n");
        for (HostReport h : r.hosts) {
            sb.append("  <host>\n");
            sb.append("    <status state=\"").append(h.up ? "up" : "down")
              .append("\" reason=\"").append(esc(h.reason)).append("\"/>\n");
            sb.append("    <address addr=\"").append(esc(h.ip != null ? h.ip : h.host))
              .append("\" addrtype=\"ipv4\"/>\n");
            if (h.mac != null) {
                sb.append("    <address addr=\"").append(esc(h.mac)).append("\" addrtype=\"mac\"/>\n");
            }
            if (h.hostname != null) {
                sb.append("    <hostnames><hostname name=\"").append(esc(h.hostname))
                  .append("\"/></hostnames>\n");
            }
            if (h.up) {
                RenderSelection sel = h.portsToRender(r.config);
                sb.append("    <ports>\n");
                for (Map.Entry<PortState, Integer> e : sel.hidden.entrySet()) {
                    sb.append("      <extraports state=\"").append(e.getKey().label())
                      .append("\" count=\"").append(e.getValue()).append("\"/>\n");
                }
                for (PortReport p : sel.shown) {
                    sb.append("      <port protocol=\"").append(p.protocol).append("\" portid=\"")
                      .append(p.port).append('"');
                    if (p.rttMs >= 0) {
                        sb.append(" rttms=\"").append(p.rttMs).append('"');
                    }
                    sb.append(">\n");
                    sb.append("        <state state=\"").append(p.state.label())
                      .append("\" reason=\"").append(esc(p.reason)).append("\"/>\n");
                    ProbeResult pr = p.probe;
                    sb.append("        <service name=\"").append(esc(p.serviceName()));
                    if (pr != null && pr.getServiceVersion() != null) {
                        sb.append("\" version=\"").append(esc(pr.getServiceVersion()));
                    }
                    if (pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE) {
                        sb.append("\" tunnel=\"ssl\" tls=\"").append(pr.getTlsState())
                          .append("\" pqc=\"").append(pr.getPqcStatus());
                    }
                    sb.append("\"/>\n");
                    sb.append("      </port>\n");
                }
                sb.append("    </ports>\n");
                if (h.osGuess != null) {
                    sb.append("    <os><osmatch name=\"").append(esc(h.osGuess))
                      .append("\" accuracy=\"").append(h.osAccuracy).append("\"/></os>\n");
                }
            }
            sb.append("  </host>\n");
        }
        sb.append("  <runstats><finished time=\"").append(r.endTimeMs / 1000)
          .append("\"/><hosts up=\"").append(r.hostsUp()).append("\" total=\"")
          .append(r.hosts.size()).append("\"/></runstats>\n");
        sb.append("</nmaprun>\n");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replaceAll("[\\r\\n]+", " ");
    }
}
