package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.result.ProbeResult;

/** nmap-compatible XML output. */
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
                sb.append("    <ports>\n");
                for (PortReport p : h.openPorts()) {
                    sb.append("      <port protocol=\"").append(p.protocol).append("\" portid=\"")
                      .append(p.port).append("\">\n");
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
