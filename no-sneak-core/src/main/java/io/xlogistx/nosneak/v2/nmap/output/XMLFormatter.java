package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.NMap;
import io.xlogistx.nosneak.v2.nmap.PortState;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.RenderSelection;
import io.xlogistx.nosneak.v2.result.ProbeResult;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * nmap-compatible XML output, with the run metadata nmap consumers key on: the {@code nmaprun}
 * DOCTYPE, {@code scanner}/{@code args}/{@code start}/{@code startstr}/{@code version} on the
 * root, one {@code <scaninfo>} per protocol scanned ({@code type="connect"} for TCP, {@code udp}
 * when UDP ports were named), {@code starttime}/{@code endtime} on each host, a PTR
 * {@code <hostnames>} block when the reverse lookup answered, and {@code <runstats>} with
 * {@code finished time/timestr/elapsed/summary} and {@code hosts up/down/total}.
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
        sb.append("<!DOCTYPE nmaprun>\n");
        sb.append("<nmaprun scanner=\"").append(ScanReport.SCANNER)
          .append("\" args=\"").append(esc(r.commandLine))
          .append("\" start=\"").append(r.startTimeMs / 1000)
          .append("\" startstr=\"").append(esc(ScanReport.nmapTime(r.startTimeMs)))
          .append("\" version=\"").append(ScanReport.VERSION).append("\">\n");
        int[] tcp = portsScanned(r, "tcp");
        sb.append("  <scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"").append(tcp.length)
          .append("\" services=\"").append(rangeString(tcp)).append("\"/>\n");
        int[] udp = portsScanned(r, "udp");
        if (udp.length > 0) {
            sb.append("  <scaninfo type=\"udp\" protocol=\"udp\" numservices=\"").append(udp.length)
              .append("\" services=\"").append(rangeString(udp)).append("\"/>\n");
        }
        for (HostReport h : r.hosts) {
            sb.append("  <host");
            if (h.startTimeMs > 0) sb.append(" starttime=\"").append(h.startTimeMs / 1000).append('"');
            if (h.endTimeMs > 0) sb.append(" endtime=\"").append(h.endTimeMs / 1000).append('"');
            sb.append(">\n");
            sb.append("    <status state=\"").append(h.up ? "up" : "down")
              .append("\" reason=\"").append(esc(h.reason)).append("\"/>\n");
            String addr = h.ip != null ? h.ip : h.host;
            sb.append("    <address addr=\"").append(esc(addr))
              .append("\" addrtype=\"").append(addr.indexOf(':') >= 0 ? "ipv6" : "ipv4").append("\"/>\n");
            if (h.mac != null) {
                sb.append("    <address addr=\"").append(esc(h.mac)).append("\" addrtype=\"mac\"/>\n");
            }
            if (h.hostname != null) {
                sb.append("    <hostnames><hostname name=\"").append(esc(h.hostname))
                  .append("\" type=\"PTR\"/></hostnames>\n");
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
            }
            sb.append("  </host>\n");
        }
        sb.append("  <runstats>\n");
        sb.append("    <finished time=\"").append(r.endTimeMs / 1000)
          .append("\" timestr=\"").append(esc(ScanReport.nmapTime(r.endTimeMs)))
          .append("\" elapsed=\"").append(String.format(Locale.US, "%.2f", r.durationSec()))
          .append("\" summary=\"").append(esc(r.summary())).append("\"/>\n");
        sb.append("    <hosts up=\"").append(r.hostsUp()).append("\" down=\"").append(r.hostsDown())
          .append("\" total=\"").append(r.hosts.size()).append("\"/>\n");
        sb.append("  </runstats>\n");
        sb.append("</nmaprun>\n");
        return sb.toString();
    }

    /**
     * The ports the scan was asked for, per protocol: from the config when the report carries one
     * ({@code null} TCP ports meaning the default set), else the union of what the hosts record.
     */
    static int[] portsScanned(ScanReport r, String protocol) {
        if (r.config != null) {
            int[] p = "udp".equals(protocol) ? r.config.udpPorts
                    : (r.config.ports != null ? r.config.ports : NMap.DEFAULT_PORTS);
            return p == null ? new int[0] : p;
        }
        TreeSet<Integer> union = new TreeSet<>();
        for (HostReport h : r.hosts) {
            for (PortReport p : h.ports) {
                if (protocol.equalsIgnoreCase(p.protocol)) union.add(p.port);
            }
        }
        int[] out = new int[union.size()];
        int i = 0;
        for (int p : union) out[i++] = p;
        return out;
    }

    /** nmap's {@code services} attribute: sorted, runs collapsed — {@code 1-1024,8080,8443}. */
    static String rangeString(int[] ports) {
        int[] sorted = ports.clone();
        Arrays.sort(sorted);
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < sorted.length) {
            int from = sorted[i];
            int to = from;
            while (i + 1 < sorted.length && sorted[i + 1] == to + 1) {
                to = sorted[++i];
            }
            if (sb.length() > 0) sb.append(',');
            sb.append(from);
            if (to != from) sb.append('-').append(to);
            i++;
        }
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replaceAll("[\\r\\n]+", " ");
    }
}
