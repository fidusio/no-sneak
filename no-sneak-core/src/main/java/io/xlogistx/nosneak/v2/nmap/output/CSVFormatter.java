package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.result.ProbeResult;

/** CSV — one row per (host, open port). */
public final class CSVFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.CSV;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("host,ip,hostname,mac,port,protocol,state,service,version,tls,pqc,grade,banner\n");
        for (HostReport h : r.hosts) {
            if (!h.up) {
                continue;
            }
            for (PortReport p : h.openPorts()) {
                ProbeResult pr = p.probe;
                String version = pr != null ? nz(pr.getServiceVersion()) : "";
                String tls = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? pr.getTlsState().name() : "";
                String pqc = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? String.valueOf(pr.getPqcStatus()) : "";
                String grade = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? io.xlogistx.nosneak.v2.grade.Grade.of(pr).toString() : "";
                row(sb, h.host, nz(h.ip), nz(h.hostname), nz(h.mac),
                        String.valueOf(p.port), p.protocol, p.state.label(), p.serviceName(),
                        version, tls, pqc, grade, nz(p.banner));
            }
        }
        return sb.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static void row(StringBuilder sb, String... cells) {
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(quote(cells[i]));
        }
        sb.append('\n');
    }

    private static String quote(String s) {
        String v = s == null ? "" : s.replaceAll("[\\r\\n]+", " ");
        if (v.contains(",") || v.contains("\"")) {
            v = "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }
}
