package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.result.ProbeResult;

/**
 * CSV — one row per (host, listed port), and one row per down host with the port columns blank
 * so a consumer sees every target that was scanned, not only the ones that answered.
 * <p>
 * The two newest columns, {@code reason} and {@code rttms}, are appended at the end so a
 * consumer that reads by position keeps working; {@code rttms} is empty when the port never
 * connected. Which ports are listed follows {@link HostReport#portsToRender}, the same rule as
 * every other format; collapsed states have no row here (CSV has no summary line).
 */
public final class CSVFormatter implements OutputFormatter {

    static final String HEADER =
            "host,ip,hostname,mac,port,protocol,state,service,version,tls,pqc,grade,banner,reason,rttms";

    @Override
    public OutputFormat format() {
        return OutputFormat.CSV;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append('\n');
        for (HostReport h : r.hosts) {
            if (!h.up) {
                // A down host is a fact worth a row: host/ip/hostname/mac, every port column empty.
                row(sb, h.host, nz(h.ip), nz(h.hostname), nz(h.mac),
                        "", "", "", "", "", "", "", "", "", "", "");
                continue;
            }
            for (PortReport p : h.portsToRender(r.config).shown) {
                ProbeResult pr = p.probe;
                String version = pr != null ? nz(pr.getServiceVersion()) : "";
                String tls = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? pr.getTlsState().name() : "";
                String pqc = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? String.valueOf(pr.getPqcStatus()) : "";
                String grade = pr != null && pr.getTlsState() != ProbeResult.TlsState.NONE
                        ? io.xlogistx.nosneak.grade.Grade.of(pr).toString() : "";
                row(sb, h.host, nz(h.ip), nz(h.hostname), nz(h.mac),
                        String.valueOf(p.port), p.protocol, p.state.label(), p.serviceName(),
                        version, tls, pqc, grade, nz(p.banner),
                        nz(p.reason), p.rttMs >= 0 ? String.valueOf(p.rttMs) : "");
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
