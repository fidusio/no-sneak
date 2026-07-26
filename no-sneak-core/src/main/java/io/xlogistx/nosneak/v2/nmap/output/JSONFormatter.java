package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.grade.Grade;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.result.ProbeResult;

/** JSON output (self-contained writer with proper string escaping). */
public final class JSONFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.JSON;
    }

    @Override
    public String render(ScanReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"scanner\": \"XNMap\",\n");
        sb.append("  \"startTimeMs\": ").append(r.startTimeMs).append(",\n");
        sb.append("  \"durationMs\": ").append(r.durationMs()).append(",\n");
        sb.append("  \"targets\": ").append(r.hosts.size()).append(",\n");
        sb.append("  \"up\": ").append(r.hostsUp()).append(",\n");
        sb.append("  \"hosts\": [\n");
        for (int i = 0; i < r.hosts.size(); i++) {
            HostReport h = r.hosts.get(i);
            sb.append("    {\n");
            kv(sb, "host", h.host, true);
            kv(sb, "ip", h.ip, true);
            kv(sb, "hostname", h.hostname, true);
            sb.append("      \"up\": ").append(h.up).append(",\n");
            kv(sb, "reason", h.reason, true);
            kv(sb, "mac", h.mac, true);
            kv(sb, "osGuess", h.osGuess, true);
            sb.append("      \"ports\": [");
            java.util.List<PortReport> open = h.openPorts();
            for (int k = 0; k < open.size(); k++) {
                PortReport p = open.get(k);
                sb.append(k == 0 ? "\n" : ",\n").append("        {");
                sb.append("\"port\": ").append(p.port);
                sb.append(", \"protocol\": ").append(str(p.protocol));
                sb.append(", \"state\": ").append(str(p.state.label()));
                sb.append(", \"service\": ").append(str(p.serviceName()));
                ProbeResult pr = p.probe;
                if (pr != null && pr.isComplete()) {
                    if (pr.getServiceVersion() != null) sb.append(", \"version\": ").append(str(pr.getServiceVersion()));
                    if (pr.getTlsState() != ProbeResult.TlsState.NONE) {
                        sb.append(", \"tls\": ").append(str(pr.getTlsState().name()));
                        sb.append(", \"pqc\": ").append(str(String.valueOf(pr.getPqcStatus())));
                        if (pr.getCertValidity() != null) sb.append(", \"certValidity\": ").append(str(pr.getCertValidity()));
                        if (pr.getCertChainTrust() != null) sb.append(", \"certChainTrust\": ").append(str(pr.getCertChainTrust()));
                        sb.append(", \"grade\": ").append(str(Grade.of(pr).toString()));
                    }
                } else if (p.banner != null && !p.banner.isEmpty()) {
                    sb.append(", \"banner\": ").append(str(p.banner));
                }
                sb.append("}");
            }
            sb.append(open.isEmpty() ? "]\n" : "\n      ]\n");
            sb.append(i + 1 < r.hosts.size() ? "    },\n" : "    }\n");
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }

    private static void kv(StringBuilder sb, String key, String val, boolean comma) {
        sb.append("      \"").append(key).append("\": ").append(str(val)).append(comma ? ",\n" : "\n");
    }

    private static String str(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
