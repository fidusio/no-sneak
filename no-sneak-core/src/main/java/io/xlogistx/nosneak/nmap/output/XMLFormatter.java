package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.os.OSFingerprint;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;

/**
 * XML output formatter (nmap-compatible format).
 */
public class XMLFormatter implements OutputFormatter {

    private static final String LINE_SEP = System.lineSeparator();
    private static final String INDENT = "  ";

    @Override
    public OutputFormat getFormat() {
        return OutputFormat.XML;
    }

    @Override
    public String format(ScanReport report) {
        StringBuilder sb = new StringBuilder();

        // XML header
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>").append(LINE_SEP);
        sb.append("<!DOCTYPE nmaprun>").append(LINE_SEP);

        // Root element
        sb.append("<nmaprun");
        attr(sb, "scanner", report.getScannerName());
        attr(sb, "args", report.getCommandLine());
        attr(sb, "start", String.valueOf(report.getStartTimeMs() / 1000));
        attr(sb, "startstr", report.getStartTimeFormatted());
        attr(sb, "version", report.getScannerVersion());
        sb.append(">").append(LINE_SEP);

        // Scan info
        sb.append(INDENT).append("<scaninfo");
        if (report.getConfig() != null) {
            attr(sb, "type", report.getConfig().getPrimaryScanType().name().toLowerCase());
            attr(sb, "protocol", report.getConfig().getPrimaryScanType().getProtocol());
        }
        sb.append("/>").append(LINE_SEP);

        // Hosts
        for (ScanResult host : report.getHostResults()) {
            formatHost(sb, host);
        }

        // Run stats
        sb.append(INDENT).append("<runstats>").append(LINE_SEP);
        sb.append(INDENT).append(INDENT).append("<finished");
        attr(sb, "time", String.valueOf(report.getEndTimeMs() / 1000));
        attr(sb, "timestr", report.getEndTimeFormatted());
        attr(sb, "elapsed", String.format("%.2f", report.getDurationSec()));
        attr(sb, "summary", report.getSummary());
        sb.append("/>").append(LINE_SEP);

        sb.append(INDENT).append(INDENT).append("<hosts");
        attr(sb, "up", String.valueOf(report.getHostsUpCount()));
        attr(sb, "down", String.valueOf(report.getHostsDownCount()));
        attr(sb, "total", String.valueOf(report.getHostCount()));
        sb.append("/>").append(LINE_SEP);
        sb.append(INDENT).append("</runstats>").append(LINE_SEP);

        // Close root
        sb.append("</nmaprun>").append(LINE_SEP);

        return sb.toString();
    }

    private void formatHost(StringBuilder sb, ScanResult host) {
        sb.append(INDENT).append("<host");
        attr(sb, "starttime", String.valueOf(host.getStartTimeMs() / 1000));
        attr(sb, "endtime", String.valueOf(host.getEndTimeMs() / 1000));
        sb.append(">").append(LINE_SEP);

        // Status
        sb.append(INDENT).append(INDENT).append("<status");
        attr(sb, "state", host.isHostUp() ? "up" : "down");
        attr(sb, "reason", host.getHostUpReason());
        sb.append("/>").append(LINE_SEP);

        // Address
        sb.append(INDENT).append(INDENT).append("<address");
        attr(sb, "addr", host.getIpAddress() != null ? host.getIpAddress() : host.getTarget());
        attr(sb, "addrtype", "ipv4");
        sb.append("/>").append(LINE_SEP);

        // MAC Address
        if (host.getMacAddress() != null) {
            sb.append(INDENT).append(INDENT).append("<address");
            attr(sb, "addr", host.getMacAddress().toUpperCase());
            attr(sb, "addrtype", "mac");
            sb.append("/>").append(LINE_SEP);
        }

        // Hostnames
        if (host.getHostname() != null) {
            sb.append(INDENT).append(INDENT).append("<hostnames>").append(LINE_SEP);
            sb.append(INDENT).append(INDENT).append(INDENT).append("<hostname");
            attr(sb, "name", host.getHostname());
            attr(sb, "type", "PTR");
            sb.append("/>").append(LINE_SEP);
            sb.append(INDENT).append(INDENT).append("</hostnames>").append(LINE_SEP);
        }

        // Ports
        if (!host.getPortResults().isEmpty()) {
            sb.append(INDENT).append(INDENT).append("<ports>").append(LINE_SEP);

            // Extra ports summary
            int closed = host.getClosedPortCount();
            int filtered = host.getFilteredPortCount();
            if (closed > 0) {
                sb.append(INDENT).append(INDENT).append(INDENT).append("<extraports");
                attr(sb, "state", "closed");
                attr(sb, "count", String.valueOf(closed));
                sb.append("/>").append(LINE_SEP);
            }
            if (filtered > 0) {
                sb.append(INDENT).append(INDENT).append(INDENT).append("<extraports");
                attr(sb, "state", "filtered");
                attr(sb, "count", String.valueOf(filtered));
                sb.append("/>").append(LINE_SEP);
            }

            // Individual ports
            for (PortResult port : host.getPortResults()) {
                if (port.isOpen() || port.getState().isPotentiallyOpen()) {
                    formatPort(sb, port);
                }
            }

            sb.append(INDENT).append(INDENT).append("</ports>").append(LINE_SEP);
        }

        // OS
        if (host.getOsFingerprint() != null && host.getOsFingerprint().hasMatches()) {
            sb.append(INDENT).append(INDENT).append("<os>").append(LINE_SEP);
            OSFingerprint.OSMatch match = host.getOsFingerprint().getBestMatch();
            sb.append(INDENT).append(INDENT).append(INDENT).append("<osmatch");
            attr(sb, "name", match.getOsName());
            attr(sb, "accuracy", String.valueOf(match.getAccuracy()));
            sb.append("/>").append(LINE_SEP);
            sb.append(INDENT).append(INDENT).append("</os>").append(LINE_SEP);
        }

        sb.append(INDENT).append("</host>").append(LINE_SEP);
    }

    private void formatPort(StringBuilder sb, PortResult port) {
        sb.append(INDENT).append(INDENT).append(INDENT).append("<port");
        attr(sb, "protocol", port.getProtocol());
        attr(sb, "portid", String.valueOf(port.getPort()));
        sb.append(">").append(LINE_SEP);

        // State
        sb.append(INDENT).append(INDENT).append(INDENT).append(INDENT).append("<state");
        attr(sb, "state", port.getState().getDisplayName());
        attr(sb, "reason", port.getReason());
        if (port.getTtl() >= 0) {
            attr(sb, "reason_ttl", String.valueOf(port.getTtl()));
        }
        sb.append("/>").append(LINE_SEP);

        // Service
        if (port.hasService()) {
            sb.append(INDENT).append(INDENT).append(INDENT).append(INDENT).append("<service");
            attr(sb, "name", port.getService().getServiceName());
            if (port.getService().getProduct() != null) {
                attr(sb, "product", port.getService().getProduct());
            }
            if (port.getService().getVersion() != null) {
                attr(sb, "version", port.getService().getVersion());
            }
            if (port.getService().getExtraInfo() != null) {
                attr(sb, "extrainfo", port.getService().getExtraInfo());
            }
            attr(sb, "method", port.getService().getMethod());
            attr(sb, "conf", String.valueOf(port.getService().getConfidence() / 10));
            sb.append("/>").append(LINE_SEP);
        }

        sb.append(INDENT).append(INDENT).append(INDENT).append("</port>").append(LINE_SEP);
    }

    private void attr(StringBuilder sb, String name, String value) {
        if (value != null) {
            sb.append(" ").append(name).append("=\"").append(escapeXml(value)).append("\"");
        }
    }

    private String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    @Override
    public void formatTo(ScanReport report, OutputStream out) {
        try {
            out.write(SharedStringUtil.getBytes(format(report)));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write XML output", e);
        }
    }

    @Override
    public void formatTo(ScanReport report, Writer writer) {
        try {
            writer.write(format(report));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write XML output", e);
        }
    }

    @Override
    public String getMimeType() {
        return "application/xml";
    }
}
