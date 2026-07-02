package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.util.StringJoiner;

/**
 * Grepable output formatter (similar to nmap -oG).
 * One line per host, easy to grep/awk/cut.
 */
public class GrepableFormatter implements OutputFormatter {

    private static final String LINE_SEP = System.lineSeparator();

    @Override
    public OutputFormat getFormat() {
        return OutputFormat.GREPABLE;
    }

    @Override
    public String format(ScanReport report) {
        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("# ").append(report.getScannerName());
        sb.append(" ").append(report.getScannerVersion());
        sb.append(" scan initiated ").append(report.getStartTimeFormatted());
        if (report.getCommandLine() != null) {
            sb.append(" as: ").append(report.getCommandLine());
        }
        sb.append(LINE_SEP);

        // Each host on one line
        for (ScanResult host : report.getHostResults()) {
            formatHost(sb, host);
        }

        // Footer
        sb.append("# ").append(report.getScannerName());
        sb.append(" done at ").append(report.getEndTimeFormatted());
        sb.append(" -- ").append(report.getHostCount()).append(" IP address");
        if (report.getHostCount() != 1) sb.append("es");
        sb.append(" (").append(report.getHostsUpCount()).append(" host");
        if (report.getHostsUpCount() != 1) sb.append("s");
        sb.append(" up) scanned in ");
        sb.append(String.format("%.2f", report.getDurationSec())).append(" seconds");
        sb.append(LINE_SEP);

        return sb.toString();
    }

    private void formatHost(StringBuilder sb, ScanResult host) {
        sb.append("Host: ");

        // IP address
        if (host.getIpAddress() != null) {
            sb.append(host.getIpAddress());
        } else {
            sb.append(host.getTarget());
        }

        // Hostname
        sb.append(" (");
        if (host.getHostname() != null) {
            sb.append(host.getHostname());
        }
        sb.append(")");

        // Status
        sb.append("\tStatus: ");
        sb.append(host.isHostUp() ? "Up" : "Down");

        // Ports
        sb.append("\tPorts: ");

        StringJoiner ports = new StringJoiner(", ");
        for (PortResult port : host.getPortResults()) {
            if (port.getState() == PortState.OPEN ||
                port.getState() == PortState.OPEN_FILTERED ||
                port.getState() == PortState.UNFILTERED) {

                StringBuilder portStr = new StringBuilder();
                portStr.append(port.getPort());
                portStr.append("/").append(port.getState().getDisplayName());
                portStr.append("/").append(port.getProtocol());

                // Service
                portStr.append("//");
                if (port.hasService()) {
                    portStr.append(port.getService().getServiceName());
                }
                portStr.append("//");

                ports.add(portStr.toString());
            }
        }

        sb.append(ports.toString());

        // Ignored ports summary
        int closed = host.getClosedPortCount();
        int filtered = host.getFilteredPortCount();

        if (closed > 0 || filtered > 0) {
            sb.append("\tIgnored State: ");
            if (closed > 0) {
                sb.append(closed).append(" closed");
            }
            if (closed > 0 && filtered > 0) {
                sb.append(", ");
            }
            if (filtered > 0) {
                sb.append(filtered).append(" filtered");
            }
        }

        // OS guess
        if (host.getOsFingerprint() != null && host.getOsFingerprint().hasMatches()) {
            sb.append("\tOS: ").append(host.getOsFingerprint().getBestMatch().getOsName());
        }

        sb.append(LINE_SEP);
    }

    @Override
    public void formatTo(ScanReport report, OutputStream out) {
        try {
            out.write(SharedStringUtil.getBytes(format(report)));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write grepable output", e);
        }
    }

    @Override
    public void formatTo(ScanReport report, Writer writer) {
        try {
            writer.write(format(report));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write grepable output", e);
        }
    }

    @Override
    public String getMimeType() {
        return "text/plain";
    }
}
