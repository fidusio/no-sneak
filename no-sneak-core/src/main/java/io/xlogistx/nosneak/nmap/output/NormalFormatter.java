package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;

/**
 * Normal console output formatter (human-readable).
 * Similar to nmap's default output format.
 */
public class NormalFormatter implements OutputFormatter {

    private static final String LINE_SEP = System.lineSeparator();

    @Override
    public OutputFormat getFormat() {
        return OutputFormat.NORMAL;
    }

    @Override
    public String format(ScanReport report) {
        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("Starting ").append(report.getScannerName());
        sb.append(" ").append(report.getScannerVersion());
        sb.append(" at ").append(report.getStartTimeFormatted());
        sb.append(LINE_SEP);

        if (report.getCommandLine() != null) {
            sb.append("Command: ").append(report.getCommandLine()).append(LINE_SEP);
        }

        sb.append(LINE_SEP);

        // Each host
        for (ScanResult host : report.getHostResults()) {
            formatHost(sb, host);
            sb.append(LINE_SEP);
        }

        // Warnings
        for (String warning : report.getWarnings()) {
            sb.append("WARNING: ").append(warning).append(LINE_SEP);
        }

        // Summary
        sb.append(LINE_SEP);
        sb.append(report.getSummary());
        sb.append(LINE_SEP);

        return sb.toString();
    }

    private void formatHost(StringBuilder sb, ScanResult host) {
        // Host header
        sb.append("Scan report for ");
        sb.append(host.getTarget());
        if (host.getIpAddress() != null && !host.getIpAddress().equals(host.getTarget())) {
            sb.append(" (").append(host.getIpAddress()).append(")");
        }
        sb.append(LINE_SEP);

        // Host status
        if (!host.isHostUp()) {
            sb.append("Host is down");
            if (host.getHostUpReason() != null) {
                sb.append(" (").append(host.getHostUpReason()).append(")");
            }
            sb.append(LINE_SEP);
            return;
        }

        sb.append("Host is up");
        // Show latency in seconds like real nmap
        long latencyMs = host.getDurationMs();
        if (latencyMs > 0) {
            sb.append(" (").append(String.format("%.4fs latency", latencyMs / 1000.0)).append(")");
        }
        sb.append(".");
        sb.append(LINE_SEP);

        // Show MAC address if available (from ARP discovery)
        if (host.getMacAddress() != null) {
            sb.append("MAC Address: ").append(host.getMacAddress().toUpperCase());
            sb.append(LINE_SEP);
        }

        // Port summary
        int open = host.getOpenPortCount();
        int closed = host.getClosedPortCount();
        int filtered = host.getFilteredPortCount();

        if (closed > 0 && closed == host.getTotalPortCount()) {
            sb.append("All ").append(closed).append(" scanned ports are closed");
            sb.append(LINE_SEP);
            return;
        }

        if (filtered > 0 && filtered == host.getTotalPortCount()) {
            sb.append("All ").append(filtered).append(" scanned ports are filtered");
            sb.append(LINE_SEP);
            return;
        }

        // Show summary of not shown ports
        int notShown = closed + filtered;
        if (notShown > 0) {
            sb.append("Not shown: ");
            if (closed > 0) {
                sb.append(closed).append(" closed");
                if (filtered > 0) sb.append(", ");
            }
            if (filtered > 0) {
                sb.append(filtered).append(" filtered");
            }
            sb.append(" ports").append(LINE_SEP);
        }

        // Port table header
        if (open > 0 || hasInterestingPorts(host)) {
            sb.append(String.format("%-10s %-8s %-12s %s", "PORT", "STATE", "SERVICE", "VERSION"));
            sb.append(LINE_SEP);

            // Port details - show open and interesting ports
            for (PortResult port : host.getPortResults()) {
                if (shouldShowPort(port)) {
                    formatPort(sb, port);
                }
            }
        }

        // OS detection
        if (host.getOsFingerprint() != null) {
            sb.append(LINE_SEP);
            sb.append("OS: ").append(host.getOsFingerprint()).append(LINE_SEP);
        }
    }

    private boolean hasInterestingPorts(ScanResult host) {
        for (PortResult port : host.getPortResults()) {
            if (shouldShowPort(port)) {
                return true;
            }
        }
        return false;
    }

    private boolean shouldShowPort(PortResult port) {
        // Show open, open|filtered, and unfiltered ports
        return port.getState() == PortState.OPEN ||
               port.getState() == PortState.OPEN_FILTERED ||
               port.getState() == PortState.UNFILTERED;
    }

    private void formatPort(StringBuilder sb, PortResult port) {
        // PORT column
        String portStr = port.getPort() + "/" + port.getProtocol();
        sb.append(String.format("%-10s ", portStr));

        // STATE column
        sb.append(String.format("%-8s ", port.getState().getDisplayName()));

        // SERVICE column
        String service = "";
        if (port.hasService()) {
            service = port.getService().getServiceName();
        }
        sb.append(String.format("%-12s ", service));

        // VERSION column
        if (port.hasService() && port.getService().hasProduct()) {
            sb.append(port.getService().getProduct());
            if (port.getService().getVersion() != null) {
                sb.append(" ").append(port.getService().getVersion());
            }
            if (port.getService().getExtraInfo() != null) {
                sb.append(" (").append(port.getService().getExtraInfo()).append(")");
            }
        }

        sb.append(LINE_SEP);
    }

    @Override
    public void formatTo(ScanReport report, OutputStream out) {
        try {
            out.write(SharedStringUtil.getBytes(format(report)));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write output", e);
        }
    }

    @Override
    public void formatTo(ScanReport report, Writer writer) {
        try {
            writer.write(format(report));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write output", e);
        }
    }

    @Override
    public String getMimeType() {
        return "text/plain";
    }
}
