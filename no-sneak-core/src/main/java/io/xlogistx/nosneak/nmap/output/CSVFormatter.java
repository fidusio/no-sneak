package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;

/**
 * CSV output formatter.
 * One row per port, suitable for spreadsheet import.
 */
public class CSVFormatter implements OutputFormatter {

    private static final String LINE_SEP = System.lineSeparator();
    private static final String DELIMITER = ",";

    @Override
    public OutputFormat getFormat() {
        return OutputFormat.CSV;
    }

    @Override
    public String format(ScanReport report) {
        StringBuilder sb = new StringBuilder();

        // Header row
        sb.append("host,ip,hostname,mac,port,protocol,state,service,product,version,banner,response_time_ms");
        sb.append(LINE_SEP);

        // Data rows - one per port
        for (ScanResult host : report.getHostResults()) {
            if (!host.isHostUp()) {
                // Include down hosts with no port data
                appendRow(sb, host, null);
                continue;
            }

            if (host.getPortResults().isEmpty()) {
                // Host up but no ports scanned
                appendRow(sb, host, null);
            } else {
                for (PortResult port : host.getPortResults()) {
                    appendRow(sb, host, port);
                }
            }
        }

        return sb.toString();
    }

    private void appendRow(StringBuilder sb, ScanResult host, PortResult port) {
        // host
        appendField(sb, host.getTarget());
        sb.append(DELIMITER);

        // ip
        appendField(sb, host.getIpAddress());
        sb.append(DELIMITER);

        // hostname
        appendField(sb, host.getHostname());
        sb.append(DELIMITER);

        // mac
        appendField(sb, host.getMacAddress() != null ? host.getMacAddress().toUpperCase() : null);
        sb.append(DELIMITER);

        if (port != null) {
            // port
            sb.append(port.getPort());
            sb.append(DELIMITER);

            // protocol
            appendField(sb, port.getProtocol());
            sb.append(DELIMITER);

            // state
            appendField(sb, port.getState().getDisplayName());
            sb.append(DELIMITER);

            // service
            if (port.hasService()) {
                appendField(sb, port.getService().getServiceName());
                sb.append(DELIMITER);

                // product
                appendField(sb, port.getService().getProduct());
                sb.append(DELIMITER);

                // version
                appendField(sb, port.getService().getVersion());
            } else {
                sb.append(DELIMITER).append(DELIMITER).append(DELIMITER);
            }
            sb.append(DELIMITER);

            // banner
            appendField(sb, port.getBanner());
            sb.append(DELIMITER);

            // response_time_ms
            if (port.getResponseTimeMs() >= 0) {
                sb.append(port.getResponseTimeMs());
            }
        } else {
            // No port data - empty columns
            sb.append(DELIMITER); // port
            sb.append(DELIMITER); // protocol
            appendField(sb, host.isHostUp() ? "up" : "down"); // state
            sb.append(DELIMITER).append(DELIMITER).append(DELIMITER).append(DELIMITER).append(DELIMITER);
        }

        sb.append(LINE_SEP);
    }

    private void appendField(StringBuilder sb, String value) {
        if (value == null) {
            return;
        }

        // Escape and quote if necessary
        boolean needsQuoting = value.contains(",") ||
                               value.contains("\"") ||
                               value.contains("\n") ||
                               value.contains("\r");

        if (needsQuoting) {
            sb.append("\"");
            sb.append(value.replace("\"", "\"\""));
            sb.append("\"");
        } else {
            sb.append(value);
        }
    }

    @Override
    public void formatTo(ScanReport report, OutputStream out) {
        try {
            out.write(SharedStringUtil.getBytes(format(report)));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write CSV output", e);
        }
    }

    @Override
    public void formatTo(ScanReport report, Writer writer) {
        try {
            writer.write(format(report));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write CSV output", e);
        }
    }

    @Override
    public String getMimeType() {
        return "text/csv";
    }
}
