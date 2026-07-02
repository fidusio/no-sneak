package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.util.*;

/**
 * JSON output formatter using GSONUtil.
 */
public class JSONFormatter implements OutputFormatter {

    private final boolean prettyPrint;

    public JSONFormatter() {
        this(true);
    }

    public JSONFormatter(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    @Override
    public OutputFormat getFormat() {
        return OutputFormat.JSON;
    }

    @Override
    public String format(ScanReport report) {
        Map<String, Object> json = buildJsonStructure(report);
        return GSONUtil.toJSONDefault(json, prettyPrint);
    }

    @Override
    public void formatTo(ScanReport report, OutputStream out) {
        try {
            out.write(SharedStringUtil.getBytes(format(report)));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write JSON output", e);
        }
    }

    @Override
    public void formatTo(ScanReport report, Writer writer) {
        try {
            writer.write(format(report));
        } catch (IOException e) {
            throw new RuntimeException("Failed to write JSON output", e);
        }
    }

    @Override
    public String getMimeType() {
        return "application/json";
    }

    private Map<String, Object> buildJsonStructure(ScanReport report) {
        Map<String, Object> root = new LinkedHashMap<>();

        // Scan info
        Map<String, Object> scanInfo = new LinkedHashMap<>();
        scanInfo.put("scanner", report.getScannerName());
        scanInfo.put("version", report.getScannerVersion());
        scanInfo.put("startTime", report.getStartTimeMs());
        scanInfo.put("startTimeFormatted", report.getStartTimeFormatted());
        scanInfo.put("endTime", report.getEndTimeMs());
        scanInfo.put("endTimeFormatted", report.getEndTimeFormatted());
        scanInfo.put("durationMs", report.getDurationMs());
        scanInfo.put("durationSec", report.getDurationSec());

        if (report.getCommandLine() != null) {
            scanInfo.put("commandLine", report.getCommandLine());
        }

        root.put("scanInfo", scanInfo);

        // Summary statistics
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalHosts", report.getHostCount());
        summary.put("hostsUp", report.getHostsUpCount());
        summary.put("hostsDown", report.getHostsDownCount());
        summary.put("totalOpenPorts", report.getTotalOpenPorts());
        summary.put("totalClosedPorts", report.getTotalClosedPorts());
        summary.put("totalFilteredPorts", report.getTotalFilteredPorts());
        root.put("summary", summary);

        // Host results
        List<Map<String, Object>> hosts = new ArrayList<>();
        for (ScanResult hostResult : report.getHostResults()) {
            hosts.add(buildHostJson(hostResult));
        }
        root.put("hosts", hosts);

        // Warnings
        if (!report.getWarnings().isEmpty()) {
            root.put("warnings", report.getWarnings());
        }

        // Additional statistics
        if (!report.getStatistics().isEmpty()) {
            root.put("statistics", report.getStatistics());
        }

        return root;
    }

    private Map<String, Object> buildHostJson(ScanResult host) {
        Map<String, Object> hostJson = new LinkedHashMap<>();

        hostJson.put("target", host.getTarget());
        if (host.getIpAddress() != null) {
            hostJson.put("ipAddress", host.getIpAddress());
        }
        if (host.getHostname() != null) {
            hostJson.put("hostname", host.getHostname());
        }
        hostJson.put("hostUp", host.isHostUp());
        if (host.getHostUpReason() != null) {
            hostJson.put("hostUpReason", host.getHostUpReason());
        }
        if (host.getMacAddress() != null) {
            hostJson.put("macAddress", host.getMacAddress().toUpperCase());
        }

        hostJson.put("startTime", host.getStartTimeMs());
        hostJson.put("endTime", host.getEndTimeMs());
        hostJson.put("durationMs", host.getDurationMs());

        // Port statistics
        Map<String, Object> portStats = new LinkedHashMap<>();
        portStats.put("total", host.getTotalPortCount());
        portStats.put("open", host.getOpenPortCount());
        portStats.put("closed", host.getClosedPortCount());
        portStats.put("filtered", host.getFilteredPortCount());
        hostJson.put("portStats", portStats);

        // Port details
        List<Map<String, Object>> ports = new ArrayList<>();
        for (PortResult port : host.getPortResults()) {
            ports.add(buildPortJson(port));
        }
        hostJson.put("ports", ports);

        // OS detection
        if (host.getOsFingerprint() != null) {
            Map<String, Object> os = new LinkedHashMap<>();
            os.put("ttl", host.getOsFingerprint().getTtl());
            if (host.getOsFingerprint().getBestMatch() != null) {
                os.put("guess", host.getOsFingerprint().getBestMatch().getOsName());
                os.put("accuracy", host.getOsFingerprint().getBestMatch().getAccuracy());
            }
            hostJson.put("os", os);
        }

        // Extra info
        if (!host.getExtraInfo().isEmpty()) {
            hostJson.put("extraInfo", host.getExtraInfo());
        }

        return hostJson;
    }

    private Map<String, Object> buildPortJson(PortResult port) {
        Map<String, Object> portJson = new LinkedHashMap<>();

        portJson.put("port", port.getPort());
        portJson.put("protocol", port.getProtocol());
        portJson.put("state", port.getState().getDisplayName());

        if (port.getReason() != null) {
            portJson.put("reason", port.getReason());
        }

        if (port.getResponseTimeMs() >= 0) {
            portJson.put("responseTimeMs", port.getResponseTimeMs());
        }

        if (port.getTtl() >= 0) {
            portJson.put("ttl", port.getTtl());
        }

        // Service info
        if (port.hasService()) {
            Map<String, Object> service = new LinkedHashMap<>();
            service.put("name", port.getService().getServiceName());
            if (port.getService().getProduct() != null) {
                service.put("product", port.getService().getProduct());
            }
            if (port.getService().getVersion() != null) {
                service.put("version", port.getService().getVersion());
            }
            if (port.getService().getExtraInfo() != null) {
                service.put("extraInfo", port.getService().getExtraInfo());
            }
            if (port.getService().getMethod() != null) {
                service.put("method", port.getService().getMethod());
            }
            service.put("confidence", port.getService().getConfidence());
            portJson.put("service", service);
        }

        if (port.hasBanner()) {
            portJson.put("banner", port.getBanner());
        }

        return portJson;
    }
}
