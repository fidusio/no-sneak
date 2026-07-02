package io.xlogistx.nosneak.nmap.output;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanResult;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Complete scan report containing all scan results.
 */
public class ScanReport {

    public static final String SCANNER_NAME = "XNMap";
    public static final String SCANNER_VERSION = "1.0.0";

    private final String scannerVersion;
    private final long startTimeMs;
    private final long endTimeMs;
    private final NMapConfig config;
    private final List<ScanResult> hostResults;
    private final Map<String, Object> statistics;
    private final List<String> warnings;
    private final String commandLine;

    private ScanReport(Builder builder) {
        this.scannerVersion = SCANNER_VERSION;
        this.startTimeMs = builder.startTimeMs;
        this.endTimeMs = builder.endTimeMs;
        this.config = builder.config;
        this.hostResults = Collections.unmodifiableList(new ArrayList<>(builder.hostResults));
        this.statistics = builder.statistics != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.statistics))
            : Collections.emptyMap();
        this.warnings = builder.warnings != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.warnings))
            : Collections.emptyList();
        this.commandLine = builder.commandLine;
    }

    // Getters
    public String getScannerName() { return SCANNER_NAME; }
    public String getScannerVersion() { return scannerVersion; }
    public long getStartTimeMs() { return startTimeMs; }
    public long getEndTimeMs() { return endTimeMs; }
    public NMapConfig getConfig() { return config; }
    public List<ScanResult> getHostResults() { return hostResults; }
    public Map<String, Object> getStatistics() { return statistics; }
    public List<String> getWarnings() { return warnings; }
    public String getCommandLine() { return commandLine; }

    /**
     * Get scan duration in milliseconds
     */
    public long getDurationMs() {
        return endTimeMs - startTimeMs;
    }

    /**
     * Get scan duration in seconds
     */
    public double getDurationSec() {
        return getDurationMs() / 1000.0;
    }

    /**
     * Get formatted start time
     */
    public String getStartTimeFormatted() {
        return formatTime(startTimeMs);
    }

    /**
     * Get formatted end time
     */
    public String getEndTimeFormatted() {
        return formatTime(endTimeMs);
    }

    /**
     * Get number of hosts scanned
     */
    public int getHostCount() {
        return hostResults.size();
    }

    /**
     * Get number of hosts that are up
     */
    public int getHostsUpCount() {
        return (int) hostResults.stream().filter(ScanResult::isHostUp).count();
    }

    /**
     * Get number of hosts that are down
     */
    public int getHostsDownCount() {
        return (int) hostResults.stream().filter(r -> !r.isHostUp()).count();
    }

    /**
     * Get total number of open ports across all hosts
     */
    public int getTotalOpenPorts() {
        return hostResults.stream().mapToInt(ScanResult::getOpenPortCount).sum();
    }

    /**
     * Get total number of closed ports across all hosts
     */
    public int getTotalClosedPorts() {
        return hostResults.stream().mapToInt(ScanResult::getClosedPortCount).sum();
    }

    /**
     * Get total number of filtered ports across all hosts
     */
    public int getTotalFilteredPorts() {
        return hostResults.stream().mapToInt(ScanResult::getFilteredPortCount).sum();
    }

    /**
     * Get hosts that have open ports
     */
    public List<ScanResult> getHostsWithOpenPorts() {
        List<ScanResult> result = new ArrayList<>();
        for (ScanResult host : hostResults) {
            if (host.getOpenPortCount() > 0) {
                result.add(host);
            }
        }
        return result;
    }

    /**
     * Get port statistics by state
     */
    public Map<PortState, Integer> getPortStateCounts() {
        Map<PortState, Integer> counts = new EnumMap<>(PortState.class);
        for (ScanResult host : hostResults) {
            for (PortResult port : host.getPortResults()) {
                counts.merge(port.getState(), 1, Integer::sum);
            }
        }
        return counts;
    }

    /**
     * Get summary string for quick overview
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append(SCANNER_NAME).append(" done: ");
        sb.append(getHostCount()).append(" IP address");
        if (getHostCount() != 1) sb.append("es");
        sb.append(" (").append(getHostsUpCount()).append(" host");
        if (getHostsUpCount() != 1) sb.append("s");
        sb.append(" up) scanned in ");
        sb.append(String.format("%.2f", getDurationSec())).append(" seconds");
        return sb.toString();
    }

    private String formatTime(long timeMs) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(timeMs));
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private long startTimeMs = System.currentTimeMillis();
        private long endTimeMs = System.currentTimeMillis();
        private NMapConfig config;
        private List<ScanResult> hostResults = new ArrayList<>();
        private Map<String, Object> statistics;
        private List<String> warnings;
        private String commandLine;

        public Builder startTime(long ms) {
            this.startTimeMs = ms;
            return this;
        }

        public Builder endTime(long ms) {
            this.endTimeMs = ms;
            return this;
        }

        public Builder config(NMapConfig config) {
            this.config = config;
            return this;
        }

        public Builder addHostResult(ScanResult result) {
            this.hostResults.add(result);
            return this;
        }

        public Builder hostResults(List<ScanResult> results) {
            this.hostResults = new ArrayList<>(results);
            return this;
        }

        public Builder statistics(Map<String, Object> stats) {
            this.statistics = stats;
            return this;
        }

        public Builder addStatistic(String key, Object value) {
            if (this.statistics == null) {
                this.statistics = new HashMap<>();
            }
            this.statistics.put(key, value);
            return this;
        }

        public Builder addWarning(String warning) {
            if (this.warnings == null) {
                this.warnings = new ArrayList<>();
            }
            this.warnings.add(warning);
            return this;
        }

        public Builder commandLine(String cmd) {
            this.commandLine = cmd;
            return this;
        }

        public ScanReport build() {
            return new ScanReport(this);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Starting ").append(SCANNER_NAME).append(" ").append(scannerVersion);
        sb.append(" at ").append(getStartTimeFormatted()).append("\n");

        if (commandLine != null) {
            sb.append("Command: ").append(commandLine).append("\n");
        }

        sb.append("\n");

        for (ScanResult host : hostResults) {
            sb.append(host.toString()).append("\n");
        }

        sb.append("\n").append(getSummary());

        return sb.toString();
    }
}
