package io.xlogistx.nosneak.nmap.config;

import io.xlogistx.nosneak.nmap.util.ScanType;
import io.xlogistx.nosneak.nmap.output.OutputFormat;

import java.util.EnumSet;
import java.util.Set;

/**
 * Main configuration class for NMap scanning.
 * Uses builder pattern for flexible configuration.
 */
public class NMapConfig {

    // Scan type configuration
    private final Set<ScanType> scanTypes;

    // Target configuration
    private final TargetSpecification targets;

    // Port configuration
    private final PortSpecification ports;

    // Timing configuration
    private final TimingTemplate timing;
    private final int timeoutSec;
    private final int maxRetries;
    private final int maxParallelism;

    // Feature flags
    private final boolean serviceDetection;
    private final boolean osDetection;
    private final boolean hostDiscovery;
    private final boolean skipHostDiscovery;
    private final boolean pingScanOnly;
    private final boolean verboseOutput;
    private final boolean debugOutput;

    // Output configuration
    private final Set<OutputFormat> outputFormats;
    private final String outputFile;

    // Discovery configuration
    private final boolean tcpSynPing;
    private final boolean tcpAckPing;
    private final boolean udpPing;
    private final boolean icmpPing;
    private final int[] discoveryPorts;

    private NMapConfig(Builder builder) {
        this.scanTypes = builder.scanTypes.isEmpty()
            ? EnumSet.of(ScanType.TCP_CONNECT)
            : EnumSet.copyOf(builder.scanTypes);
        this.targets = builder.targets;
        this.ports = builder.ports != null ? builder.ports : PortSpecification.defaultPorts();
        this.timing = builder.timing;
        this.timeoutSec = builder.timeoutSec > 0 ? builder.timeoutSec : builder.timing.getTimeoutSec();
        this.maxRetries = builder.maxRetries;
        this.maxParallelism = builder.maxParallelism > 0 ? builder.maxParallelism : builder.timing.getMaxParallelism();
        this.serviceDetection = builder.serviceDetection;
        this.osDetection = builder.osDetection;
        this.hostDiscovery = builder.hostDiscovery;
        this.skipHostDiscovery = builder.skipHostDiscovery;
        this.pingScanOnly = builder.pingScanOnly;
        this.verboseOutput = builder.verboseOutput;
        this.debugOutput = builder.debugOutput;
        this.outputFormats = builder.outputFormats.isEmpty()
            ? EnumSet.of(OutputFormat.NORMAL)
            : EnumSet.copyOf(builder.outputFormats);
        this.outputFile = builder.outputFile;
        this.tcpSynPing = builder.tcpSynPing;
        this.tcpAckPing = builder.tcpAckPing;
        this.udpPing = builder.udpPing;
        this.icmpPing = builder.icmpPing;
        this.discoveryPorts = builder.discoveryPorts;
    }

    // Getters
    public Set<ScanType> getScanTypes() { return scanTypes; }
    public TargetSpecification getTargets() { return targets; }
    public PortSpecification getPorts() { return ports; }
    public TimingTemplate getTiming() { return timing; }
    public int getTimeoutSec() { return timeoutSec; }
    public int getMaxRetries() { return maxRetries; }
    public int getMaxParallelism() { return maxParallelism; }
    public boolean isServiceDetection() { return serviceDetection; }
    public boolean isOsDetection() { return osDetection; }
    public boolean isHostDiscovery() { return hostDiscovery; }
    public boolean isSkipHostDiscovery() { return skipHostDiscovery; }
    public boolean isPingScanOnly() { return pingScanOnly; }
    public boolean isVerboseOutput() { return verboseOutput; }
    public boolean isDebugOutput() { return debugOutput; }
    public Set<OutputFormat> getOutputFormats() { return outputFormats; }
    public String getOutputFile() { return outputFile; }
    public boolean isTcpSynPing() { return tcpSynPing; }
    public boolean isTcpAckPing() { return tcpAckPing; }
    public boolean isUdpPing() { return udpPing; }
    public boolean isIcmpPing() { return icmpPing; }
    public int[] getDiscoveryPorts() { return discoveryPorts; }

    /**
     * Check if any raw socket scan types are requested
     */
    public boolean requiresRawSockets() {
        for (ScanType type : scanTypes) {
            if (type.requiresRawSockets()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the primary scan type (first in set)
     */
    public ScanType getPrimaryScanType() {
        return scanTypes.iterator().next();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Set<ScanType> scanTypes = EnumSet.noneOf(ScanType.class);
        private TargetSpecification targets;
        private PortSpecification ports;
        private TimingTemplate timing = TimingTemplate.T3;
        private int timeoutSec = 0; // 0 means use timing template default
        private int maxRetries = 2;
        private int maxParallelism = 0; // 0 means use timing template default
        private boolean serviceDetection = false;
        private boolean osDetection = false;
        private boolean hostDiscovery = true;
        private boolean skipHostDiscovery = false;
        private boolean pingScanOnly = false;
        private boolean verboseOutput = false;
        private boolean debugOutput = false;
        private Set<OutputFormat> outputFormats = EnumSet.noneOf(OutputFormat.class);
        private String outputFile;
        private boolean tcpSynPing = true;
        private boolean tcpAckPing = false;
        private boolean udpPing = false;
        private boolean icmpPing = false;
        private int[] discoveryPorts = {80, 443};

        public Builder scanType(ScanType type) {
            this.scanTypes.add(type);
            return this;
        }

        public Builder scanTypes(ScanType... types) {
            for (ScanType type : types) {
                this.scanTypes.add(type);
            }
            return this;
        }

        public Builder target(String target) {
            this.targets = TargetSpecification.parse(target);
            return this;
        }

        public Builder targets(String... targets) {
            this.targets = TargetSpecification.parse(targets);
            return this;
        }

        public Builder targets(TargetSpecification targets) {
            this.targets = targets;
            return this;
        }

        public Builder ports(String portSpec) {
            this.ports = PortSpecification.parse(portSpec);
            return this;
        }

        public Builder ports(PortSpecification ports) {
            this.ports = ports;
            return this;
        }

        public Builder topPorts(int count) {
            this.ports = PortSpecification.topPorts(count);
            return this;
        }

        public Builder timing(TimingTemplate timing) {
            this.timing = timing;
            return this;
        }

        public Builder timing(String timing) {
            this.timing = TimingTemplate.parse(timing);
            return this;
        }

        public Builder timeout(int seconds) {
            this.timeoutSec = seconds;
            return this;
        }

        public Builder maxRetries(int retries) {
            this.maxRetries = retries;
            return this;
        }

        public Builder maxParallelism(int parallelism) {
            this.maxParallelism = parallelism;
            return this;
        }

        public Builder serviceDetection(boolean enable) {
            this.serviceDetection = enable;
            return this;
        }

        public Builder osDetection(boolean enable) {
            this.osDetection = enable;
            return this;
        }

        public Builder hostDiscovery(boolean enable) {
            this.hostDiscovery = enable;
            return this;
        }

        public Builder skipHostDiscovery(boolean skip) {
            this.skipHostDiscovery = skip;
            return this;
        }

        public Builder pingScanOnly(boolean enable) {
            this.pingScanOnly = enable;
            return this;
        }

        public Builder verbose(boolean enable) {
            this.verboseOutput = enable;
            return this;
        }

        public Builder debug(boolean enable) {
            this.debugOutput = enable;
            return this;
        }

        public Builder outputFormat(OutputFormat format) {
            this.outputFormats.add(format);
            return this;
        }

        public Builder outputFormats(OutputFormat... formats) {
            for (OutputFormat format : formats) {
                this.outputFormats.add(format);
            }
            return this;
        }

        public Builder outputFile(String file) {
            this.outputFile = file;
            return this;
        }

        public Builder tcpSynPing(boolean enable) {
            this.tcpSynPing = enable;
            return this;
        }

        public Builder tcpAckPing(boolean enable) {
            this.tcpAckPing = enable;
            return this;
        }

        public Builder udpPing(boolean enable) {
            this.udpPing = enable;
            return this;
        }

        public Builder icmpPing(boolean enable) {
            this.icmpPing = enable;
            return this;
        }

        public Builder discoveryPorts(int... ports) {
            this.discoveryPorts = ports;
            return this;
        }

        public NMapConfig build() {
            if (targets == null || targets.isEmpty()) {
                throw new IllegalStateException("At least one target must be specified");
            }
            return new NMapConfig(this);
        }
    }

    @Override
    public String toString() {
        return "NMapConfig{" +
            "scanTypes=" + scanTypes +
            ", targets=" + targets +
            ", ports=" + ports +
            ", timing=" + timing +
            ", serviceDetection=" + serviceDetection +
            ", osDetection=" + osDetection +
            '}';
    }
}
