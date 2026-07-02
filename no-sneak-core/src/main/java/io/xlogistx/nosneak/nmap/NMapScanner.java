package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.config.PortSpecification;
import io.xlogistx.nosneak.nmap.config.TargetSpecification;
import io.xlogistx.nosneak.nmap.config.TimingTemplate;
import io.xlogistx.nosneak.nmap.discovery.DiscoveryResult;
import io.xlogistx.nosneak.nmap.discovery.HostDiscovery;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import io.xlogistx.nosneak.nmap.output.ScanReport;
import io.xlogistx.nosneak.nmap.scan.ScanEngine;
import io.xlogistx.nosneak.nmap.util.ScanCache;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.task.ConsumerCallback;

import java.io.Closeable;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main NMap scanner orchestrator.
 * Coordinates scan engines, collects results, and generates reports.
 *
 * All scan engines use pure Java NIO (SocketChannel, DatagramChannel, Selector)
 * and do not require external system commands.
 */
public class NMapScanner implements Closeable {

    public static final LogWrapper log = new LogWrapper(NMapScanner.class).setEnabled(false);

    private final NMapConfig config;
    private final Map<ScanType, ScanEngine> engines;
    //private final ExecutorService executor;
    private final HostDiscovery hostDiscovery;
    private final ScanCache scanCache = new ScanCache();
    private NIOSocket nioSocket;
    private volatile boolean running = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private NMapScanner(ExecutorService executor, NMapConfig config) {
        this(executor, config, null);
    }

    private NMapScanner(ExecutorService executor, NMapConfig config, NIOSocket nioSocket) {
        this.config = config;
        this.engines = new EnumMap<>(ScanType.class);
        //this.executor = executor;
        this.nioSocket = nioSocket;
        this.hostDiscovery = new HostDiscovery(executor, scanCache);
    }

    /**
     * Create a scanner with the given configuration
     */
    public static NMapScanner create(ExecutorService executor, NMapConfig config) {
        return new NMapScanner(executor, config);
    }

    /**
     * Create a scanner with the given configuration and NIOSocket.
     * Using NIOSocket enables efficient callback-based scanning with a shared event loop.
     *
     * @param executor the executor service for async operations
     * @param config the scan configuration
     * @param nioSocket the shared NIOSocket instance for callback-based scanning
     */
    public static NMapScanner create(ExecutorService executor, NMapConfig config, NIOSocket nioSocket) {
        return new NMapScanner(executor, config, nioSocket);
    }

    /**
     * Set the NIOSocket for callback-based scanning.
     * This will be passed to engines that support NIOSocket.
     *
     * @param nioSocket the shared NIOSocket instance
     */
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
        // Update existing engines with the new NIOSocket
        for (ScanEngine engine : engines.values()) {
            engine.setNIOSocket(nioSocket);
        }
    }

    /**
     * Get the NIOSocket instance.
     *
     * @return the NIOSocket, or null if not configured
     */
    public NIOSocket getNIOSocket() {
        return nioSocket;
    }


    /**
     * Register a scan engine for a specific scan type.
     * If NIOSocket is configured, it will be passed to the engine for
     * efficient callback-based scanning.
     */
    public NMapScanner registerEngine(ScanEngine engine) {
        engine.setScanCache(scanCache);
        engine.init(TaskUtil.defaultTaskProcessor(), config);
        // Pass NIOSocket to engine if available
        if (nioSocket != null) {
            engine.setNIOSocket(nioSocket);
        }
        engines.put(engine.getScanType(), engine);
        return this;
    }

    /**
     * Get the engine for a scan type
     */
    public ScanEngine getEngine(ScanType type) {
        return engines.get(type);
    }

    /**
     * Perform the scan according to configuration.
     * This is a BLOCKING convenience method - use scanAsync() for non-blocking.
     */
    public ScanReport scan() {
        return scanAsync().join();
    }

    /**
     * Perform the scan asynchronously using scanStreaming() - no join() or blocking.
     */
    public CompletableFuture<ScanReport> scanAsync() {
        long startTime = System.currentTimeMillis();
        TargetSpecification targets = config.getTargets();
        PortSpecification ports = config.getPorts();
        ScanType primaryType = config.getPrimaryScanType();

        // Collect results as they stream in
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());

        // Use scanStreaming and build report when complete
        return scanStreaming(new ConsumerCallback<ScanResult>() {
            @Override
            public void accept(ScanResult result) {
                if(log.isEnabled())  log.getLogger().info("Scan result: " + result);
                results.add(result);
            }

            @Override
            public void exception(Throwable e) {
                if(log.isEnabled()) log.getLogger().info("Scan error: " + e.getMessage());
            }
        }).thenApply(v -> {
            long endTime = System.currentTimeMillis();

            return ScanReport.builder()
                .config(config)
                .startTime(startTime)
                .endTime(endTime)
                .hostResults(results)
                .addStatistic("total_hosts", targets.getTargetCount())
                .addStatistic("total_ports_per_host", ports.getTotalPortCount())
                .addStatistic("scan_type", primaryType.name())
                .addStatistic("timing", config.getTiming().name())
                .build();
        });
    }

    /**
     * Perform scan with streaming results - callback invoked as each host completes.
     * No join() or blocking - results stream as they become available.
     *
     * @param callback receives each ScanResult as it completes; exception() called on errors
     * @return CompletableFuture that completes when all scans finish
     */
    public CompletableFuture<Void> scanStreaming(ConsumerCallback<ScanResult> callback) {
        if (closed.get()) {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scanner is closed"));
            return future;
        }

        if (running) {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scan already in progress"));
            return future;
        }

        running = true;

        // Handle ping scan only mode (-sn)
        if (config.isPingScanOnly()) {
            return scanPingOnly(callback);
        }

        // Get the primary scan engine
        ScanType primaryType = config.getPrimaryScanType();
        ScanEngine engine = engines.get(primaryType);

        if (engine == null) {
            running = false;
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException(
                "No engine registered for scan type: " + primaryType));
            return future;
        }

        if (!engine.isAvailable()) {
            log.getLogger().info("Engine not available: " + primaryType +
                ", falling back to TCP_CONNECT");
            engine = engines.get(ScanType.TCP_CONNECT);
            if (engine == null) {
                running = false;
                CompletableFuture<Void> future = new CompletableFuture<>();
                future.completeExceptionally(new IllegalStateException("No fallback engine available"));
                return future;
            }
        }

        TargetSpecification targets = config.getTargets();
        List<Integer> portsToScan = getPortsForEngine(engine);
        List<CompletableFuture<Void>> completionFutures = new ArrayList<>();
        final ScanEngine finalEngine = engine;

        for (String target : targets.getTargets()) {
            // Create future for this host
            CompletableFuture<Void> hostFuture;

            if (config.isSkipHostDiscovery()) {
                // Skip host discovery (-Pn), scan directly
                if (log.isEnabled()) {
                    log.getLogger().info("Scanning " + target + " with " + portsToScan.size() + " ports (skip discovery)");
                }
                hostFuture = scanHostDirect(finalEngine, target, portsToScan, callback);
            } else {
                // Do host discovery first
                hostFuture = hostDiscovery.discover(target, config)
                    .thenCompose(discoveryResult -> {
                        if (discoveryResult.isHostUp()) {
                            if (log.isEnabled()) {
                                log.getLogger().info("Host " + target + " is up (" + discoveryResult.getMethod() +
                                    "), scanning " + portsToScan.size() + " ports");
                            }
                            return scanHostDirect(finalEngine, target, portsToScan, callback);
                        } else {
                            // Host is down - report it
                            if (log.isEnabled()) {
                                log.getLogger().info("Host " + target + " is down (" + discoveryResult.getReason() + ")");
                            }
                            ScanResult downResult = ScanResult.builder(target)
                                .resolveAddress()
                                .hostUp(false)
                                .hostUpReason(discoveryResult.getReason())
                                .startTime(System.currentTimeMillis())
                                .endTime(System.currentTimeMillis())
                                .build();
                            try {
                                callback.accept(downResult);
                            } catch (Exception e) {
                                log.getLogger().warning("Callback error for " + target + ": " + e.getMessage());
                            }
                            return CompletableFuture.completedFuture(null);
                        }
                    });
            }

            completionFutures.add(hostFuture);
        }

        // Return a future that completes when ALL hosts are done (but doesn't block)
        return CompletableFuture.allOf(completionFutures.toArray(new CompletableFuture[0]))
            .whenComplete((v, e) -> running = false);
    }

    /**
     * Perform ping scan only - just host discovery, no port scanning.
     * Only reports hosts that are UP (responding).
     * Uses batch discovery for better efficiency with multiple hosts.
     */
    private CompletableFuture<Void> scanPingOnly(ConsumerCallback<ScanResult> callback) {
        TargetSpecification targets = config.getTargets();
        List<String> allTargets = targets.getTargets();

        // Use batch discovery for efficiency
        return hostDiscovery.discoverAll(allTargets, config)
            .thenAccept(results -> {
                long now = System.currentTimeMillis();
                for (Map.Entry<String, DiscoveryResult> entry : results.entrySet()) {
                    String target = entry.getKey();
                    DiscoveryResult discoveryResult = entry.getValue();

                    // Only report hosts that are UP
                    if (discoveryResult.isHostUp()) {
                        ScanResult.Builder builder = ScanResult.builder(target)
                            .resolveAddress()
                            .hostUp(true)
                            .hostUpReason(discoveryResult.getMethod() + " (" + discoveryResult.getReason() + ")")
                            .startTime(now - discoveryResult.getLatencyMs())
                            .endTime(now);
                        if (discoveryResult.getMacAddress() != null) {
                            builder.macAddress(discoveryResult.getMacAddress());
                        }
                        ScanResult result = builder.build();
                        try {
                            callback.accept(result);
                        } catch (Exception e) {
                            log.getLogger().warning("Callback error for " + target + ": " + e.getMessage());
                        }
                    }
                    // Skip hosts that are down - don't report them
                }
            })
            .exceptionally(e -> {
                callback.exception(e instanceof Exception ? (Exception) e : new Exception(e));
                return null;
            })
            .whenComplete((v, e) -> running = false);
    }

    /**
     * Scan a host directly without host discovery.
     */
    private CompletableFuture<Void> scanHostDirect(ScanEngine engine, String target,
            List<Integer> portsToScan, ConsumerCallback<ScanResult> callback) {
        return engine.scanHost(target, portsToScan)
            .thenAccept(result -> {
                try {
                    callback.accept(result);
                } catch (Exception e) {
                    log.getLogger().warning("Callback error for " + target + ": " + e.getMessage());
                }
            })
            .exceptionally(e -> {
                callback.exception(e instanceof Exception ? (Exception) e : new Exception(e));
                return null;
            });
    }

    /**
     * Get ports to scan for the given engine
     */
    private List<Integer> getPortsForEngine(ScanEngine engine) {
        PortSpecification ports = config.getPorts();

        if (engine.getScanType().isTcp()) {
            return ports.getTcpPortList();
        } else if (engine.getScanType().isUdp()) {
            List<Integer> udpPorts = ports.getUdpPortList();
            if (udpPorts.isEmpty()) {
                // Use default top UDP ports when none specified
                return PortSpecification.topUdpPorts(20).getUdpPortList();
            }
            return udpPorts;
        }

        // Default to TCP ports
        return ports.getTcpPortList();
    }

    /**
     * Stop any in-progress scan
     */
    public void stop() {
        for (ScanEngine engine : engines.values()) {
            try {
                engine.close();
            } catch (Exception e) {
                log.getLogger().warning("Error closing engine: " + e.getMessage());
            }
        }
    }

    /**
     * Reset all tracked maps in one shot.
     */
    public void resetCaches() {
        scanCache.reset();
    }

    /**
     * Check if a scan is currently running
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Check if the scanner is closed
     */
    public boolean isClosed() {
        return closed.get();
    }

    /**
     * Get the configuration
     */
    public NMapConfig getConfig() {
        return config;
    }

    /**
     * Get scanner statistics
     */
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("running", running);
        stats.put("closed", closed);
        stats.put("engines", engines.size());

        int totalActive = 0;
        for (ScanEngine engine : engines.values()) {
            totalActive += engine.getActiveScans();
        }
        stats.put("active_scans", totalActive);

        return stats;
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            stop();
            resetCaches();
        }
    }

    /**
     * Builder for creating NMapScanner instances
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final NMapConfig.Builder configBuilder = NMapConfig.builder();
        private final List<ScanEngine> customEngines = new ArrayList<>();
        private NIOSocket nioSocket;

        public Builder target(String target) {
            configBuilder.target(target);
            return this;
        }

        public Builder targets(String... targets) {
            configBuilder.targets(targets);
            return this;
        }

        public Builder ports(String portSpec) {
            configBuilder.ports(portSpec);
            return this;
        }

        public Builder topPorts(int count) {
            configBuilder.topPorts(count);
            return this;
        }

        public Builder scanType(ScanType type) {
            configBuilder.scanType(type);
            return this;
        }

        public Builder timing(TimingTemplate timing) {
            configBuilder.timing(timing);
            return this;
        }

        public Builder timing(String timing) {
            configBuilder.timing(timing);
            return this;
        }

        public Builder timeout(int seconds) {
            configBuilder.timeout(seconds);
            return this;
        }

        public Builder serviceDetection(boolean enable) {
            configBuilder.serviceDetection(enable);
            return this;
        }

        public Builder osDetection(boolean enable) {
            configBuilder.osDetection(enable);
            return this;
        }

        public Builder verbose(boolean enable) {
            configBuilder.verbose(enable);
            return this;
        }

        public Builder outputFormat(OutputFormat format) {
            configBuilder.outputFormat(format);
            return this;
        }

        /**
         * Set the NIOSocket for efficient callback-based scanning.
         * This enables the scanner to use a shared event loop instead of
         * creating per-port selectors.
         *
         * @param nioSocket the shared NIOSocket instance
         */
        public Builder nioSocket(NIOSocket nioSocket) {
            this.nioSocket = nioSocket;
            return this;
        }

        public Builder registerEngine(ScanEngine engine) {
            this.customEngines.add(engine);
            return this;
        }

        public NMapScanner build(ExecutorService executorService) {
            NMapConfig config = configBuilder.build();
            NMapScanner scanner = NMapScanner.create(executorService, config, nioSocket);

            // Register custom engines
            for (ScanEngine engine : customEngines) {
                scanner.registerEngine(engine);
            }

            return scanner;
        }
    }
}
