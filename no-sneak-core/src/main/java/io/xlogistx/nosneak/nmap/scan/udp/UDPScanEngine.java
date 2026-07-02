package io.xlogistx.nosneak.nmap.scan.udp;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.ScanEngine;
import io.xlogistx.nosneak.nmap.util.*;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.io.SharedIOUtil;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * UDP scan engine implementation using NIOSocket callbacks.
 * Uses shared NIOSocket event loop for efficient non-blocking UDP scanning.
 */
public class UDPScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(UDPScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private ExecutorService executor;
    //private NIOSocket nioSocket;
    private ScanCache scanCache;
    private UDPPortScanCallback scanCallback;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;

    // Track pending results by host — allocated from ScanCache for centralized reset
    private Map<String, List<CompletableFuture<PortResult>>> pendingByHost = new ConcurrentHashMap<>();




    @Override
    public ScanType getScanType() {
        return ScanType.UDP;
    }

    @Override
    public String getDescription() {
        return "UDP Scan - NIO callback-based UDP probes to detect open ports";
    }

    @Override
    public boolean isAvailable() {
        // UDP scan is always available (no raw sockets required)
        return true;
    }

    @Override
    public void setScanCache(ScanCache scanCache) {
        this.scanCache = scanCache;
        this.pendingByHost = scanCache.newMap("udp-pending");
    }

    @Override
    public void setNIOSocket(NIOSocket nioSocket) {
        //this.nioSocket = nioSocket;

        // Create and register the UDP scan callback
        if (nioSocket != null && scanCallback == null) {
            try {
                scanCallback = new UDPPortScanCallback(scanCache);
                scanCallback.setExecutor(nioSocket.getExecutor());
                nioSocket.addDatagramSocket(scanCallback);

                if (log.isEnabled()) {
                    log.getLogger().info("UDP scan callback registered with NIOSocket");
                }
            } catch (IOException e) {
                log.getLogger().warning("Failed to register UDP callback: " + e.getMessage());
                scanCallback = null;
            }
        }
    }

    @Override
    public void init(ExecutorService executor, NMapConfig config) {
        if (initialized) {
            throw new IllegalStateException("Engine already initialized");
        }

        this.config = config;
        this.parallelismLimiter = new Semaphore(config.getMaxParallelism());
        this.executor = executor;
        this.initialized = true;

        if (log.isEnabled()) {
            log.getLogger().info("UDPScanEngine initialized with parallelism: " +
                    config.getMaxParallelism());
        }
    }

    @Override
    public CompletableFuture<PortResult> scanPort(String host, int port) {
        checkInitialized();

        if (closed.get()) {
            CompletableFuture<PortResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        CompletableFuture<PortResult> future = new CompletableFuture<>();
        scanPortWithNIOSocket(host, port, future);
        return future;
    }

    /**
     * Scan port using NIOSocket callback pattern (non-blocking).
     */
    private void scanPortWithNIOSocket(String host, int port, CompletableFuture<PortResult> future) {
        try {
            parallelismLimiter.acquire();
            activeScans.incrementAndGet();

            int timeoutMs = config.getTimeoutSec() * 1000;
            if (timeoutMs <= 0) {
                timeoutMs = 10000; // 10 second default for UDP
            }

            if (log.isEnabled()) {
                log.getLogger().info("Scanning UDP " + host + ":" + port + " with NIOSocket");
            }

            scanCallback.sendProbe(host, port, timeoutMs, result -> {
                activeScans.decrementAndGet();
                parallelismLimiter.release();
                future.complete(result);
            });

        } catch (InterruptedException e) {
            // acquire() threw before we incremented or acquired — don't release/decrement
            Thread.currentThread().interrupt();
            future.complete(PortResult.error(port, "udp", "interrupted"));
        } catch (Exception e) {
            activeScans.decrementAndGet();
            parallelismLimiter.release();

            if (log.isEnabled()) {
                log.getLogger().warning("Error scanning UDP " + host + ":" + port + ": " + e.getMessage());
            }

            future.complete(PortResult.error(port, "udp", e.getMessage()));
        }
    }

    @Override
    public CompletableFuture<ScanResult> scanHost(String host, List<Integer> ports) {
        checkInitialized();

        if (closed.get()) {
            CompletableFuture<ScanResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        long startTime = System.currentTimeMillis();

        List<CompletableFuture<PortResult>> futures = new ArrayList<>();

        for (int port : ports) {
            if (log.isEnabled()) {
                log.getLogger().info("Scanning UDP port " + port);
            }
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // UDP scans typically need more delay to avoid overwhelming
            long delay = config.getTiming().getProbeDelayMs();
            if (delay <= 0) {
                delay = 100; // Minimum 100ms between UDP probes
            }

            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        pendingByHost.put(host, futures);

        CompletableFuture<Void> allOf = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0])
        );

        return allOf.handle((v, ex) -> {
            // Guaranteed cleanup — runs on both success and failure
            pendingByHost.remove(host);

            if (ex != null) {
                return ScanResult.builder(host)
                        .resolveAddress()
                        .hostUp(false)
                        .hostUpReason("error: " + ex.getMessage())
                        .startTime(startTime)
                        .endTime(System.currentTimeMillis())
                        .build();
            }

            long endTime = System.currentTimeMillis();

            List<PortResult> results = new ArrayList<>();
            boolean hostUp = false;

            for (CompletableFuture<PortResult> future : futures) {
                try {
                    PortResult result = future.join();
                    if (log.isEnabled()) {
                        log.getLogger().info("Result: " + result);
                    }
                    results.add(result);
                    if (result.isOpen() || result.isClosed()) {
                        hostUp = true;
                    }
                } catch (Exception e) {
                    if (log.isEnabled()) {
                        log.getLogger().warning("UDP port scan failed: " + e.getMessage());
                    }
                }
            }

            return ScanResult.builder(host)
                    .resolveAddress()
                    .hostUp(hostUp)
                    .hostUpReason(hostUp ? "udp-response" : "no-response")
                    .startTime(startTime)
                    .endTime(endTime)
                    .portResults(results)
                    .build();
        });
    }

    @Override
    public void stop() {
        for (List<CompletableFuture<PortResult>> futures : pendingByHost.values()) {
            for (CompletableFuture<PortResult> future : futures) {
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
        }
        pendingByHost.clear();
    }

    @Override
    public int getActiveScans() {
        return activeScans.get();
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            stop();
            // Close the scan callback
            SharedIOUtil.close(scanCallback);
            scanCallback = null;
        }
    }

    @Override
    public ExecutorService getExecutor() {
        return executor;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Engine not initialized. Call init() first.");
        }
    }
}
