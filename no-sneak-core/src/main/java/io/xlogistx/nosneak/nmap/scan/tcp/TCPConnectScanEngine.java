package io.xlogistx.nosneak.nmap.scan.tcp;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.*;
import io.xlogistx.nosneak.nmap.util.*;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TCP Connect scan engine implementation using NIOSocket callbacks.
 * Uses shared NIOSocket event loop for efficient non-blocking TCP connections.
 */
public class TCPConnectScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(TCPConnectScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private ExecutorService executor;
    private NIOSocket nioSocket;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;
    private boolean grabBanner = true;

    // Track pending results by host — allocated from ScanCache for centralized reset
    private Map<String, List<CompletableFuture<PortResult>>> pendingByHost = new ConcurrentHashMap<>();

    @Override
    public ScanType getScanType() {
        return ScanType.TCP_CONNECT;
    }

    @Override
    public String getDescription() {
        return "TCP Connect Scan - NIO callback-based TCP connection to each port";
    }

    @Override
    public boolean isAvailable() {
        // TCP connect scan is always available (no raw sockets required)
        return true;
    }

    @Override
    public void setScanCache(ScanCache scanCache) {
        this.pendingByHost = scanCache.newMap("tcp-pending");
    }

    @Override
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
    }

    @Override
    public void init(ExecutorService executor, NMapConfig config) {
        if (initialized) {
            throw new IllegalStateException("Engine already initialized");
        }

        this.config = config;
        this.grabBanner = config.isServiceDetection();
        this.parallelismLimiter = new Semaphore(config.getMaxParallelism());
        this.executor = executor;
        this.initialized = true;

        if (log.isEnabled()) {
            log.getLogger().info("TCPConnectScanEngine initialized with parallelism: " +
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

            IPAddress address = new IPAddress(host, port);
            TCPPortScanCallback callback = new TCPPortScanCallback(
                    address,
                    result -> {
                        activeScans.decrementAndGet();
                        parallelismLimiter.release();
                        future.complete(result);
                    },
                    grabBanner
            );

            int timeoutSec = config.getTimeoutSec();
            if (timeoutSec <= 0) {
                timeoutSec = 5;
            }

            if (log.isEnabled()) {
                log.getLogger().info("Scanning " + host + ":" + port + " with NIOSocket");
            }

            nioSocket.addClientSocket(callback, timeoutSec);

        } catch (InterruptedException e) {
            // acquire() threw before we incremented or acquired — don't release/decrement
            Thread.currentThread().interrupt();
            future.complete(PortResult.error(port, "tcp", "interrupted"));
        } catch (Exception e) {
            activeScans.decrementAndGet();
            parallelismLimiter.release();

            if (log.isEnabled()) {
                log.getLogger().warning("Error scanning " + host + ":" + port + ": " + e.getMessage());
            }

            future.complete(PortResult.error(port, "tcp", e.getMessage()));
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
                log.getLogger().info("Scanning port " + port);
            }
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // Apply delay between probes if configured
            if (config.getTiming().getProbeDelayMs() > 0) {
                try {
                    Thread.sleep(config.getTiming().getProbeDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
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
                        log.getLogger().warning("Port scan failed: " + e.getMessage());
                    }
                }
            }

            return ScanResult.builder(host)
                    .resolveAddress()
                    .hostUp(hostUp)
                    .hostUpReason(hostUp ? "tcp-response" : "no-response")
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
