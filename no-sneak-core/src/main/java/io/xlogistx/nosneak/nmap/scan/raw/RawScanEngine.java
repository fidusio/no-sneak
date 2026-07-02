package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.*;
import io.xlogistx.nosneak.nmap.scan.tcp.TCPPortScanCallback;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Abstract base class for scan engines that use TCP connect via NIOSocket.
 *
 * Note: True raw socket scans (SYN-only, FIN, NULL, Xmas) require OS-level
 * raw sockets which Java NIO doesn't support. This implementation uses
 * TCP connect behavior via NIOSocket callbacks to approximate results.
 */
public abstract class RawScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(RawScanEngine.class).setEnabled(false);

    protected NMapConfig config;
    protected ExecutorService executor;
    protected NIOSocket nioSocket;
    protected final AtomicBoolean closed = new AtomicBoolean(false);
    protected final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;
    private boolean grabBanner = false;

    @Override
    public abstract ScanType getScanType();

    @Override
    public String getDescription() {
        return getScanType().getDescription() + " (NIOSocket callback implementation)";
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
    }

    @Override
    public void init(ExecutorService executorService, NMapConfig config) {
        this.config = config;
        this.executor = executorService;
        this.grabBanner = config.isServiceDetection();
        this.parallelismLimiter = new Semaphore(config.getMaxParallelism());
    }

    @Override
    public CompletableFuture<PortResult> scanPort(String host, int port) {
        if (closed.get()) {
            CompletableFuture<PortResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        CompletableFuture<PortResult> future = new CompletableFuture<>();

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
                log.getLogger().info("Scanning " + host + ":" + port + " with NIOSocket (" + getScanType() + ")");
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

        return future;
    }

    @Override
    public CompletableFuture<ScanResult> scanHost(String host, List<Integer> ports) {
        if (closed.get()) {
            CompletableFuture<ScanResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        long startTime = System.currentTimeMillis();

        List<CompletableFuture<PortResult>> futures = new ArrayList<>();

        for (int port : ports) {
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // Rate limiting based on timing template
            long delay = config.getTiming().getProbeDelayMs();
            if (delay > 0) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .handle((v, ex) -> {
                if (ex != null) {
                    return ScanResult.builder(host)
                            .resolveAddress()
                            .hostUp(false)
                            .hostUpReason("error: " + ex.getMessage())
                            .startTime(startTime)
                            .endTime(System.currentTimeMillis())
                            .build();
                }

                List<PortResult> results = new ArrayList<>();
                boolean hostUp = false;

                for (CompletableFuture<PortResult> future : futures) {
                    try {
                        PortResult result = future.join();
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

                long endTime = System.currentTimeMillis();

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
    }

    @Override
    public int getActiveScans() {
        return activeScans.get();
    }

    @Override
    public void close() {
        closed.getAndSet(true);
    }

    @Override
    public ExecutorService getExecutor() {
        return executor;
    }
}
