package io.xlogistx.nosneak.nmap.scan.udp;

import io.xlogistx.nosneak.nmap.util.PacketDataConst;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanCache;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * UDP port scan callback for NIOSocket-based scanning.
 * Manages multiple pending UDP probes and handles responses.
 *
 * This callback binds to a local ephemeral port and:
 * - Sends probes to target host:port combinations
 * - Receives responses and matches them to pending scans
 * - Handles timeouts for scans that don't receive responses
 */
public class UDPPortScanCallback extends UDPSessionCallback {

    public static final LogWrapper log = new LogWrapper(UDPPortScanCallback.class).setEnabled(false);
    private static final int BUFFER_SIZE = 2048;

    // Track pending scans by remote address — allocated from ScanCache for centralized reset
    private final Map<InetSocketAddress, PendingScan> pendingScans;

    // Scheduler for timeout handling
    private final ScheduledExecutorService timeoutScheduler;
    private final boolean ownScheduler;

    /**
     * Create a UDP port scan callback with a ScanCache for centralized map management.
     */
    public UDPPortScanCallback(ScanCache scanCache) {
        super(null, 0, BUFFER_SIZE); // Bind to ephemeral port
        this.pendingScans = scanCache != null ? scanCache.newMap("udp-scans") : new ConcurrentHashMap<>();
        this.timeoutScheduler = TaskUtil.defaultTaskScheduler();
        this.ownScheduler = false;
    }

    /**
     * Create a UDP port scan callback.
     * Uses a shared scheduler for timeout handling.
     */
    public UDPPortScanCallback(ScheduledExecutorService scheduler) {
        super(null, 0, BUFFER_SIZE); // Bind to ephemeral port
        this.pendingScans = new ConcurrentHashMap<>();
        this.timeoutScheduler = scheduler;
        this.ownScheduler = false;
    }

    /**
     * Create a UDP port scan callback with its own scheduler.
     */
    public UDPPortScanCallback() {
        super(null, 0, BUFFER_SIZE); // Bind to ephemeral port
        this.pendingScans = new ConcurrentHashMap<>();
        this.timeoutScheduler = TaskUtil.defaultTaskScheduler();
        this.ownScheduler = false;
    }

    /**
     * Send a probe to target and register for response.
     *
     * @param host           target host
     * @param port           target port
     * @param timeoutMs      timeout in milliseconds
     * @param resultConsumer consumer to receive the scan result
     */
    public void sendProbe(String host, int port, int timeoutMs, Consumer<PortResult> resultConsumer) {
        long startTime = System.currentTimeMillis();
        InetSocketAddress target = new InetSocketAddress(host, port);

        // Create pending scan entry
        PendingScan pending = new PendingScan(port, startTime, resultConsumer);
        pendingScans.put(target, pending);

        try {
            // Get appropriate probe for the port
            byte[] probe = getProbeForPort(port);
            ByteBuffer buffer;
            if (probe.length > 0) {
                buffer = ByteBuffer.wrap(probe);
            } else {
                // Send minimal packet
                buffer = ByteBuffer.allocate(1);
                buffer.put((byte) 0);
                buffer.flip();
            }

            if (log.isEnabled()) {
                log.getLogger().info("Sending UDP probe to " + host + ":" + port);
            }

            // Send the probe
            send(buffer, target, false);

            // Schedule timeout
            pending.timeoutFuture = timeoutScheduler.schedule(() -> {
                handleTimeout(target);
            }, timeoutMs, TimeUnit.MILLISECONDS);

        } catch (PortUnreachableException e) {
            // ICMP port unreachable - port is closed
            pendingScans.remove(target);
            long responseTime = System.currentTimeMillis() - startTime;
            resultConsumer.accept(PortResult.builder(port, "udp")
                    .state(PortState.CLOSED)
                    .reason("port-unreach")
                    .responseTime(responseTime)
                    .build());
        } catch (IOException e) {
            pendingScans.remove(target);
            long responseTime = System.currentTimeMillis() - startTime;

            String reason = e.getMessage();
            if (reason != null && reason.toLowerCase().contains("unreachable")) {
                resultConsumer.accept(PortResult.builder(port, "udp")
                        .state(PortState.CLOSED)
                        .reason("port-unreach")
                        .responseTime(responseTime)
                        .build());
            } else {
                resultConsumer.accept(PortResult.builder(port, "udp")
                        .state(PortState.OPEN_FILTERED)
                        .reason("error: " + reason)
                        .responseTime(responseTime)
                        .build());
            }
        } catch (RuntimeException e) {
            // Catch-all: e.g. RejectedExecutionException from scheduler.schedule()
            // Without this, the pendingScans entry is orphaned forever
            pendingScans.remove(target);
            long responseTime = System.currentTimeMillis() - startTime;
            resultConsumer.accept(PortResult.builder(port, "udp")
                    .state(PortState.OPEN_FILTERED)
                    .reason("error: " + e.getMessage())
                    .responseTime(responseTime)
                    .build());
        }
    }

    /**
     * Handle incoming UDP response.
     */
    @Override
    public void accept(DataPacket dp) throws IOException {
        InetSocketAddress source = (InetSocketAddress) dp.getAddress();

        if (log.isEnabled()) {
            log.getLogger().info("Received UDP response from " + source);
        }

        PendingScan pending = pendingScans.remove(source);
        if (pending != null) {
            // Cancel timeout
            if (pending.timeoutFuture != null) {
                pending.timeoutFuture.cancel(false);
            }

            long responseTime = System.currentTimeMillis() - pending.startTime;

            // Extract banner from response
            String banner = null;
            ByteBuffer buffer = dp.getBuffer();
            if (buffer != null && buffer.hasRemaining()) {
                byte[] data = ByteBufferUtil.toBytes(buffer, false);
                if (data.length > 0) {
                    banner = new String(data).trim();
                }
            }

            // Port is open - we got a response
            PortResult result = PortResult.builder(pending.port, "udp")
                    .state(PortState.OPEN)
                    .reason("udp-response")
                    .responseTime(responseTime)
                    .banner(banner)
                    .build();

            pending.resultConsumer.accept(result);
        } else {
            if (log.isEnabled()) {
                log.getLogger().info("Received unexpected UDP response from " + source);
            }
        }
    }

    /**
     * Handle ICMP errors or exceptions.
     */
    @Override
    public void exception(Throwable e) {
        if (log.isEnabled()) {
            log.getLogger().info("UDP callback exception: " + e.getMessage());
        }

        // For port unreachable errors, we'd need to match them to pending scans
        // This is tricky because ICMP errors don't always include enough info
        // For now, just log it - timeouts will handle unmatched scans
    }

    /**
     * Handle timeout for a pending scan.
     */
    private void handleTimeout(InetSocketAddress target) {
        PendingScan pending = pendingScans.remove(target);
        if (pending != null) {
            long responseTime = System.currentTimeMillis() - pending.startTime;

            if (log.isEnabled()) {
                log.getLogger().info("UDP scan timeout for port " + pending.port);
            }

            // No response - port is open|filtered
            PortResult result = PortResult.builder(pending.port, "udp")
                    .state(PortState.OPEN_FILTERED)
                    .reason("no-response")
                    .responseTime(responseTime)
                    .build();

            pending.resultConsumer.accept(result);
        }
    }

    /**
     * Get appropriate probe payload for the port.
     */
    private byte[] getProbeForPort(int port) {
        switch (port) {
            case 53:    // DNS
                return PacketDataConst.DNS_PROBE;
            case 161:   // SNMP
            case 162:
                return PacketDataConst.SNMP_PROBE;
            default:
                return Const.EMPTY_BYTE_ARRAY;
        }
    }

    /**
     * Get the number of pending scans.
     */
    public int getPendingCount() {
        return pendingScans.size();
    }

    /**
     * Close the callback and cancel all pending scans.
     */
    @Override
    public void close() throws IOException {
        // Cancel all pending timeouts
        for (PendingScan pending : pendingScans.values()) {
            if (pending.timeoutFuture != null) {
                pending.timeoutFuture.cancel(false);
            }
        }
        pendingScans.clear();

        // Shutdown scheduler if we own it
        if (ownScheduler && timeoutScheduler != null) {
            timeoutScheduler.shutdownNow();
        }

        super.close();
    }

    @Override
    public void sslHandshakeSuccessful() throws IOException {

    }

    /**
     * Tracks a pending UDP scan.
     */
    private static class PendingScan {
        final int port;
        final long startTime;
        final Consumer<PortResult> resultConsumer;
        volatile ScheduledFuture<?> timeoutFuture;

        PendingScan(int port, long startTime, Consumer<PortResult> resultConsumer) {
            this.port = port;
            this.startTime = startTime;
            this.resultConsumer = resultConsumer;
        }
    }
}
