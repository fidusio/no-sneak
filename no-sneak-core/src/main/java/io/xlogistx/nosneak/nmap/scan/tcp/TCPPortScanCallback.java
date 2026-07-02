package io.xlogistx.nosneak.nmap.scan.tcp;

import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.ConnectException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.function.Consumer;

/**
 * TCP port scan callback for NIOSocket-based scanning.
 * Extends TCPSessionCallback to handle connection events and build PortResult.
 */
public class TCPPortScanCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(TCPPortScanCallback.class).setEnabled(false);

    private final Consumer<PortResult> resultConsumer;
    private final long startTime;
    private final boolean grabBanner;
    private volatile String banner;
    private volatile boolean completed = false;

    /**
     * Create a new TCP port scan callback.
     *
     * @param address        the target address (host:port)
     * @param resultConsumer consumer to receive the scan result
     * @param grabBanner     whether to attempt banner grabbing
     */
    public TCPPortScanCallback(IPAddress address, Consumer<PortResult> resultConsumer, boolean grabBanner) {
        super(address);
        this.resultConsumer = resultConsumer;
        this.grabBanner = grabBanner;
        this.startTime = System.currentTimeMillis();
    }

    /**
     * Called when TCP connection is successfully established.
     * Port is OPEN.
     */
    @Override
    protected void connectedFinished() throws IOException {
        if (completed) return;

        long responseTime = System.currentTimeMillis() - startTime;

        if (log.isEnabled()) {
            log.getLogger().info("Connected to " + getRemoteAddress() + " in " + responseTime + "ms");
        }

        if (grabBanner) {
            // Banner will be collected via accept() if server sends data
            // Give a short window for banner before completing
            // The NIOSocket will call accept() if data arrives
            return; // Don't complete yet, wait for possible banner
        }

        completeWithOpen(responseTime);
    }

    /**
     * Complete the scan as OPEN.
     */
    private synchronized void completeWithOpen(long responseTime) {
        if (completed) return;
        completed = true;

        PortResult result = PortResult.builder(getRemoteAddress().getPort(), "tcp")
                .state(PortState.OPEN)
                .reason("syn-ack")
                .responseTime(responseTime)
                .banner(banner)
                .build();

        resultConsumer.accept(result);
        SharedIOUtil.close(this);
    }

    /**
     * Called when data is received from the server (banner grabbing).
     */
    @Override
    public void accept(ByteBuffer buffer) {
        if (buffer != null && buffer.hasRemaining()) {
            int size = Math.min(buffer.remaining(), 1024);
            byte[] data = new byte[size];
            buffer.get(data);
            banner = new String(data).trim();

            if (log.isEnabled()) {
                log.getLogger().info("Banner from " + getRemoteAddress() + ": " + banner);
            }
        }

        // After receiving banner, complete the scan
        long responseTime = System.currentTimeMillis() - startTime;
        completeWithOpen(responseTime);
    }

    /**
     * Called on connection error.
     * Determines port state based on exception type.
     */
    @Override
    public void exception(Throwable e) {
        if (completed) return;
        completed = true;

        long responseTime = System.currentTimeMillis() - startTime;
        PortState state = PortState.FILTERED;
        String reason = "timeout";

        if (e instanceof ConnectException) {
            state = PortState.CLOSED;
            reason = "conn-refused";
        } else if (e != null && e.getMessage() != null) {
            String msg = e.getMessage().toLowerCase();
            if (msg.contains("refused")) {
                state = PortState.CLOSED;
                reason = "conn-refused";
            } else if (msg.contains("reset")) {
                state = PortState.CLOSED;
                reason = "reset";
            } else if (msg.contains("unreachable") || msg.contains("no route")) {
                state = PortState.FILTERED;
                reason = "no-route";
            }
        }

        if (log.isEnabled()) {
            log.getLogger().info("Exception for " + getRemoteAddress() + ": " + state + " (" + reason + ")");
        }

        PortResult result = PortResult.builder(getRemoteAddress().getPort(), "tcp")
                .state(state)
                .reason(reason)
                .responseTime(responseTime)
                .build();

        resultConsumer.accept(result);
        SharedIOUtil.close(this);
    }

    /**
     * Called on timeout - complete if banner grab pending.
     * This is invoked by NIOSocket when the connection timeout expires.
     */
    public void timeout() {
        if (completed) return;

        // If we connected but were waiting for banner, complete as OPEN
        if (isConnected()) {
            long responseTime = System.currentTimeMillis() - startTime;
            completeWithOpen(responseTime);
        } else {
            // Connection timeout - port is filtered
            exception(new IOException("Connection timeout"));
        }
    }

    /**
     * Check if connection was established.
     */
    private boolean isConnected() {
        try {
            if (getChannel() instanceof SocketChannel) {
                return ((SocketChannel) getChannel()).isConnected();
            }
            return getChannel() != null && getChannel().isOpen();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if this callback has completed.
     */
    public boolean isCompleted() {
        return completed;
    }
}
