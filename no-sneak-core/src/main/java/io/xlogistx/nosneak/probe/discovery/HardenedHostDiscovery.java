package io.xlogistx.nosneak.probe.discovery;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Hardened, non-blocking host detection: fire ICMP and TCP-connect probes to a
 * few common ports in parallel and declare the host <em>up</em> on the first
 * positive from any method. Unlike the sequential/blocking {@code HostDiscovery}
 * chain (which uses {@code java.net.Socket}), the TCP probes run on the shared
 * {@link NIOSocket} event loop.
 * <p>
 * Firewalled-but-up detection: a TCP <em>connection-refused</em> (RST) proves a
 * live host even though the port is closed, so it counts as up. A host that
 * silently drops both ICMP and TCP is reported down after the deadline.
 */
public class HardenedHostDiscovery {

    public static final LogWrapper log = new LogWrapper(HardenedHostDiscovery.class).setEnabled(false);

    /** Ports probed via TCP connect (common, likely-open or likely-RST). */
    public static final int[] TCP_PROBE_PORTS = {443, 80, 22};

    private final NIOSocket nioSocket;
    private final ExecutorService executor;
    private int timeoutSec = 3;

    public HardenedHostDiscovery(NIOSocket nioSocket, ExecutorService executor) {
        this.nioSocket = nioSocket;
        this.executor = executor;
    }

    public HardenedHostDiscovery timeoutInSec(int seconds) {
        this.timeoutSec = seconds > 0 ? seconds : 3;
        return this;
    }

    /**
     * @return a future completing {@code true} on the first positive from any
     *         method (open port, RST, or ICMP echo), or {@code false} at the
     *         deadline if the host is dark.
     */
    public CompletableFuture<Boolean> isUp(String host) {
        CompletableFuture<Boolean> result = new CompletableFuture<>();
        AtomicBoolean done = new AtomicBoolean(false);

        // Finalize 'down' at the deadline unless something reported 'up' first.
        ScheduledFuture<?> deadline = TaskUtil.defaultTaskScheduler().schedule(() -> {
            if (done.compareAndSet(false, true)) {
                result.complete(false);
            }
        }, timeoutSec + 1, TimeUnit.SECONDS);

        Runnable markUp = () -> {
            if (done.compareAndSet(false, true)) {
                try { deadline.cancel(false); } catch (Exception ignored) { }
                result.complete(true);
            }
        };

        // TCP-connect probes on the NIO loop.
        for (int port : TCP_PROBE_PORTS) {
            try {
                nioSocket.addClientSocket(new TcpAliveProbe(new IPAddress(host, port), markUp), timeoutSec);
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("tcp probe launch failed " + host + ":" + port + " " + e.getMessage());
            }
        }

        // ICMP echo (isReachable) on the executor — blocking call kept off the loop.
        executor.execute(() -> {
            try {
                if (InetAddress.getByName(host).isReachable(timeoutSec * 1000)) {
                    markUp.run();
                }
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("icmp probe failed " + host + ": " + e.getMessage());
            }
        });

        return result;
    }

    /**
     * A minimal NIO TCP-connect probe: a successful connect OR a
     * connection-refused (RST) both prove the host is alive.
     */
    private static final class TcpAliveProbe extends TCPSessionCallback {
        private final Runnable markUp;

        private TcpAliveProbe(IPAddress address, Runnable markUp) {
            super(address);
            this.markUp = markUp;
            // No custom close delegate: the parent TCPSessionCallback delegate already
            // closes the channel/output stream on close().
        }

        @Override
        protected void connectedFinished() throws IOException {
            markUp.run();
            try { close(); } catch (Exception ignored) { }
        }

        @Override
        public void accept(ByteBuffer buffer) {
            // Liveness probe: connect/RST is all we need; ignore any payload.
        }

        @Override
        public void exception(Throwable e) {
            // A refused connection (RST) still proves the host is up.
            if (isConnectionRefused(e)) {
                markUp.run();
            }
            try { close(); } catch (Exception ignored) { }
        }

        private static boolean isConnectionRefused(Throwable e) {
            for (Throwable t = e; t != null; t = t.getCause()) {
                String msg = t.getMessage();
                if (msg != null && msg.toLowerCase().contains("refused")) {
                    return true;
                }
            }
            return false;
        }
    }
}
