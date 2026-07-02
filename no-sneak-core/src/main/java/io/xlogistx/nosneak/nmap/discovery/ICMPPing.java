package io.xlogistx.nosneak.nmap.discovery;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import org.zoxweb.server.logging.LogWrapper;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * ICMP ping discovery method.
 * Uses Java's InetAddress.isReachable() for ICMP ping.
 * Falls back to TCP ping on common ports if ICMP is blocked.
 */
public class ICMPPing implements DiscoveryMethod {

    public static final LogWrapper log = new LogWrapper(ICMPPing.class).setEnabled(false);

    // Common ports to try for TCP ping fallback
    private static final int[] FALLBACK_PORTS = {80, 443, 22, 21, 25};

    private final ExecutorService executor;

    public ICMPPing(ExecutorService executor) {
        this.executor = executor;
    }

    @Override
    public String getName() {
        return "ICMP Ping";
    }

    @Override
    public String getDescription() {
        return "ICMP echo request via Java InetAddress.isReachable()";
    }

    @Override
    public boolean requiresRawSockets() {
        // InetAddress.isReachable() may use ICMP or TCP echo depending on privileges
        return false;
    }

    @Override
    public CompletableFuture<DiscoveryResult> isHostUp(String host, NMapConfig config) {
        return CompletableFuture.supplyAsync(() -> {
            int timeout = config.getTimeoutSec() * 1000;
            if (timeout <= 0) {
                timeout = 2000;
            }

            // Try Java's isReachable (uses ICMP if privileged, TCP echo port 7 otherwise)
            try {
                long start = System.currentTimeMillis();
                InetAddress addr = InetAddress.getByName(host);
                boolean reachable = addr.isReachable(timeout);
                long latency = System.currentTimeMillis() - start;

                if (reachable) {
                    if (log.isEnabled()) {
                        log.getLogger().info("ICMP ping to " + host + " succeeded via isReachable()");
                    }
                    return DiscoveryResult.up("echo-reply", "icmp", latency);
                }
            } catch (Exception e) {
                if (log.isEnabled()) {
                    log.getLogger().info("InetAddress.isReachable failed: " + e.getMessage());
                }
            }

            // Fallback: Try TCP connection to common ports
            // This is a pure Java alternative when ICMP is blocked
            return tryTcpPingFallback(host, timeout);
        }, executor);
    }

    /**
     * Try TCP connection to common ports as fallback when ICMP is blocked.
     * This is a pure Java approach that doesn't require system commands.
     */
    private DiscoveryResult tryTcpPingFallback(String host, int timeoutMs) {
        for (int port : FALLBACK_PORTS) {
            try {
                long start = System.currentTimeMillis();

                Socket socket = new Socket();
                try {
                    socket.connect(new InetSocketAddress(host, port), timeoutMs);
                    long latency = System.currentTimeMillis() - start;

                    if (log.isEnabled()) {
                        log.getLogger().info("TCP ping to " + host + ":" + port + " succeeded");
                    }

                    // Connection successful - host is up
                    return DiscoveryResult.up("syn-ack", "tcp-ping:" + port, latency);
                } finally {
                    try {
                        socket.close();
                    } catch (Exception ignored) {
                    }
                }
            } catch (java.net.ConnectException e) {
                // Connection refused means host is up but port is closed
                long latency = System.currentTimeMillis();

                if (log.isEnabled()) {
                    log.getLogger().info("TCP ping to " + host + ":" + port +
                        " - connection refused (host is up)");
                }

                return DiscoveryResult.up("conn-refused", "tcp-ping:" + port, latency);
            } catch (Exception e) {
                // Timeout or other error - try next port
                if (log.isEnabled()) {
                    log.getLogger().fine("TCP ping to " + host + ":" + port +
                        " failed: " + e.getMessage());
                }
            }
        }

        return DiscoveryResult.down("no-response", "icmp");
    }
}
