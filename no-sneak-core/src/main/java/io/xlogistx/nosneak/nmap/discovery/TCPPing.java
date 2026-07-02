package io.xlogistx.nosneak.nmap.discovery;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import org.zoxweb.server.logging.LogWrapper;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * TCP ping discovery method.
 * Attempts TCP connection to common ports to determine if host is up.
 */
public class TCPPing implements DiscoveryMethod {

    public static final LogWrapper log = new LogWrapper(TCPPing.class).setEnabled(false);

    private static final int[] DEFAULT_PORTS = {80, 443, 22, 25, 21};
    private final ExecutorService executor;

    public TCPPing(ExecutorService executor) {
        this.executor = executor;
    }

    @Override
    public String getName() {
        return "TCP Ping";
    }

    @Override
    public String getDescription() {
        return "TCP connection attempt to common ports";
    }

    @Override
    public boolean requiresRawSockets() {
        return false;
    }

    @Override
    public int[] getDefaultPorts() {
        return DEFAULT_PORTS;
    }

    @Override
    public CompletableFuture<DiscoveryResult> isHostUp(String host, NMapConfig config) {
        return CompletableFuture.supplyAsync(() -> {
            int[] ports = config.getDiscoveryPorts();
            if (ports == null || ports.length == 0) {
                ports = DEFAULT_PORTS;
            }

            int timeout = config.getTimeoutSec() * 1000;
            if (timeout <= 0) {
                timeout = 2000;
            }

            for (int port : ports) {
                long start = System.currentTimeMillis();

                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), timeout);
                    long latency = System.currentTimeMillis() - start;

                    if (log.isEnabled()) {
                        log.getLogger().info("TCP ping to " + host + ":" + port + " succeeded");
                    }

                    // Connection succeeded - host is up
                    return DiscoveryResult.up("syn-ack", "tcp-ping:" + port, latency);
                } catch (java.net.ConnectException e) {
                    // Connection refused means host is up but port closed
                    long latency = System.currentTimeMillis() - start;

                    if (log.isEnabled()) {
                        log.getLogger().info("TCP ping to " + host + ":" + port +
                            " - connection refused (host is up)");
                    }

                    return DiscoveryResult.up("conn-refused", "tcp-ping:" + port, latency);
                } catch (Exception e) {
                    // Timeout or other error - try next port
                    if (log.isEnabled()) {
                        log.getLogger().info("TCP ping to " + host + ":" + port +
                            " failed: " + e.getMessage());
                    }
                }
            }

            // All ports failed
            return DiscoveryResult.down("no-response", "tcp-ping");
        }, executor);
    }
}
