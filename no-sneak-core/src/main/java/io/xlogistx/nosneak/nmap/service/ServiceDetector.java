package io.xlogistx.nosneak.nmap.service;

import io.xlogistx.nosneak.nmap.service.probes.*;
import org.zoxweb.server.logging.LogWrapper;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

/**
 * Service detection orchestrator.
 * Runs probes against open ports to identify services.
 */
public class ServiceDetector {

    public static final LogWrapper log = new LogWrapper(ServiceDetector.class).setEnabled(false);

    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int BUFFER_SIZE = 4096;

    private final List<ServiceProbe> probes;
    private final ExecutorService executor;
    private final int timeoutMs;

    public ServiceDetector(ExecutorService executor) {
        this(executor, DEFAULT_TIMEOUT_MS);
    }

    public ServiceDetector(ExecutorService executor, int timeoutMs) {
        this.timeoutMs = timeoutMs;
        this.probes = new ArrayList<>();
        this.executor = executor;

        // Register default probes
        registerDefaultProbes();
    }

    private void registerDefaultProbes() {
        // Order matters - higher priority probes run first
        probes.add(new GenericBannerProbe());
        probes.add(new HTTPProbe());
        probes.add(new SSHProbe());
        probes.add(new FTPProbe());
        probes.add(new SMTPProbe());
        probes.add(new TLSProbe());

        // Sort by priority (highest first)
        probes.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
    }

    /**
     * Register a custom probe
     */
    public void registerProbe(ServiceProbe probe) {
        probes.add(probe);
        probes.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
    }

    /**
     * Detect service on the given host:port
     */
    public CompletableFuture<ServiceMatch> detect(String host, int port) {
        return CompletableFuture.supplyAsync(() -> {
            // First, try passive detection (read banner)
            ServiceMatch match = tryPassiveDetection(host, port);
            if (match != null) {
                return match;
            }

            // Try active probes
            for (ServiceProbe probe : probes) {
                if (!probe.isPassive()) {
                    match = tryActiveProbe(host, port, probe);
                    if (match != null) {
                        return match;
                    }
                }
            }

            // Fall back to well-known port lookup
            return ServiceMatch.fromPort(port, "tcp");
        }, executor);
    }

    /**
     * Detect services on multiple ports (non-blocking)
     */
    public CompletableFuture<Map<Integer, ServiceMatch>> detectAll(String host, List<Integer> ports) {
        Map<Integer, CompletableFuture<ServiceMatch>> futures = new LinkedHashMap<>();

        for (int port : ports) {
            // Add timeout to each detection
            futures.put(port, detect(host, port)
                .orTimeout(timeoutMs * 2, TimeUnit.MILLISECONDS)
                .exceptionally(e -> {
                    if (log.isEnabled()) {
                        log.getLogger().info("Service detection failed for port " + port + ": " + e.getMessage());
                    }
                    return null;
                }));
        }

        // Wait for all futures without blocking
        return CompletableFuture.allOf(futures.values().toArray(new CompletableFuture[0]))
            .thenApply(v -> {
                Map<Integer, ServiceMatch> results = new LinkedHashMap<>();
                for (Map.Entry<Integer, CompletableFuture<ServiceMatch>> entry : futures.entrySet()) {
                    try {
                        // Use join() - futures are already complete after allOf()
                        ServiceMatch match = entry.getValue().join();
                        if (match != null) {
                            results.put(entry.getKey(), match);
                        }
                    } catch (Exception e) {
                        // Already handled in exceptionally above
                    }
                }
                return results;
            });
    }

    /**
     * Try passive detection (just connect and read banner)
     */
    private ServiceMatch tryPassiveDetection(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(timeoutMs);
            socket.connect(new InetSocketAddress(host, port), timeoutMs);

            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[BUFFER_SIZE];

            // Wait for data with shorter timeout
            socket.setSoTimeout(2000);
            int bytesRead = in.read(buffer);

            if (bytesRead > 0) {
                ByteBuffer data = ByteBuffer.wrap(buffer, 0, bytesRead);

                // Try each passive probe
                for (ServiceProbe probe : probes) {
                    if (probe.isPassive()) {
                        Optional<ServiceMatch> match = probe.analyze(data.duplicate());
                        if (match.isPresent()) {
                            return match.get();
                        }
                    }
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Passive detection failed: " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Try an active probe (send data and analyze response)
     */
    private ServiceMatch tryActiveProbe(String host, int port, ServiceProbe probe) {
        byte[] probeData = probe.getProbeData();
        if (probeData == null) {
            return null;
        }

        try (Socket socket = new Socket()) {
            socket.setSoTimeout(probe.getTimeoutMs());
            socket.connect(new InetSocketAddress(host, port), timeoutMs);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Send probe
            out.write(probeData);
            out.flush();

            // Read response
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead = in.read(buffer);

            if (bytesRead > 0) {
                ByteBuffer data = ByteBuffer.wrap(buffer, 0, bytesRead);
                Optional<ServiceMatch> match = probe.analyze(data);
                if (match.isPresent()) {
                    return match.get();
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Active probe " + probe.getName() +
                    " failed: " + e.getMessage());
            }
        }

        return null;
    }

}
