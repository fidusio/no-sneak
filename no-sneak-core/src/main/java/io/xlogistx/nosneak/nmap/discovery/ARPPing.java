package io.xlogistx.nosneak.nmap.discovery;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.util.ScanCache;
import org.zoxweb.server.logging.LogWrapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * ARP-based host discovery for local networks.
 * Uses system ARP cache and triggers ARP by attempting connections.
 * This is more effective than TCP ping on local networks.
 */
public class ARPPing implements DiscoveryMethod {

    public static final LogWrapper log = new LogWrapper(ARPPing.class).setEnabled(false);

    private final ExecutorService executor;
    private final Map<String, String> arpCache;

    public ARPPing(ExecutorService executor, ScanCache scanCache) {
        this.executor = executor;
        this.arpCache = scanCache.newMap("arp-cache");
    }

    @Override
    public String getName() {
        return "ARP Ping";
    }

    @Override
    public String getDescription() {
        return "ARP-based discovery using system ARP cache";
    }

    @Override
    public boolean requiresRawSockets() {
        return false;
    }

    @Override
    public CompletableFuture<DiscoveryResult> isHostUp(String host, NMapConfig config) {
        return CompletableFuture.supplyAsync(() -> {
            int timeout = config.getTimeoutSec() * 1000;
            if (timeout <= 0) {
                timeout = 2000;
            }

            long start = System.currentTimeMillis();

            try {
                // Step 1: Try to trigger ARP by sending packets to multiple ports
                // This causes the OS to do ARP resolution
                triggerArp(host, timeout);

                // Step 2: Force refresh ARP cache after triggering
                // Small delay to allow ARP to complete
                Thread.sleep(50);
                refreshArpCache();

                InetAddress addr = InetAddress.getByName(host);
                String ip = addr.getHostAddress();

                if (arpCache.containsKey(ip)) {
                    long latency = System.currentTimeMillis() - start;
                    if (log.isEnabled()) {
                        log.getLogger().info("ARP: " + host + " found in ARP cache");
                    }
                    return DiscoveryResult.up("arp-response", "arp", latency, arpCache.get(ip));
                }

                // Step 3: Also try isReachable which may use ICMP
                if (addr.isReachable(timeout)) {
                    long latency = System.currentTimeMillis() - start;
                    return DiscoveryResult.up("echo-reply", "arp", latency);
                }

            } catch (Exception e) {
                if (log.isEnabled()) {
                    log.getLogger().info("ARP ping failed for " + host + ": " + e.getMessage());
                }
            }

            return DiscoveryResult.down("no-response", "arp");
        }, executor);
    }

    // Common ports to try for ARP trigger - any connection attempt triggers ARP
    private static final int[] TRIGGER_PORTS = {80, 443, 22, 135, 445, 139, 21, 23, 25, 53, 8080};

    /**
     * Trigger ARP resolution by attempting connections to multiple ports.
     * We don't need the connection to succeed - just sending the SYN
     * packet causes the OS to do ARP resolution.
     */
    private void triggerArp(String host, int timeout) {
        // Use a short timeout since we don't care if connections succeed
        int quickTimeout = Math.min(timeout, 200);

        // Try multiple ports in parallel to maximize chance of triggering ARP
        CompletableFuture<?>[] futures = new CompletableFuture[TRIGGER_PORTS.length + 1];

        for (int i = 0; i < TRIGGER_PORTS.length; i++) {
            final int port = TRIGGER_PORTS[i];
            futures[i] = CompletableFuture.runAsync(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), quickTimeout);
                } catch (Exception ignored) {
                    // We don't care if connection fails - ARP was triggered
                }
            }, executor);
        }

        // Also try isReachable which may use ICMP
        futures[TRIGGER_PORTS.length] = CompletableFuture.runAsync(() -> {
            try {
                InetAddress addr = InetAddress.getByName(host);
                addr.isReachable(quickTimeout);
            } catch (Exception ignored) {
            }
        }, executor);

        // Wait for all triggers to complete (or timeout) - use join() after orTimeout()
        try {
            CompletableFuture.allOf(futures)
                .orTimeout(quickTimeout + 100, java.util.concurrent.TimeUnit.MILLISECONDS)
                .join();
        } catch (Exception ignored) {
            // Timeout or other errors are expected and ignored
        }
    }

    /**
     * Refresh the ARP cache from the system.
     */
    private synchronized void refreshArpCache() {
        arpCache.clear();

        try {
            ProcessBuilder pb;
            String os = System.getProperty("os.name").toLowerCase();

            if (os.contains("windows")) {
                pb = new ProcessBuilder("arp", "-a");
            } else {
                // Linux/Mac
                pb = new ProcessBuilder("arp", "-n");
            }

            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;
                boolean isWindows = os.contains("windows");
                while ((line = reader.readLine()) != null) {
                    // Parse IP and MAC addresses from ARP output
                    // Windows format: "  10.0.0.1            00-1a-2b-3c-4d-5e     dynamic"
                    // Linux format:   "10.0.0.1              ether   00:1a:2b:3c:4d:5e   C   eth0"

                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        String potentialIp = parts[0];
                        // Check if it looks like an IP address
                        if (potentialIp.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                            // Extract MAC address
                            String mac = null;
                            if (isWindows && parts.length >= 2) {
                                // Windows: MAC is in parts[1], format 00-1a-2b-3c-4d-5e
                                String candidate = parts[1];
                                if (candidate.matches("[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5}")) {
                                    mac = candidate.replace('-', ':').toLowerCase();
                                }
                            } else if (parts.length >= 3) {
                                // Linux: MAC is in parts[2], format 00:1a:2b:3c:4d:5e
                                String candidate = parts[2];
                                if (candidate.matches("[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}")) {
                                    mac = candidate.toLowerCase();
                                }
                            }
                            arpCache.put(potentialIp, mac);
                        }
                    }
                }
            }

            process.waitFor();

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to read ARP cache: " + e.getMessage());
            }
        }
    }

    /**
     * Get all known hosts from ARP cache (IP -> MAC address).
     */
    public Map<String, String> getArpCacheHosts() {
        refreshArpCache();
        return new HashMap<>(arpCache);
    }

    /**
     * Batch trigger ARP for multiple hosts in parallel.
     * This is more efficient than individual host triggers.
     * @param hosts List of hosts to trigger ARP for
     * @param timeoutMs Timeout for each trigger attempt
     */
    public void batchTriggerArp(List<String> hosts, int timeoutMs) {
        int quickTimeout = Math.min(timeoutMs, 200);

        // Trigger ARP for all hosts in parallel
        List<CompletableFuture<?>> allFutures = new ArrayList<>();

        for (String host : hosts) {
            // Just try one fast port per host for batch mode
            allFutures.add(CompletableFuture.runAsync(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, 80), quickTimeout);
                } catch (Exception ignored) {
                }
            }, executor));

            // Also try isReachable (ICMP if possible)
            allFutures.add(CompletableFuture.runAsync(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    addr.isReachable(quickTimeout);
                } catch (Exception ignored) {
                }
            }, executor));
        }

        // Wait for all triggers (with overall timeout) - use join() after orTimeout()
        try {
            CompletableFuture.allOf(allFutures.toArray(new CompletableFuture[0]))
                .orTimeout(timeoutMs + 1000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .join();
        } catch (Exception ignored) {
            // Timeout or other errors are expected and ignored
        }

        // Wait briefly for ARP resolution
        try {
            Thread.sleep(100);
        } catch (InterruptedException ignored) {
        }

        // Force refresh cache after batch trigger
        refreshArpCache();
    }

    /**
     * Batch discover multiple hosts efficiently.
     * First triggers ARP for all hosts, then checks cache, then falls back to individual checks.
     * @return Map of host to discovery result (only hosts that are UP)
     */
    public CompletableFuture<Map<String, DiscoveryResult>> batchDiscover(List<String> hosts, NMapConfig config) {
        return CompletableFuture.supplyAsync(() -> {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();

            // Step 1: Batch trigger ARP for all hosts
            long triggerStart = System.currentTimeMillis();
            batchTriggerArp(hosts, config.getTimeoutSec() * 1000);
            long triggerDuration = System.currentTimeMillis() - triggerStart;

            // Step 2: Check which hosts are in ARP cache (IP -> MAC)
            Map<String, String> cachedHosts = getArpCacheHosts();

            // Estimate per-host latency based on trigger duration / hosts found
            // This is approximate since we don't know exact response times for each host
            int foundCount = 0;
            for (String host : hosts) {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    String ip = addr.getHostAddress();
                    if (cachedHosts.containsKey(ip)) {
                        foundCount++;
                    }
                } catch (Exception ignored) {
                }
            }

            // Estimate average latency per host
            long estimatedLatencyMs = foundCount > 0 ? Math.min(triggerDuration / foundCount, 100) : 10;

            for (String host : hosts) {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    String ip = addr.getHostAddress();

                    if (cachedHosts.containsKey(ip)) {
                        // Use estimated latency for ARP-discovered hosts, include MAC
                        String mac = cachedHosts.get(ip);
                        results.put(host, DiscoveryResult.up("arp-response", "arp", estimatedLatencyMs, mac));
                    }
                } catch (Exception ignored) {
                }
            }

            return results;
        }, executor);
    }
}
