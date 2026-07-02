package io.xlogistx.nosneak.nmap.discovery;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.util.ScanCache;
import org.zoxweb.server.logging.LogWrapper;

import java.util.*;
import java.util.concurrent.*;

/**
 * Host discovery orchestrator.
 * Runs multiple discovery methods to determine if hosts are up.
 */
public class HostDiscovery {

    public static final LogWrapper log = new LogWrapper(HostDiscovery.class).setEnabled(false);

    private final List<DiscoveryMethod> methods;
    //private final ExecutorService executor;

    public HostDiscovery(ExecutorService executor, ScanCache scanCache) {
        this.methods = new ArrayList<>();
        //  this.executor = executor;

        // Register default methods - ARP first for local networks
        methods.add(new ARPPing(executor, scanCache));
        methods.add(new TCPPing(executor));
        methods.add(new ICMPPing(executor));
    }

    /**
     * Register a custom discovery method
     */
    public void registerMethod(DiscoveryMethod method) {
        methods.add(method);
    }

    /**
     * Discover if a host is up using all available methods.
     * Tries methods sequentially without blocking - chains futures together.
     */
    public CompletableFuture<DiscoveryResult> discover(String host, NMapConfig config) {
        if (config.isSkipHostDiscovery()) {
            return CompletableFuture.completedFuture(
                DiscoveryResult.up("user-set", "skip", 0)
            );
        }

        // Build a chain of method attempts - try each method, if it fails or returns down, try next
        CompletableFuture<DiscoveryResult> chain = CompletableFuture.completedFuture(
            DiscoveryResult.down("not-started", "none")
        );

        for (DiscoveryMethod method : methods) {
            // Skip raw socket methods if not available
            if (method.requiresRawSockets()) {
                continue;
            }

            final DiscoveryMethod currentMethod = method;
            chain = chain.thenCompose(previousResult -> {
                // If previous method found host up, return that result
                if (previousResult.isHostUp()) {
                    return CompletableFuture.completedFuture(previousResult);
                }

                // Try current method with timeout
                return currentMethod.isHostUp(host, config)
                    .orTimeout(config.getTimeoutSec(), TimeUnit.SECONDS)
                    .exceptionally(e -> {
                        if (log.isEnabled()) {
                            log.getLogger().info("Discovery method " + currentMethod.getName() +
                                " failed: " + e.getMessage());
                        }
                        return DiscoveryResult.down("error", currentMethod.getName());
                    });
            });
        }

        // If all methods failed, return down
        return chain.thenApply(result -> {
            if (!result.isHostUp() && "not-started".equals(result.getReason())) {
                return DiscoveryResult.down("no-response", "all-methods");
            }
            return result;
        });
    }

    /**
     * Discover multiple hosts using batch ARP discovery for efficiency.
     * First does batch ARP trigger, then falls back to individual methods.
     * Fully non-blocking implementation.
     */
    public CompletableFuture<Map<String, DiscoveryResult>> discoverAll(
            List<String> hosts, NMapConfig config) {

        // Skip host discovery if configured
        if (config.isSkipHostDiscovery()) {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();
            for (String host : hosts) {
                results.put(host, DiscoveryResult.up("user-set", "skip", 0));
            }
            return CompletableFuture.completedFuture(results);
        }

        // Find ARPPing method
        ARPPing arpPing = null;
        for (DiscoveryMethod method : methods) {
            if (method instanceof ARPPing) {
                arpPing = (ARPPing) method;
                break;
            }
        }

        // Step 1: Batch ARP discovery (non-blocking)
        CompletableFuture<Map<String, DiscoveryResult>> arpFuture;
        if (arpPing != null) {
            arpFuture = arpPing.batchDiscover(hosts, config)
                .orTimeout(config.getTimeoutSec() * 2, TimeUnit.SECONDS)
                .exceptionally(e -> {
                    if (log.isEnabled()) {
                        log.getLogger().info("Batch ARP discovery failed: " + e.getMessage());
                    }
                    return new LinkedHashMap<>();
                });
        } else {
            arpFuture = CompletableFuture.completedFuture(new LinkedHashMap<>());
        }

        // Step 2: After ARP completes, discover remaining hosts in parallel
        return arpFuture.thenCompose(arpResults -> {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();
            Set<String> hostsFoundByArp = new HashSet<>();

            // Collect ARP results
            for (Map.Entry<String, DiscoveryResult> entry : arpResults.entrySet()) {
                if (entry.getValue().isHostUp()) {
                    results.put(entry.getKey(), entry.getValue());
                    hostsFoundByArp.add(entry.getKey());
                }
            }

            // Find remaining hosts
            List<String> remainingHosts = new ArrayList<>();
            for (String host : hosts) {
                if (!hostsFoundByArp.contains(host)) {
                    remainingHosts.add(host);
                }
            }

            if (remainingHosts.isEmpty()) {
                return CompletableFuture.completedFuture(results);
            }

            // Launch discovery for all remaining hosts in parallel
            Map<String, CompletableFuture<DiscoveryResult>> futures = new LinkedHashMap<>();
            for (String host : remainingHosts) {
                futures.put(host, discover(host, config));
            }

            // Wait for all and collect results
            CompletableFuture<Void> allOf = CompletableFuture.allOf(
                futures.values().toArray(new CompletableFuture[0])
            );

            return allOf.thenApply(v -> {
                for (Map.Entry<String, CompletableFuture<DiscoveryResult>> entry : futures.entrySet()) {
                    try {
                        // Use join() - futures are already complete after allOf()
                        DiscoveryResult result = entry.getValue().join();
                        results.put(entry.getKey(), result);
                    } catch (Exception e) {
                        results.put(entry.getKey(),
                            DiscoveryResult.down("error: " + e.getMessage(), "error"));
                    }
                }
                return results;
            });
        });
    }

    /**
     * Get hosts that are up
     */
    public CompletableFuture<List<String>> getUpHosts(List<String> hosts, NMapConfig config) {
        return discoverAll(hosts, config).thenApply(results -> {
            List<String> upHosts = new ArrayList<>();
            for (Map.Entry<String, DiscoveryResult> entry : results.entrySet()) {
                if (entry.getValue().isHostUp()) {
                    upHosts.add(entry.getKey());
                }
            }
            return upHosts;
        });
    }

}
