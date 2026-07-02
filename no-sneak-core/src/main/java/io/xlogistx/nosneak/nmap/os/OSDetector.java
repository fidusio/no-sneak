package io.xlogistx.nosneak.nmap.os;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.discovery.ICMPPing;
import io.xlogistx.nosneak.nmap.util.PortResult;
import org.zoxweb.server.logging.LogWrapper;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * OS detection based on TCP/IP stack analysis.
 * Uses TTL values, TCP window sizes, and other heuristics.
 */
public class OSDetector {

    public static final LogWrapper log = new LogWrapper(OSDetector.class).setEnabled(false);

    private final ExecutorService executor;
    private final ICMPPing icmpPing;

    public OSDetector(ExecutorService executor) {
        this.executor = executor;
        this.icmpPing = new ICMPPing(executor);
    }

    /**
     * Detect OS for a host (non-blocking)
     */
    public CompletableFuture<OSFingerprint> detect(String host, NMapConfig config) {
        // Get TTL from ping - chain futures instead of blocking
        return icmpPing.isHostUp(host, config)
            .orTimeout(config.getTimeoutSec(), TimeUnit.SECONDS)
            .thenApply(pingResult -> {
                OSFingerprint.Builder builder = OSFingerprint.builder();

                if (pingResult.isHostUp() && pingResult.getTtl() > 0) {
                    builder.ttl(pingResult.getTtl());

                    // Guess OS from TTL
                    String osGuess = guessFromTtl(pingResult.getTtl());
                    if (osGuess != null) {
                        builder.addMatch(osGuess, 70);
                    }
                }

                return builder.build();
            })
            .exceptionally(e -> {
                if (log.isEnabled()) {
                    log.getLogger().info("Failed to get TTL: " + e.getMessage());
                }
                return OSFingerprint.builder().build();
            });
    }

    /**
     * Enhance OS detection with port scan results
     */
    public OSFingerprint enhanceWithPorts(OSFingerprint initial, List<PortResult> ports) {
        OSFingerprint.Builder builder = OSFingerprint.builder();

        // Copy TTL if available
        if (initial.getTtl() > 0) {
            builder.ttl(initial.getTtl());
        }

        // Analyze open ports for OS hints
        boolean hasSmb = false;
        boolean hasRdp = false;
        boolean hasSsh = false;
        boolean hasIis = false;
        boolean hasApache = false;

        for (PortResult port : ports) {
            if (!port.isOpen()) continue;

            switch (port.getPort()) {
                case 445:
                case 139:
                case 135:
                    hasSmb = true;
                    break;
                case 3389:
                    hasRdp = true;
                    break;
                case 22:
                    hasSsh = true;
                    break;
            }

            // Check service detection
            if (port.hasService()) {
                String product = port.getService().getProduct();
                if (product != null) {
                    String lower = product.toLowerCase();
                    if (lower.contains("iis") || lower.contains("microsoft")) {
                        hasIis = true;
                    } else if (lower.contains("apache") || lower.contains("nginx")) {
                        hasApache = true;
                    }
                }
            }
        }

        // Score based on port heuristics
        if (hasRdp || (hasSmb && hasIis)) {
            builder.addMatch("Windows", 85);
        } else if (hasSmb && !hasSsh) {
            builder.addMatch("Windows", 60);
        } else if (hasSsh && !hasSmb) {
            builder.addMatch("Linux", 70);
        } else if (hasSsh && hasApache) {
            builder.addMatch("Linux", 75);
        }

        // Add TTL-based guess if not already matched
        if (initial.getTtl() > 0) {
            String ttlGuess = guessFromTtl(initial.getTtl());
            if (ttlGuess != null) {
                // Add with lower confidence since we already have other info
                builder.addMatch(ttlGuess, 50);
            }
        }

        return builder.build();
    }

    /**
     * Guess OS family from TTL value
     */
    private String guessFromTtl(int ttl) {
        // Common initial TTL values:
        // Linux/Unix: 64
        // Windows: 128
        // Cisco/Network devices: 255

        if (ttl <= 64) {
            return "Linux/Unix (TTL <= 64)";
        } else if (ttl <= 128) {
            return "Windows (TTL <= 128)";
        } else {
            return "Network Device (TTL > 128)";
        }
    }

}
