package io.xlogistx.nosneak.nmap.discovery;

import io.xlogistx.nosneak.nmap.config.NMapConfig;

import java.util.concurrent.CompletableFuture;

/**
 * Interface for host discovery methods.
 */
public interface DiscoveryMethod {

    /**
     * Get the name of this discovery method
     */
    String getName();

    /**
     * Get a description of this method
     */
    String getDescription();

    /**
     * Check if this method requires raw sockets (root privileges)
     */
    boolean requiresRawSockets();

    /**
     * Check if the host is up
     *
     * @param host the target host
     * @param config scan configuration
     * @return future completing with true if host is up
     */
    CompletableFuture<DiscoveryResult> isHostUp(String host, NMapConfig config);

    /**
     * Get the default ports used for discovery (if applicable)
     */
    default int[] getDefaultPorts() {
        return new int[]{80, 443};
    }
}
