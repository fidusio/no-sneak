package io.xlogistx.nosneak.nmap.service;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Interface for service detection probes.
 * Each probe knows how to detect a specific service type.
 */
public interface ServiceProbe {

    /**
     * Get the name of this probe (e.g., "HTTP", "SSH", "FTP")
     */
    String getName();

    /**
     * Get the default ports this probe targets
     */
    int[] getDefaultPorts();

    /**
     * Get the protocol (tcp/udp)
     */
    String getProtocol();

    /**
     * Get probe data to send to the target.
     * Return null if probe just listens for banner (passive probe).
     */
    byte[] getProbeData();

    /**
     * Analyze response data and attempt to match service
     * @param response the response data from the target
     * @return matched service or empty if no match
     */
    Optional<ServiceMatch> analyze(ByteBuffer response);

    /**
     * Analyze response string (convenience method)
     */
    default Optional<ServiceMatch> analyze(String response) {
        if (response == null) return Optional.empty();
        return analyze(ByteBuffer.wrap(response.getBytes()));
    }

    /**
     * Get probe priority (higher = tried first)
     */
    default int getPriority() {
        return 50;
    }

    /**
     * Check if this is a passive probe (just reads banner, sends nothing)
     */
    default boolean isPassive() {
        return getProbeData() == null;
    }

    /**
     * Get timeout in milliseconds for this probe
     */
    default int getTimeoutMs() {
        return 5000;
    }
}
