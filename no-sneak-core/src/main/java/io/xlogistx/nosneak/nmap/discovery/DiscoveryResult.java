package io.xlogistx.nosneak.nmap.discovery;

/**
 * Result of a host discovery attempt.
 */
public class DiscoveryResult {

    private final boolean hostUp;
    private final String reason;
    private final String method;
    private final long latencyMs;
    private final int ttl;
    private final String macAddress;

    private DiscoveryResult(boolean hostUp, String reason, String method, long latencyMs, int ttl, String macAddress) {
        this.hostUp = hostUp;
        this.reason = reason;
        this.method = method;
        this.latencyMs = latencyMs;
        this.ttl = ttl;
        this.macAddress = macAddress;
    }

    public boolean isHostUp() {
        return hostUp;
    }

    public String getReason() {
        return reason;
    }

    public String getMethod() {
        return method;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public int getTtl() {
        return ttl;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public static DiscoveryResult up(String reason, String method, long latencyMs) {
        return new DiscoveryResult(true, reason, method, latencyMs, -1, null);
    }

    public static DiscoveryResult up(String reason, String method, long latencyMs, String macAddress) {
        return new DiscoveryResult(true, reason, method, latencyMs, -1, macAddress);
    }

    public static DiscoveryResult up(String reason, String method, long latencyMs, int ttl) {
        return new DiscoveryResult(true, reason, method, latencyMs, ttl, null);
    }

    public static DiscoveryResult down(String reason, String method) {
        return new DiscoveryResult(false, reason, method, -1, -1, null);
    }

    @Override
    public String toString() {
        if (hostUp) {
            return "Host is up (" + reason + ") via " + method +
                   (latencyMs >= 0 ? " [" + latencyMs + "ms]" : "");
        }
        return "Host is down (" + reason + ")";
    }
}
