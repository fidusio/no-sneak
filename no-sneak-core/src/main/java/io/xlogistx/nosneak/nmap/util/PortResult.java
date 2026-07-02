package io.xlogistx.nosneak.nmap.util;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;

/**
 * Result of scanning a single port.
 */
public class PortResult {

    private final int port;
    private final String protocol;  // tcp, udp
    private final PortState state;
    private final String reason;    // syn-ack, rst, timeout, etc.
    private final long responseTimeMs;
    private final ServiceMatch service;
    private final String banner;
    private final int ttl;

    private PortResult(Builder builder) {
        this.port = builder.port;
        this.protocol = builder.protocol;
        this.state = builder.state;
        this.reason = builder.reason;
        this.responseTimeMs = builder.responseTimeMs;
        this.service = builder.service;
        this.banner = builder.banner;
        this.ttl = builder.ttl;
    }

    // Getters
    public int getPort() { return port; }
    public String getProtocol() { return protocol; }
    public PortState getState() { return state; }
    public String getReason() { return reason; }
    public long getResponseTimeMs() { return responseTimeMs; }
    public ServiceMatch getService() { return service; }
    public String getBanner() { return banner; }
    public int getTtl() { return ttl; }

    public boolean isOpen() {
        return state == PortState.OPEN;
    }

    public boolean isClosed() {
        return state == PortState.CLOSED;
    }

    public boolean isFiltered() {
        return state.isFiltered();
    }

    public boolean hasService() {
        return service != null;
    }

    public boolean hasBanner() {
        return banner != null && !banner.isEmpty();
    }

    // Factory methods for common cases
    public static PortResult open(int port, String protocol) {
        return builder(port, protocol)
            .state(PortState.OPEN)
            .reason("syn-ack")
            .build();
    }

    public static PortResult open(int port, String protocol, String reason) {
        return builder(port, protocol)
            .state(PortState.OPEN)
            .reason(reason)
            .build();
    }

    public static PortResult closed(int port, String protocol) {
        return builder(port, protocol)
            .state(PortState.CLOSED)
            .reason("conn-refused")
            .build();
    }

    public static PortResult closed(int port, String protocol, String reason) {
        return builder(port, protocol)
            .state(PortState.CLOSED)
            .reason(reason)
            .build();
    }

    public static PortResult filtered(int port, String protocol) {
        return builder(port, protocol)
            .state(PortState.FILTERED)
            .reason("no-response")
            .build();
    }

    public static PortResult filtered(int port, String protocol, String reason) {
        return builder(port, protocol)
            .state(PortState.FILTERED)
            .reason(reason)
            .build();
    }

    public static PortResult openFiltered(int port, String protocol) {
        return builder(port, protocol)
            .state(PortState.OPEN_FILTERED)
            .reason("no-response")
            .build();
    }

    public static PortResult error(int port, String protocol, String reason) {
        return builder(port, protocol)
            .state(PortState.UNKNOWN)
            .reason(reason)
            .build();
    }

    public static Builder builder(int port, String protocol) {
        return new Builder(port, protocol);
    }

    public static class Builder {
        private final int port;
        private final String protocol;
        private PortState state = PortState.UNKNOWN;
        private String reason;
        private long responseTimeMs = -1;
        private ServiceMatch service;
        private String banner;
        private int ttl = -1;

        public Builder(int port, String protocol) {
            this.port = port;
            this.protocol = protocol;
        }

        public Builder state(PortState state) {
            this.state = state;
            return this;
        }

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder responseTime(long ms) {
            this.responseTimeMs = ms;
            return this;
        }

        public Builder service(ServiceMatch service) {
            this.service = service;
            return this;
        }

        public Builder banner(String banner) {
            this.banner = banner;
            return this;
        }

        public Builder ttl(int ttl) {
            this.ttl = ttl;
            return this;
        }

        public PortResult build() {
            return new PortResult(this);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(port).append("/").append(protocol);
        sb.append(" ").append(state);
        if (reason != null) {
            sb.append(" (").append(reason).append(")");
        }
        if (service != null) {
            sb.append(" ").append(service.getServiceName());
            if (service.getVersion() != null) {
                sb.append(" ").append(service.getVersion());
            }
        }
        if (responseTimeMs >= 0) {
            sb.append(" [").append(responseTimeMs).append("ms]");
        }
        return sb.toString();
    }
}
