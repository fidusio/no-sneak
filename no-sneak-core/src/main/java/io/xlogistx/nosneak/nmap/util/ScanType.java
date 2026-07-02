package io.xlogistx.nosneak.nmap.util;

/**
 * Enumeration of supported scan types.
 * Maps to nmap scan type flags.
 */
public enum ScanType {
    // TCP scans
    TCP_CONNECT("-sT", "TCP Connect Scan", "tcp", false),
    SYN("-sS", "TCP SYN Scan", "tcp", true),
    FIN("-sF", "TCP FIN Scan", "tcp", true),
    NULL("-sN", "TCP Null Scan", "tcp", true),
    XMAS("-sX", "TCP Xmas Scan", "tcp", true),
    ACK("-sA", "TCP ACK Scan", "tcp", true),
    WINDOW("-sW", "TCP Window Scan", "tcp", true),
    MAIMON("-sM", "TCP Maimon Scan", "tcp", true),

    // UDP scan
    UDP("-sU", "UDP Scan", "udp", false),

    // Other scans
    IP_PROTOCOL("-sO", "IP Protocol Scan", "ip", true),
    SCTP_INIT("-sY", "SCTP INIT Scan", "sctp", true),
    SCTP_COOKIE("-sZ", "SCTP COOKIE-ECHO Scan", "sctp", true);

    private final String flag;
    private final String description;
    private final String protocol;
    private final boolean requiresRawSockets;

    ScanType(String flag, String description, String protocol, boolean requiresRawSockets) {
        this.flag = flag;
        this.description = description;
        this.protocol = protocol;
        this.requiresRawSockets = requiresRawSockets;
    }

    public String getFlag() {
        return flag;
    }

    public String getDescription() {
        return description;
    }

    public String getProtocol() {
        return protocol;
    }

    public boolean requiresRawSockets() {
        return requiresRawSockets;
    }

    public boolean isTcp() {
        return "tcp".equals(protocol);
    }

    public boolean isUdp() {
        return "udp".equals(protocol);
    }

    /**
     * Parse scan type from flag string (e.g., "-sT", "sT", "TCP_CONNECT")
     */
    public static ScanType parse(String value) {
        if (value == null || value.isEmpty()) {
            return TCP_CONNECT;
        }

        String normalized = value.trim();

        // Try direct enum name match
        try {
            return valueOf(normalized.toUpperCase().replace("-", "_"));
        } catch (IllegalArgumentException ignored) {
        }

        // Try flag match
        for (ScanType type : values()) {
            if (type.flag.equalsIgnoreCase(normalized) ||
                type.flag.substring(1).equalsIgnoreCase(normalized)) {
                return type;
            }
        }

        // Default
        return TCP_CONNECT;
    }

    @Override
    public String toString() {
        return flag + " (" + description + ")";
    }
}
