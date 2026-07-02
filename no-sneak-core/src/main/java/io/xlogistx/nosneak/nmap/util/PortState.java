package io.xlogistx.nosneak.nmap.util;

/**
 * Port state enumeration matching nmap's port state classifications.
 */
public enum PortState {
    /**
     * Port is accepting connections (TCP) or responding (UDP)
     */
    OPEN("open"),

    /**
     * Port is not accepting connections (RST received for TCP, ICMP unreachable for UDP)
     */
    CLOSED("closed"),

    /**
     * No response received - packet may be dropped by firewall
     */
    FILTERED("filtered"),

    /**
     * Port responds but cannot determine if open or closed (ACK scan)
     */
    UNFILTERED("unfiltered"),

    /**
     * Cannot determine if port is open or filtered (UDP with no response)
     */
    OPEN_FILTERED("open|filtered"),

    /**
     * Cannot determine if port is closed or filtered (rare)
     */
    CLOSED_FILTERED("closed|filtered"),

    /**
     * Scan not performed or error occurred
     */
    UNKNOWN("unknown");

    private final String displayName;

    PortState(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Check if this state indicates the port is accessible
     */
    public boolean isAccessible() {
        return this == OPEN || this == UNFILTERED;
    }

    /**
     * Check if this state indicates potential accessibility
     */
    public boolean isPotentiallyOpen() {
        return this == OPEN || this == OPEN_FILTERED || this == UNFILTERED;
    }

    /**
     * Check if this state indicates the port is definitely closed
     */
    public boolean isDefinitelyClosed() {
        return this == CLOSED;
    }

    /**
     * Check if filtering is detected
     */
    public boolean isFiltered() {
        return this == FILTERED || this == OPEN_FILTERED || this == CLOSED_FILTERED;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
