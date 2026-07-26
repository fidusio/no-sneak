package io.xlogistx.nosneak.v2.nmap;

/**
 * Port states (nmap semantics). TCP-connect yields OPEN / CLOSED / FILTERED; UDP adds
 * OPEN_FILTERED (no response — could be open or filtered).
 */
public enum PortState {
    OPEN("open"),
    CLOSED("closed"),
    FILTERED("filtered"),
    UNFILTERED("unfiltered"),
    OPEN_FILTERED("open|filtered"),
    CLOSED_FILTERED("closed|filtered"),
    UNKNOWN("unknown");

    private final String label;

    PortState(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean isOpen() {
        return this == OPEN;
    }

    public boolean isPotentiallyOpen() {
        return this == OPEN || this == OPEN_FILTERED || this == UNFILTERED;
    }
}
