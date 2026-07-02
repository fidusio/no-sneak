package io.xlogistx.nosneak.nmap.output;

/**
 * Supported output formats for scan results.
 */
public enum OutputFormat {
    /**
     * Normal console output (human-readable)
     */
    NORMAL("-oN", "Normal output", ".txt"),

    /**
     * JSON output
     */
    JSON("-oJ", "JSON output", ".json"),

    /**
     * XML output (nmap-compatible)
     */
    XML("-oX", "XML output", ".xml"),

    /**
     * CSV output
     */
    CSV("-oC", "CSV output", ".csv"),

    /**
     * Grepable output (similar to nmap -oG)
     */
    GREPABLE("-oG", "Grepable output", ".gnmap"),

    /**
     * All formats
     */
    ALL("-oA", "All formats", "");

    private final String flag;
    private final String description;
    private final String extension;

    OutputFormat(String flag, String description, String extension) {
        this.flag = flag;
        this.description = description;
        this.extension = extension;
    }

    public String getFlag() {
        return flag;
    }

    public String getDescription() {
        return description;
    }

    public String getExtension() {
        return extension;
    }

    /**
     * Parse output format from flag or name
     */
    public static OutputFormat parse(String value) {
        if (value == null || value.isEmpty()) {
            return NORMAL;
        }

        String normalized = value.trim().toUpperCase();

        // Try direct name match
        try {
            return valueOf(normalized);
        } catch (IllegalArgumentException ignored) {
        }

        // Try flag match
        for (OutputFormat format : values()) {
            if (format.flag.equalsIgnoreCase(value) ||
                format.flag.substring(1).equalsIgnoreCase(value)) {
                return format;
            }
        }

        return NORMAL;
    }

    /**
     * Get filename with appropriate extension
     */
    public String getFilename(String baseName) {
        return baseName + extension;
    }

    @Override
    public String toString() {
        return flag + " (" + description + ")";
    }
}
