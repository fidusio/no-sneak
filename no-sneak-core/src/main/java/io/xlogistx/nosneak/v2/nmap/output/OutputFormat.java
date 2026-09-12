package io.xlogistx.nosneak.v2.nmap.output;

/** Supported scan-report output formats (matches the CLI {@code -oN/-oX/-oG/-oJ/-oC} flags). */
public enum OutputFormat {
    NORMAL("txt", "text/plain"),
    JSON("json", "application/json"),
    XML("xml", "application/xml"),
    CSV("csv", "text/csv"),
    GREPABLE("gnmap", "text/plain");

    private final String ext;
    private final String mimeType;

    OutputFormat(String ext, String mimeType) {
        this.ext = ext;
        this.mimeType = mimeType;
    }

    public String extension() {
        return ext;
    }

    /** The media type a consumer should label this format with (no charset parameter; every renderer is UTF-8). */
    public String mimeType() {
        return mimeType;
    }

    public static OutputFormatter formatter(OutputFormat f) {
        switch (f) {
            case JSON:     return new JSONFormatter();
            case XML:      return new XMLFormatter();
            case CSV:      return new CSVFormatter();
            case GREPABLE: return new GrepableFormatter();
            case NORMAL:
            default:       return new NormalFormatter();
        }
    }
}
