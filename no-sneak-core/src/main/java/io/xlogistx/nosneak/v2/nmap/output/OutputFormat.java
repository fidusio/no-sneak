package io.xlogistx.nosneak.v2.nmap.output;

/** Supported scan-report output formats (matches the CLI {@code -oN/-oX/-oG/-oJ/-oC} flags). */
public enum OutputFormat {
    NORMAL("txt"),
    JSON("json"),
    XML("xml"),
    CSV("csv"),
    GREPABLE("gnmap");

    private final String ext;

    OutputFormat(String ext) {
        this.ext = ext;
    }

    public String extension() {
        return ext;
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
