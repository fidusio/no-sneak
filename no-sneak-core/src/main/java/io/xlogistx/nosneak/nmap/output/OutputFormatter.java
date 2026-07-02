package io.xlogistx.nosneak.nmap.output;

import java.io.OutputStream;
import java.io.Writer;

/**
 * Interface for scan report formatters.
 */
public interface OutputFormatter {

    /**
     * Get the output format this formatter produces
     */
    OutputFormat getFormat();

    /**
     * Format a scan report to a string
     */
    String format(ScanReport report);

    /**
     * Format a scan report to an output stream
     */
    void formatTo(ScanReport report, OutputStream out);

    /**
     * Format a scan report to a writer
     */
    void formatTo(ScanReport report, Writer writer);

    /**
     * Get the MIME type for this format
     */
    String getMimeType();

    /**
     * Check if this formatter supports streaming output
     */
    default boolean supportsStreaming() {
        return false;
    }
}
