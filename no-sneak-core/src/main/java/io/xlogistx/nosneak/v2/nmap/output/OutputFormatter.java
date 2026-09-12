package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Renders a {@link ScanReport} to a specific textual format. */
public interface OutputFormatter {

    OutputFormat format();

    String render(ScanReport report);

    /**
     * Renders the report and writes it to {@code out} as UTF-8. The stream is flushed, not
     * closed — the caller owns it. Every format is text, so there is one encoding rule here
     * rather than one per renderer.
     */
    default void formatTo(ScanReport report, OutputStream out) throws IOException {
        out.write(render(report).getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    /** The media type of {@link #render}'s output: {@code text/plain}, {@code application/xml}, {@code application/json} or {@code text/csv}. */
    default String mimeType() {
        return format().mimeType();
    }
}
