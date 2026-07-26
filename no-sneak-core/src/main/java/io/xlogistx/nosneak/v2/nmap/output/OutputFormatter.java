package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;

/** Renders a {@link ScanReport} to a specific textual format. */
public interface OutputFormatter {

    OutputFormat format();

    String render(ScanReport report);
}
