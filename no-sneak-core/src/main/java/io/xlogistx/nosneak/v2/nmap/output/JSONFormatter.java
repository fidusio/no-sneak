package io.xlogistx.nosneak.v2.nmap.output;

import io.xlogistx.nosneak.v2.nmap.ScanReport;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * JSON output: the report's {@link ScanReport#toNVGenericMap()} rendered by the house
 * serialiser, the same way {@code ProbeResult} and the REST endpoint render theirs.
 * <p>
 * This used to be a hand-written writer with its own string escaper (a straight port of v1's).
 * Two JSON serialisers in one module meant two places for escaping bugs and two shapes to keep
 * in sync; now the shape is declared once, on the report, and Gson does the escaping. Absent
 * facts are absent, not {@code null}: an unmeasured RTT has no {@code rttMs} key, a host with
 * no MAC has no {@code mac} key.
 */
public final class JSONFormatter implements OutputFormatter {

    @Override
    public OutputFormat format() {
        return OutputFormat.JSON;
    }

    @Override
    public String render(ScanReport r) {
        try {
            // printNull=true: with it off, Gson also drops default-valued primitives, and a
            // `cancelled: false` or `up: false` that vanishes is the tri-state trap this repo
            // already met once (see the NVBoolean note in the memory and ProbeResult). The map
            // never holds a null, so nothing else changes.
            return GSONUtil.toJSONGenericMap(r.toNVGenericMap(), true, true, false);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
