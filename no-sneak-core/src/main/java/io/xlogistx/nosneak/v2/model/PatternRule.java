package io.xlogistx.nosneak.v2.model;

import java.util.regex.Pattern;

/**
 * A single pattern-match rule inside an {@code expect}/{@code starttls} state.
 * Deserialized directly from JSON via {@code GSONUtil.fromJSONDefault}.
 * <p>
 * {@code regex} is matched (via {@link java.util.regex.Matcher#find()}) against
 * the accumulated inbound bytes; on the first match the engine fires the
 * transition labelled {@code outcome}. An optional {@code capture} records a regex
 * capture group as a service fact (see {@code ProbeContext.captureFact}).
 */
public class PatternRule {

    private String regex;
    private String outcome;

    // Optional service-fact extraction: when this rule matches, the regex capture
    // group `group` (default 1; 0 = whole match) is recorded on the ProbeResult
    // under the fact name `capture` (e.g. "version", "product", "banner"),
    // serialized as "service-<capture>". Absent `capture` => no extraction.
    private String capture;
    private Integer group;

    // Lazily-compiled, cached pattern (transient: not part of the JSON model).
    private transient Pattern compiled;

    public PatternRule() {
    }

    public PatternRule(String regex, String outcome) {
        this.regex = regex;
        this.outcome = outcome;
    }

    public String getRegex() {
        return regex;
    }

    public String getOutcome() {
        return outcome;
    }

    /** The service-fact name to record on a match, or {@code null} to extract nothing. */
    public String getCapture() {
        return capture;
    }

    /** The regex capture-group index for {@link #getCapture()} (default 1; 0 = whole match). */
    public int getCaptureGroup() {
        return group == null ? 1 : group;
    }

    /**
     * The compiled {@link Pattern}, built once and cached. Uses DOTALL so a
     * banner spanning several lines is treated as one blob.
     */
    public Pattern pattern() {
        Pattern p = compiled;
        if (p == null) {
            p = Pattern.compile(regex, Pattern.DOTALL);
            compiled = p;
        }
        return p;
    }

    @Override
    public String toString() {
        return "PatternRule{regex='" + regex + "', outcome='" + outcome + "'}";
    }
}
