package io.xlogistx.nosneak.probe.model;

import java.util.regex.Pattern;

/**
 * A single pattern-match rule inside an {@code expect}/{@code starttls} state.
 * Deserialized directly from JSON via {@code GSONUtil.fromJSONDefault}.
 * <p>
 * {@code regex} is matched (via {@link java.util.regex.Matcher#find()}) against
 * the accumulated inbound bytes; on the first match the state machine fires the
 * transition labelled {@code outcome}.
 */
public class PatternRule {

    private String regex;
    private String outcome;

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
