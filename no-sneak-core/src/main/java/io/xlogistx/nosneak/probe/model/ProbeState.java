package io.xlogistx.nosneak.probe.model;

import java.util.List;
import java.util.Map;

/**
 * One state of a {@link ProbeDefinition} state machine, deserialized from JSON.
 * <p>
 * Every state names exactly one {@code action} (a key into the fixed action
 * library) plus an optional {@code on} map of <em>outcome label &rarr; next state
 * id</em>. Action-specific configuration ({@code payload}, {@code patterns},
 * {@code command}, {@code ready}, {@code mode}, {@code note}, {@code port}) is
 * read by the corresponding action class. Unknown JSON fields are ignored by
 * GSON, so definitions stay forward-compatible.
 */
public class ProbeState {

    private String action;
    private Map<String, String> on;

    // Action-specific config (only the relevant subset is populated per action).
    private String payload;          // send: templated text (UTF-8) — legacy/text convenience
    private String data;             // send: codec-prefixed payload "hex:..|base64:..|text:.." (text if no prefix); supports binary protocols
    private List<PatternRule> patterns; // expect
    private String command;          // starttls (protocol command to send)
    private String ready;            // starttls (regex signalling the server is ready to upgrade)
    private String mode;             // tls-handshake: "pqc" (default) | "jsse" (deferred)
    private String note;             // record: free-form annotation merged into the result
    private Integer port;            // connect/reconnect: alternate port (defaults to the target port)

    public String getAction() {
        return action;
    }

    public Map<String, String> getOn() {
        return on;
    }

    /**
     * Resolve the next state id for {@code outcome}, or {@code null} if this
     * state declares no transition for it.
     */
    public String next(String outcome) {
        return on == null ? null : on.get(outcome);
    }

    public String getPayload() {
        return payload;
    }

    /** Codec-prefixed send payload ({@code hex:} / {@code base64:} / {@code text:}; plain text if unprefixed). */
    public String getData() {
        return data;
    }

    public List<PatternRule> getPatterns() {
        return patterns;
    }

    public String getCommand() {
        return command;
    }

    public String getReady() {
        return ready;
    }

    public String getMode() {
        return mode;
    }

    public String getNote() {
        return note;
    }

    public Integer getPort() {
        return port;
    }

    @Override
    public String toString() {
        return "ProbeState{action='" + action + "', on=" + on + "}";
    }
}
