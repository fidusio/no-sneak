package io.xlogistx.nosneak.model;

import java.util.List;
import java.util.Map;

/**
 * One state of a {@link ProbeDefinition} state machine, deserialized from JSON.
 * <p>
 * Every state names exactly one {@code action} (a key into the fixed action
 * library) plus an optional {@code on} map of <em>outcome label &rarr; next state
 * id</em>. Action-specific configuration ({@code payload}, {@code data},
 * {@code patterns}, {@code command}, {@code ready}, {@code mode}, {@code note},
 * {@code port}) is read by the corresponding action class. Unknown JSON fields are
 * ignored by GSON, so definitions stay forward-compatible.
 * <p>
 * The enumeration actions take their toggles from here too: {@code enumerate-versions} reads
 * {@code includeSSLv3} / {@code includeTLS10} / {@code includeTLS11}, {@code enumerate-ciphers}
 * reads {@code includeWeak} / {@code includeInsecure} / {@code rankServerPreference}, and every
 * enumeration reads {@code maxInFlight}. A toggle left out keeps the engine's observe-everything
 * default (all candidates offered); the bundled deep scans spell each one out so the choice is
 * visible in the JSON rather than implied by the code.
 */
public class ProbeState {

    private String action;
    private Map<String, String> on;

    // Action-specific config (only the relevant subset is populated per action).
    private String payload;          // send: templated text (UTF-8) — legacy/text convenience
    private String data;             // send: codec-prefixed payload "hex:..|base64:..|text:.." (text if no prefix)
    private List<PatternRule> patterns; // expect
    private String command;          // starttls (protocol command to send)
    private String ready;            // starttls (regex signalling the server is ready to upgrade)
    private String mode;             // tls-handshake: "pqc" (default) | "jsse"/"classical"
    private String note;             // record: free-form annotation merged into the result
    private Integer port;            // connect/reconnect/tls-connect: alternate port
    private Integer revocationTimeoutMs; // revocation-check: bound on the active OCSP/CRL fetch (default 5000)
    // enumerate-versions: which legacy versions to offer besides TLSv1.3/1.2 (null = offered)
    private Boolean includeSSLv3;
    private Boolean includeTLS10;
    private Boolean includeTLS11;
    // enumerate-ciphers: whether opsec's weak / insecure TLS 1.2 sets are offered (null = offered)
    private Boolean includeWeak;
    private Boolean includeInsecure;
    // enumerate-ciphers: derive the server's full preference order after a "server" verdict (null = no)
    private Boolean rankServerPreference;
    // enumerate-*: child handshakes launched at once against the target (null = engine default, 8)
    private Integer maxInFlight;

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

    /** Bound, in milliseconds, on the active OCSP/CRL fetch of {@code revocation-check}; null = default. */
    public Integer getRevocationTimeoutMs() {
        return revocationTimeoutMs;
    }

    /** {@code enumerate-versions}: offer SSLv3 as well; null = yes (observe everything). */
    public Boolean getIncludeSSLv3() {
        return includeSSLv3;
    }

    /** {@code enumerate-versions}: offer TLSv1.0 as well; null = yes. */
    public Boolean getIncludeTLS10() {
        return includeTLS10;
    }

    /** {@code enumerate-versions}: offer TLSv1.1 as well; null = yes. */
    public Boolean getIncludeTLS11() {
        return includeTLS11;
    }

    /** {@code enumerate-ciphers}: offer opsec's weak TLS 1.2 set; null = yes. */
    public Boolean getIncludeWeak() {
        return includeWeak;
    }

    /** {@code enumerate-ciphers}: offer opsec's insecure TLS 1.2 set; null = yes. */
    public Boolean getIncludeInsecure() {
        return includeInsecure;
    }

    /**
     * {@code enumerate-ciphers}: when the server enforces its own order, derive that order with a
     * bounded sequential chain of handshakes ({@code server-cipher-ranking}); null = no, so the
     * default cost of the action is unchanged.
     */
    public Boolean getRankServerPreference() {
        return rankServerPreference;
    }

    /** {@code enumerate-*}: child handshakes in flight at once against the target; null = engine default (8). */
    public Integer getMaxInFlight() {
        return maxInFlight;
    }

    /** Resolves a tri-state toggle: {@code null} means the engine default {@code dflt}. */
    public static boolean flag(Boolean value, boolean dflt) {
        return value == null ? dflt : value;
    }

    @Override
    public String toString() {
        return "ProbeState{action='" + action + "', on=" + on + "}";
    }
}
