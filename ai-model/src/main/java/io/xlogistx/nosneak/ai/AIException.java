package io.xlogistx.nosneak.ai;

import org.zoxweb.shared.api.APIException;


/**
 * A provider call that failed, tagged with a {@link Kind} so callers can react without parsing
 * message text — retry on {@code RATE_LIMIT} or {@code TIMEOUT}, prompt for a key on {@code AUTH},
 * trim history on {@code CONTEXT_OVERFLOW}. {@code PROVIDER} is the catch-all for a provider-side
 * error that does not fit the others.
 */
public final class AIException extends APIException {

    public AIException(Kind kind) {
        this.kind = kind;
    }

    public AIException(Kind kind, Exception e) {
        super(e);
        this.kind = kind;
    }

    public enum Kind {AUTH, RATE_LIMIT, CONTEXT_OVERFLOW, TIMEOUT, NETWORK, PROVIDER}

    private final Kind kind;

    public Kind kind() {
        return kind;
    }
}
