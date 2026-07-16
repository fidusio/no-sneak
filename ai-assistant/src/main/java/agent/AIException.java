package agent;

import org.zoxweb.shared.api.APIException;


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
