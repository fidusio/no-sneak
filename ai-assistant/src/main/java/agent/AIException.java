package agent;

/**
 * Something went wrong talking to a provider. Carries a {@link Kind} so callers can react (e.g. retry
 * on a transient failure, show an auth error). In a fan-out it is carried inside
 * {@link AIRunner.RunResult.Failure} rather than thrown, so one bad model doesn't sink the run.
 */
public final class AIException extends RuntimeException {

    public AIException(Kind kind) {
        this.kind = kind;
    }

    /**
     * What kind of failure occurred.
     */
    public enum Kind {AUTH, RATE_LIMIT, CONTEXT_OVERFLOW, TIMEOUT, NETWORK, PROVIDER}

    private final Kind kind;

    /**
     * @return the failure category.
     */
    public Kind kind() {
        return kind;
    }

    /**
     * @return true if retrying might succeed (rate-limit or network blip).
     */
    public boolean retryable() {
        return kind == Kind.RATE_LIMIT || kind == Kind.NETWORK;
    }
}
