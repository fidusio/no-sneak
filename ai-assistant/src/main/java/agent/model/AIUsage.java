package agent.model;

/**
 * Token counts for one call.
 *
 * @param inputTokens  tokens sent
 * @param outputTokens tokens received
 */
public record AIUsage(int inputTokens, int outputTokens) {

    /** Zero usage, e.g. for a failed or empty call. */
    public static final AIUsage EMPTY = new AIUsage(0, 0);
}
