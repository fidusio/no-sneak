package agent.model;

/**
 * A vendor-neutral answer from an AI model. Usage and latency are first-class so the compare columns
 * can display them.
 *
 * @param model         the model that answered
 * @param text          the answer text
 * @param usage         input/output token counts
 * @param latencyMillis how long the call took, in milliseconds
 * @param stopReason    why the model stopped (e.g. end of turn, max tokens)
 */
public record AIResponse(
        String model,
        String text,
        AIUsage usage,
        long latencyMillis,
        String stopReason
        //JsonNode raw                                              // kept for audit
) {
}
