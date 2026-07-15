package agent;

import agent.model.AIResponse;

/**
 * Receives a streamed answer as it arrives, one piece at a time. Passed to
 * {@link AIProvider#stream}; the provider calls these callbacks in order: {@code onStart} once, then
 * {@code onDelta} per chunk, then either {@code onComplete} or {@code onError}.
 */
public interface AIStreamListener {

    /**
     * Called once before any text, with the model that will answer.
     */
    default void onStart(String model) {
    }

    /**
     * Called for each chunk of answer text as it streams in.
     */
    void onDelta(String text);

    /**
     * Called once when the answer is fully received.
     */
    void onComplete(AIResponse response);

    /**
     * Called instead of {@code onComplete} if the stream fails.
     */
    void onError(AIException e);
}
