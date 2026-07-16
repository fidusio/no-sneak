package agent;

import agent.model.AIResponse;

import java.util.List;

/**
 * used when running one message request through multiple AI models. Carries
 * the number of AIs running, the number of completed messages, and aggregates
 * the list of all responses and errors, connected to each individual chat
 */
public interface AICallbackCollection {
    int size();

    int completed();

    default boolean isComplete() {
        return completed() >= size();
    }

    List<AIResponse> responses();

    List<AIException> errors();

    void onComplete(Runnable action);
}
