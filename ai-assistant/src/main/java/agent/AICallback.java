package agent;

import agent.model.AIResponse;

/**
 * Used with async call to an AI model, that can do something when the AI sends data
 * back, or can do something if there is an error.
 */
public interface AICallback {
    void onResponse(AIResponse response);

    void onError(AIException error);
}
