package agent;

import agent.model.AIResponse;
import org.zoxweb.shared.task.ConsumerCallback;

/**
 * Used with async call to an AI model, that can do something when the AI sends data
 * back, or can do something if there is an error.
 */
public interface AICallback extends ConsumerCallback<AIResponse> {

}
