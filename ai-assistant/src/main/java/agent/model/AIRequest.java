package agent.model;

import org.zoxweb.shared.util.NVGenericMap;

import java.util.List;

/**
 * A vendor-neutral request to an AI model. Providers translate this into their own wire format.
 *
 * @param model        the model id to answer
 * @param systemPrompt the system prompt (active skills, concatenated)
 * @param messages     the conversation so far
 * @param maxTokens    the answer length limit
 * @param options      extra settings like temperature and vendor-specific extras
 */
public record AIRequest(
        String model,
        String systemPrompt,                                      // skills, concatenated
        List<AIMessage> messages,
        int maxTokens,
        NVGenericMap options                                      // temperature, vendor extras
) {
    /**
     * Copies this request with a different model. Lets a fan-out reuse one request
     * (same prompt/skills/messages) across many models.
     */
    public AIRequest withModel(String m) {
        return new AIRequest(m, systemPrompt, messages, maxTokens, options);
    }
}
