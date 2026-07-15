package agent;

import agent.model.AIModel;
import agent.model.AIRequest;
import agent.model.AIResponse;

import java.util.List;

/**
 * The vendor boundary: one implementation per AI provider (Anthropic, OpenAI, ...). It is the only
 * place that knows a vendor's wire format — everything above it stays vendor-neutral. Implementations
 * are resolved by {@link #providerType()} through an {@link AIProviderRegistry}.
 */
public interface AIProvider {

    /**
     * @return the vendor id this impl handles (matched against {@link AICredential#providerType()}).
     */
    String providerType();

    /**
     * Discovers the models this credential can use (the Providers "Refresh").
     */
    List<AIModel> listModels(AICredential cred) throws AIException;

    /**
     * Sends one request and waits for the full answer.
     */
    AIResponse send(AICredential cred, AIRequest req) throws AIException;

    /**
     * Sends one request and streams the answer back in pieces via {@code listener}; {@code token} can cancel it.
     */
    void stream(AICredential cred, AIRequest req,
                AIStreamListener listener, AICancelToken token) throws AIException;
}
