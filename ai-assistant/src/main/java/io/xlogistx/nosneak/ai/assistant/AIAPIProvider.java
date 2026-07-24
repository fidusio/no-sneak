package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.api.ai.AIAPI;
import io.xlogistx.api.ai.AIAPIBuilder;
import io.xlogistx.nosneak.ai.AICallback;
import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIModelCatalog;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.zoxweb.shared.security.APIKey;

import java.io.IOException;
import java.time.Instant;

public class AIAPIProvider implements AIProvider {

    private APIKey<String> key;
    private final AIAPIBuilder.AIAPIType type;
    private AIAPI api;
    private final ModelCatalog modelCatalog;

    public AIAPIProvider(APIKey<String> key, AIAPIBuilder.AIAPIType type) {
        this.key = key;
        this.type = type;

        api = AIAPIBuilder.createAIAPI(type, null, key.getAPIKey());

        modelCatalog = new ModelCatalog();
        modelCatalog.refresh();
    }

    @Override
    public AIModelCatalog getModelCatalog() throws AIException {
        return modelCatalog;
    }

    @Override
    public void setAPIKey(APIKey<String> key) {
        this.key = key;
    }

    @Override
    public APIKey<String> getAPIKey() {
        return key;
    }

    @Override
    public void setHTTPAPICaller(AIAPI APICaller) {
        this.api = APICaller;
    }

    @Override
    public AIAPI getHTTPAPICaller() {
        return api;
    }

    @Override
    public AIResponse send(AIRequest req) throws AIException {
        AIResponse response = new AIResponse();

        try {
            int maxTokens = (req.getMaxTokens() != null) ? req.getMaxTokens() : 1024;
            String res = api.completion(req.getModel(), req.getContent(), maxTokens);
            response.setContent(res);

        } catch (IOException e) {
            throw new AIException(AIException.Kind.NETWORK, e);
        }

        return response;
    }

    @Override
    public void asyncSend(AIRequest req, AICallback callback) throws AIException {

    }

    @Override
    public String getDescription() {
        return type.getDescription();
    }

    @Override
    public String getName() {
        return key.getName();
    }

    public static AIAPIProvider create(APIKey<String> key) {
        String provider = (key.getProperties() != null) ? key.getProperties().getValue("provider") : null;
        AIAPIBuilder.AIAPIType type = resolveType(provider);
        return (type == null) ? null : new AIAPIProvider(key, type);
    }

    public static AIAPIBuilder.AIAPIType resolveType(String provider) {
        if (provider == null) {
            return null;
        }
        String p = provider.toLowerCase().replaceAll("[^a-z]", "");
        return switch (p) {
            case "openai" -> AIAPIBuilder.AIAPIType.OPEN_AI;
            case "gemini", "google" -> AIAPIBuilder.AIAPIType.GEMINI;
            case "anthropic", "claude" -> AIAPIBuilder.AIAPIType.ANTHROPIC;
            case "grok", "xai" -> AIAPIBuilder.AIAPIType.GROK;
            default -> null;
        };
    }

    public class ModelCatalog implements AIModelCatalog {

        private String[] models;
        private Instant lastSynced;

        @Override
        public String[] models() {
            return models;
        }

        @Override
        public String[] refresh() throws AIException {
            String[] newList;
            try {
                newList = api.availableModels();
                lastSynced = Instant.now();
            } catch (IOException e) {
                throw new AIException(AIException.Kind.PROVIDER, e);
            }

            this.models = newList;
            return newList;
        }

        @Override
        public Instant lastSynced() {
            return lastSynced;
        }
    }
}
