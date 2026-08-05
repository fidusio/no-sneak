package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.api.ai.AIAPI;
import io.xlogistx.api.ai.AIAPIBuilder;
import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIModelCatalog;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.time.Instant;

public class AIAPIProvider implements AIProvider {

    private final AIProviderConfig config;
    private APIKey<String> key;
    private final AIAPIBuilder.AIAPIType type;
    private AIAPI api;
    private final ModelCatalog modelCatalog;

    public AIAPIProvider(AIProviderConfig config, APIKey<String> key, AIAPIBuilder.AIAPIType type) {
        this.config = config;
        this.key = key;
        this.type = type;

        api = AIAPIBuilder.createAIAPI(type, null, key.getAPIKey());
        api.updateExecutor(TaskUtil.defaultTaskProcessor());
        modelCatalog = new ModelCatalog();
    }

    public AIProviderConfig getConfig() {
        return config;
    }

    /**
     * @return the endpoint this provider talks to: its own base URL, or the provider type's default
     */
    public String getBaseURL() {
        String url = SUS.trimOrNull(config.getBaseURL());
        return (url == null) ? type.getURL() : url;
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

    private AIAPI bound() {
        api.updateURL(getBaseURL());
        api.lookupEndPoint(AIAPIBuilder.Command.MODELS.getName()).setAuthorizationEncoder(
                type == AIAPIBuilder.AIAPIType.ANTHROPIC
                        ? AIAPIBuilder.ANTHROPIC_AUTHORIZATION
                        : HTTPAPIEndPoint.DEFAULT_AUTHORIZATION_ENCODER);
        return api;
    }

    @Override
    public AIResponse send(AIRequest req, String skill) throws AIException {
        AIResponse response = new AIResponse();

        try {
            int maxTokens = (req.getMaxTokens() != null) ? req.getMaxTokens() : 1024;

            String res = bound().completion(req.getModel(), req.getContent(), maxTokens, skill);
            response.setContent(res);

        } catch (IOException e) {
            throw new AIException(AIException.Kind.NETWORK, e);
        }

        return response;
    }

    @Override
    public void asyncSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback) throws AIException {
        int maxTokens = (req.getMaxTokens() != null) ? req.getMaxTokens() : 1024;
        bound().asyncCompletion(req.getModel(), req.getContent(), maxTokens, skill, callback);
    }

    /**
     * Identity, and the registrar key. The config GUID rather than the name, so two providers can
     * share one credential and either can be relabelled without orphaning the chats bound to it.
     */
    @Override
    public String getID() {
        return config.getGUID();
    }

    @Override
    public String getDescription() {
        return type.getDescription();
    }

    /**
     * The editable label. Falls back to the credential's name for a config saved without one.
     */
    @Override
    public String getName() {
        String label = config.getName();
        return SUS.isEmpty(label) ? key.getName() : label;
    }

    public static AIAPIProvider create(AIProviderConfig config, APIKey<String> key) {
        if (config == null || key == null) return null;
        AIAPIBuilder.AIAPIType type = resolveType(config.getProviderType());
        return (type == null) ? null : new AIAPIProvider(config, key, type);
    }

    public static AIAPIBuilder.AIAPIType resolveType(String provider) {
        if (provider == null) {
            return null;
        }
        String p = provider.toLowerCase().replaceAll("[^a-z]", "");
        return switch (p) {
            case "openai" -> AIAPIBuilder.AIAPIType.OPEN_AI;
            case "gemini", "google", "googlegemini" -> AIAPIBuilder.AIAPIType.GEMINI;
            case "anthropic", "claude", "anthropicclaude" -> AIAPIBuilder.AIAPIType.ANTHROPIC;
            case "grok", "xai", "grokxai" -> AIAPIBuilder.AIAPIType.GROK;
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
                newList = bound().availableModels();
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
