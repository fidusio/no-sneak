package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * Creates a request that can be sent to an AI that will send a response back.
 */
public class AIRequest extends PropertyDAO {

    public enum Param implements GetNVConfig {
        MODEL(NVConfigManager.createNVConfig("model", "the ai model for the request", "Model", false, false, String.class)),
        CONTENT(NVConfigManager.createNVConfig("content", "content to send to an ai", "Content", false, false, String.class)),
        CORRELATION_ID(NVConfigManager.createNVConfig("correlation_id", "id to connect request with responses", "CorrelationID", false, false, String.class)),
        PROVIDER_SESSION_ID(NVConfigManager.createNVConfig("provider_session_id", "id to send to stateful ai for context", "ProviderSessionID", false, false, String.class)),
        MAX_TOKENS(NVConfigManager.createNVConfig("max_tokens", "the max number of tokens the request should use", "MaxTokens", false, false, Integer.class)),
        ATTACHMENTS(NVConfigManager.createNVConfigEntity("attachments", "sources sent with this turn", "Attachments", false, true, AISource[].class, NVConfigEntity.ArrayType.LIST));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_REQUEST = new NVConfigEntityPortable(
            "ai_request", null, "AIRequest", true, false, false, false,
            AIRequest.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AIRequest() {
        super(NVC_AI_REQUEST);
    }

    public AIRequest(String model, String content, Integer maxTokens) {
        this();
        setModel(model);
        setContent(content);
        setMaxTokens(maxTokens);
    }

    public String getModel() {
        return lookupValue(Param.MODEL);
    }

    public void setModel(String model) {
        setValue(Param.MODEL, model);
    }


    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {
        setValue(Param.CONTENT, content);
    }

    /**
     * Joins one request to the response(s) it produced. Only meaningful once a send fans out to
     * several providers — with a single provider the pairing is already the {@link AIMessage}.
     */
    public String getCorrelationID() {
        return lookupValue(Param.CORRELATION_ID);
    }

    public void setCorrelationID(String correlationID) {
        setValue(Param.CORRELATION_ID, correlationID);
    }

    /**
     * A <i>stateful</i> provider's resume handle — a different thing from
     * {@link #getCorrelationID()}. Null for a fresh or stateless chat; a provider that keeps
     * server-side context mints one on its first response, and replaying it lets later turns skip
     * resending the transcript. Stateless providers ignore it and get the flattened history.
     * <p>
     * Nothing captures it off a response today, so every chat is effectively stateless.
     */
    public String getProviderSessionID() {
        return lookupValue(Param.PROVIDER_SESSION_ID);
    }

    public void setProviderSessionID(String sessionID) {
        setValue(Param.PROVIDER_SESSION_ID, sessionID);
    }

    public Integer getMaxTokens() {
        return lookupValue(Param.MAX_TOKENS);
    }

    public void setMaxTokens(Integer maxTokens) {
        setValue(Param.MAX_TOKENS, maxTokens);
    }

    public ArrayValues<NVEntity> getAttachments() {
        return lookup(Param.ATTACHMENTS);
    }

    public AIRequest addAttachment(AISource source) {
        getAttachments().add(source);
        return this;
    }
}
