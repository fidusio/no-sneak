package agent.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * Creates a response received from an AI model
 */
public class AIResponse extends PropertyDAO {

    public enum Param implements GetNVConfig {
        MODEL(NVConfigManager.createNVConfig("model", "the ai model for the request", "Model", false, true, String.class)),
        CONTENT(NVConfigManager.createNVConfig("content", "the content the ai sends back", "Content", false, true, String.class)),
        CORRELATION_ID(NVConfigManager.createNVConfig("correlation_id", "id to connect response with request", "CorrelationID", false, true, String.class)),
        PROVIDER_SESSION_ID(NVConfigManager.createNVConfig("provider_session_id", "id for stateful ai for context", "ProviderSessionID", false, true, String.class)),
        TOKENS(NVConfigManager.createNVConfig("tokens", "number of tokens used", "Tokens", false, true, Integer.class)),
        LATENCY(NVConfigManager.createNVConfig("latency", "the time taken for the request", "Latency", false, true, Long.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_RESPONSE = new NVConfigEntityPortable(
            "ai_response", null, "AIResponse", true, false, false, false,
            AIResponse.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );


    public AIResponse() {
        super(NVC_AI_RESPONSE);
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

    public String getCorrelationID() {
        return lookupValue(Param.CORRELATION_ID);
    }

    public void setCorrelationID(String correlationID) {
        setValue(Param.CORRELATION_ID, correlationID);
    }

    public String getProviderSessionID() {
        return lookupValue(Param.PROVIDER_SESSION_ID);
    }

    public void setProviderSessionID(String sessionID) {
        setValue(Param.PROVIDER_SESSION_ID, sessionID);
    }

    public int getTokens() {
        return lookupValue(Param.TOKENS);
    }

    public void setTokens(int tokens) {
        setValue(Param.TOKENS, tokens);
    }

    public long getLatency() {
        return lookupValue(Param.LATENCY);
    }

    public void setLatency(long latency) {
        setValue(Param.LATENCY, latency);
    }
}
