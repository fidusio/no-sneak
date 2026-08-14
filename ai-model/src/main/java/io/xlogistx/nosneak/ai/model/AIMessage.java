package io.xlogistx.nosneak.ai.model;


import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * One exchange — a single provider round trip. Holds an {@link AIRequest} and the
 * {@link AIResponse} it produced; the response half stays null until the provider replies (or
 * forever, if the send failed).
 * <p>
 * <b>Roles are implicit in the pair</b>, which is why there is no role field. A multi-step or
 * tool-using turn is several {@code AIMessage}s in a row, so "request" means "model input this
 * round" — user text <i>or</i> a tool result — not strictly what a human typed.
 */
public class AIMessage extends PropertyDAO {

    public enum Param implements GetNVConfig {
        AI_REQUEST(NVConfigManager.createNVConfigEntity("ai_request", "a request sent to an ai provider", "AIRequest", false, true, AIRequest.NVC_AI_REQUEST)),
        AI_RESPONSE(NVConfigManager.createNVConfigEntity("ai_response", "a response sent from an an ai provider", "AIResponse", false, true, AIResponse.NVC_AI_RESPONSE));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_MESSAGE = new NVConfigEntityPortable(
            "ai_message", null, "AIMessage", true, false, false, false,
            AIMessage.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AIMessage() {
        super(NVC_AI_MESSAGE);
    }

    public AIMessage(AIRequest request) {
        this();
        setAIRequest(request);
    }

    public AIRequest getAIRequest() {
        return lookupValue(Param.AI_REQUEST);
    }

    public void setAIRequest(AIRequest request) {
        setValue(Param.AI_REQUEST, request);
    }

    public AIResponse getAIResponse() {
        return lookupValue(Param.AI_RESPONSE);
    }

    public void setAIResponse(AIResponse response) {
        setValue(Param.AI_RESPONSE, response);
    }
}
