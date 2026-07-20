package agent.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class AIChat extends PropertyDAO {

    public enum Param implements GetNVConfig {
        PROVIDER_SESSION_ID(NVConfigManager.createNVConfig("provider_session_id", "provider-issued handle to resume server-side context on a stateful api; null until a response supplies it", "ProviderSessionID", false, true, String.class)),
        MODEL(NVConfigManager.createNVConfig("model", "default model id", "Model", false, true, String.class)),
        SYSTEM_PROMPT(NVConfigManager.createNVConfig("system_prompt", "persistent assistant identity/instructions for the whole conversation", "SystemPrompt", false, true, String.class)),
        MESSAGES(NVConfigManager.createNVConfigEntity("messages", "the chat history", "Messages",
                false, true, AIMessage[].class, NVConfigEntity.ArrayType.LIST));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_CHAT = new NVConfigEntityPortable(
            "ai_chat", null, "AIChat", true, false, false, false,
            AIChat.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AIChat() {
        super(NVC_AI_CHAT);
    }

    public AIChat(String title) {
        this();
        setTitle(title);
        long now = System.currentTimeMillis();
        setCreationTime(now);
        setLastTimeUpdated(now);
    }

    public String getTitle() {
        return getName();
    }

    public void setTitle(String title) {
        setName(title);
    }

    public String getProviderSessionID() {
        return lookupValue(Param.PROVIDER_SESSION_ID);
    }

    public void setProviderSessionID(String sessionID) {
        setValue(Param.PROVIDER_SESSION_ID, sessionID);
    }

    public String getModel() {
        return lookupValue(Param.MODEL);
    }

    public void setModel(String model) {
        setValue(Param.MODEL, model);
    }

    public String getSystemPrompt() {
        return lookupValue(Param.SYSTEM_PROMPT);
    }

    public void setSystemPrompt(String systemPrompt) {
        setValue(Param.SYSTEM_PROMPT, systemPrompt);
    }

    public ArrayValues<NVEntity> getMessages() {
        return lookup(Param.MESSAGES);
    }

    public AIChat addMessage(AIMessage msg) {
        getMessages().add(msg);
        setLastTimeUpdated(System.currentTimeMillis());
        return this;
    }

    public AIRequest toRequest(String userInput, int maxTokens) {
        AIRequest req = new AIRequest();
        req.setModel(getModel());
        req.setContent(userInput);
        req.setProviderSessionID(getProviderSessionID());
        req.setMaxTokens(maxTokens);
        return req;
    }

    public AIMessage startTurn(String userInput, int maxTokens) {
        AIMessage msg = new AIMessage(toRequest(userInput, maxTokens));
        addMessage(msg);
        return msg;
    }
}
