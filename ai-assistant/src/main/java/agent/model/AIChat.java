package agent.model;

import org.zoxweb.shared.data.TimeStampDAO;
import org.zoxweb.shared.util.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class AIChat extends TimeStampDAO {

    public enum Param implements GetNVConfig {
        TOPIC_ID(NVConfigManager.createNVConfig("topic_id", "stable conversation id", "TopicID", true, true, String.class)),
        MODEL(NVConfigManager.createNVConfig("model", "default model id", "Model", false, true, String.class)),
        SYSTEM_PROMPT(NVConfigManager.createNVConfig("system_prompt", "system prompt", "SystemPrompt", false, true, String.class)),
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
            TimeStampDAO.NVC_TIME_STAMP_DAO
    );

    public AIChat() {
        super(NVC_AI_CHAT);
    }

    public AIChat(String title) {
        this();
        setTitle(title);
        setTopicID(UUID.randomUUID().toString());
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

    public String getTopicID() {
        return lookupValue(Param.TOPIC_ID);
    }

    public void setTopicID(String topicID) {
        setValue(Param.TOPIC_ID, topicID);
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

    public AIChat addUser(String text) {
        return addMessage(new AIMessage(AIMessage.Role.USER, text));
    }

    public AIChat addAssistant(String text) {
        return addMessage(new AIMessage(AIMessage.Role.ASSISTANT, text));
    }

    public AIRequest toRequest(int maxTokens, NVGenericMap options) {
        List<AIMessage> history = new ArrayList<>();
        for (NVEntity e : getMessages().values()) {
            history.add((AIMessage) e);
        }
        return new AIRequest(getModel(), getSystemPrompt(), history, getTopicID(), maxTokens, options);
    }
}
