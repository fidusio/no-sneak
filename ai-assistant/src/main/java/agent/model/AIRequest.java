package agent.model;

import org.zoxweb.shared.util.NVGenericMap;

import java.util.List;
import java.util.UUID;

/**
 * Creates a request that can be sent to an AI that will send a response back.
 */
public class AIRequest {
    private String model;
    private String systemPrompt;                                      // skills, concatenated
    private List<AIMessage> messages;
    private String correlationID;                                     // we generate correlation id uuid
    private String topicID;
    //can have chat/topic where you get an id or one message chat
    private int maxTokens;
    private NVGenericMap options;

    public AIRequest() {
    }

    public AIRequest(String model, String systemPrompt, List<AIMessage> messages, String topicID, int maxTokens, NVGenericMap options, String correlationID) {
        this.model = model;
        this.systemPrompt = systemPrompt;
        this.messages = messages;
        this.correlationID = correlationID;
        this.topicID = topicID;
        this.maxTokens = maxTokens;
        this.options = options;
    }

    public AIRequest(String model, String systemPrompt, List<AIMessage> messages, String topicID, int maxTokens, NVGenericMap options) {
        this(model, systemPrompt, messages, topicID, maxTokens, options, UUID.randomUUID().toString());
    }

    public String getModel() {
        return model;
    }

    // do this for all set functions
    public AIRequest setModel(String model) {
        this.model = model;
        return this;
    }

    public String getSystemPrompt() {
        return systemPrompt;
    }

    public AIRequest setSystemPrompt(String systemPrompt) {
        this.systemPrompt = systemPrompt;
        return this;
    }

    public List<AIMessage> getMessages() {
        return messages;
    }

    public AIRequest setMessages(List<AIMessage> messages) {
        this.messages = messages;
        return this;
    }

    public String getCorrelationID() {
        return correlationID;
    }

    public AIRequest setCorrelationID(String correlationID) {
        this.correlationID = correlationID;
        return this;
    }

    public String getTopicID() {
        return topicID;
    }

    public AIRequest setTopicID(String topicID) {
        this.topicID = topicID;
        return this;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public AIRequest setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
        return this;
    }

    public NVGenericMap getOptions() {
        return options;
    }

    public AIRequest setOptions(NVGenericMap options) {
        this.options = options;
        return this;
    }
}
