package agent.model;

import org.zoxweb.shared.util.NVGenericMap;

import java.util.List;

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

    public AIRequest(String model, String systemPrompt, List<AIMessage> messages, String correlationID, String topicID, int maxTokens, NVGenericMap options) {
        this.model = model;
        this.systemPrompt = systemPrompt;
        this.messages = messages;
        this.correlationID = correlationID;
        this.topicID = topicID;
        this.maxTokens = maxTokens;
        this.options = options;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getSystemPrompt() {
        return systemPrompt;
    }

    public void setSystemPrompt(String systemPrompt) {
        this.systemPrompt = systemPrompt;
    }

    public List<AIMessage> getMessages() {
        return messages;
    }

    public void setMessages(List<AIMessage> messages) {
        this.messages = messages;
    }

    public String getCorrelationID() {
        return correlationID;
    }

    public void setCorrelationID(String correlationID) {
        this.correlationID = correlationID;
    }

    public String getTopicID() {
        return topicID;
    }

    public void setTopicID(String topicID) {
        this.topicID = topicID;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }

    public NVGenericMap getOptions() {
        return options;
    }

    public void setOptions(NVGenericMap options) {
        this.options = options;
    }
}
