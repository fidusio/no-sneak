package agent.model;

/**
 * Creates a response received from an AI model
 */
public class AIResponse {
    private String model;
    private String content;
    private String correlationID;
    private String topicID;
    private int tokens;
    private long latencyMillis;
    private String stopReason;

    public AIResponse() {
    }

    public AIResponse(String model, String content, String correlationID, String topicID, int tokens, long latencyMillis, String stopReason) {
        this.model = model;
        this.content = content;
        this.correlationID = correlationID;
        this.topicID = topicID;
        this.tokens = tokens;
        this.latencyMillis = latencyMillis;
        this.stopReason = stopReason;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
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

    public int getTokens() {
        return tokens;
    }

    public void setTokens(int tokens) {
        this.tokens = tokens;
    }

    public long getLatencyMillis() {
        return latencyMillis;
    }

    public void setLatencyMillis(long latencyMillis) {
        this.latencyMillis = latencyMillis;
    }

    public String getStopReason() {
        return stopReason;
    }

    public void setStopReason(String stopReason) {
        this.stopReason = stopReason;
    }
}
