package agent.model;


/**
 * Creates a message to send to an AI provider
 */
public class AIMessage {

    public enum Role {
        USER, ASSISTANT;
    }

    private Role role;
    private String content;

    public AIMessage() {
    }

    public AIMessage(Role role, String content) {
        this.role = role;
        this.content = content;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
