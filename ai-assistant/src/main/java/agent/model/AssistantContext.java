package agent.model;

import agent.AIChatRepository;
import agent.AICredentialSource;
import org.zoxweb.shared.security.APIKey;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

public class AssistantContext {
    private final AICredentialSource credentials;
    private final AIChatRepository chats;
    private final AIProviderRegistrar providers;

    private AIChat currentChat;
    private APIKey<String> currentCredential;
    private String currentModel;

    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    public AssistantContext(AICredentialSource credentials, AIChatRepository chats) {
        this.credentials = credentials;
        this.chats = chats;
        providers = new AIProviderRegistrar();
    }

    public void openChat(String refID) {
        currentChat = chats.getChat(refID);
        pcs.firePropertyChange("currentChat", null, currentChat);
    }

    public void newChat() {
        currentChat = new AIChat("New chat");
        pcs.firePropertyChange("currentChat", null, currentChat);
    }

    public AIChat currentChat() {
        return currentChat;
    }

    public void onChange(String prop, PropertyChangeListener l) {
        pcs.addPropertyChangeListener(prop, l);
    }

    public AICredentialSource getCredentials() {
        return credentials;
    }

    public AIChatRepository getChats() {
        return chats;
    }

    public AIProviderRegistrar getProviders() {
        return providers;
    }

    public AIChat getCurrentChat() {
        return currentChat;
    }

    public APIKey<String> getCurrentCredential() {
        return currentCredential;
    }

    public String getCurrentModel() {
        return currentModel;
    }
}
