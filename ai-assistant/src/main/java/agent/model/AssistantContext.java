package agent.model;

import agent.AIChatRepository;
import agent.AICredentialSource;
import agent.AIProvider;
import org.zoxweb.shared.security.APIKey;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.List;

public class AssistantContext {
    private final AICredentialSource credentials;
    private final AIChatRepository chats;
    private final AIProviderRegistrar providers;

    private AIChat currentChat;
    private APIKey<String> currentCredential;
    private String currentModel;
    private List<AISkill> skills;

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
        currentChat = chats.save(new AIChat("New chat"));
        pcs.firePropertyChange("currentChat", null, currentChat);
    }

    public void deleteChat(AIChat chat) {
        chats.delete(chat);
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

    public void addProvider(APIKey<String> key) {

    }

    public APIKey<String> getCurrentCredential() {
        return currentCredential;
    }

    public String getCurrentModel() {
        return currentModel;
    }

    public void setCurrentChat(AIChat currentChat) {
        this.currentChat = currentChat;
    }

    public void setCurrentCredential(APIKey<String> currentCredential) {
        this.currentCredential = currentCredential;
    }

    public void setCurrentModel(String currentModel) {
        this.currentModel = currentModel;
    }

    public List<AISkill> getSkills() {
        return skills;
    }

    public void setSkills(List<AISkill> skills) {
        this.skills = skills;
    }
}
