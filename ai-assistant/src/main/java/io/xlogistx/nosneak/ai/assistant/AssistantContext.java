package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderRegistrar;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.security.APIKey;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AssistantContext {
    private final AICredentialSource credentials;
    private final AIRepository repository;
    private final AIProviderRegistrar providers;

    private AIChat currentChat;
    private APIKey<String> currentCredential;
    private String currentModel;
    private List<AISkill> skills;

    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    private final Map<String, AIChat> cache = new ConcurrentHashMap<>();

    public AssistantContext(AICredentialSource credentials, AIRepository repository) {
        this.credentials = credentials;
        this.repository = repository;
        providers = new AIProviderRegistrar();
    }

    public void deleteChat(AIChat chat) {
        repository.deleteChat(chat);
        if (chat.getReferenceID() != null) cache.remove(chat.getReferenceID());
        currentChat = null;
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

    public AIRepository getRepository() {
        return repository;
    }

    public AIProviderRegistrar getProviders() {
        return providers;
    }

    public void addProvider(APIKey<String> key) {
        AIAPIProvider temp = AIAPIProvider.create(key);
        if (temp != null) {
            providers.put(temp.getName(), temp);
        }

    }

    public APIKey<String> getCurrentCredential() {
        return currentCredential;
    }

    public String getCurrentModel() {
        return currentModel;
    }

    public void setCurrentChat(AIChat chat) {
        this.currentChat = canonical(chat);
        pcs.firePropertyChange("currentChat", null, currentChat);
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

    public void clearProviders() {
        providers.getCacheMap().clear();
    }

    private AIChat canonical(AIChat c) {
        if (c == null) return null;
        String id = c.getReferenceID();
        if (id == null) return c;
        return cache.merge(id, c, (existing, incoming) -> existing);
    }

    public List<AIChat> allChats() {
        List<AIChat> out = new ArrayList<>();
        for (AIChat c : repository.getAllChats()) out.add(canonical(c));
        return out;
    }

    public AIChat saveChat(AIChat chat) {
        return canonical(repository.saveChat(chat));
    }
}
