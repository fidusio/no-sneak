package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderRegistrar;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.security.APIKey;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
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

    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    private final Map<String, AIChat> chatCache = new ConcurrentHashMap<>();
    private final Map<String, AISkill> skillCache = new ConcurrentHashMap<>();

    public AssistantContext(AICredentialSource credentials, AIRepository repository) {
        this.credentials = credentials;
        this.repository = repository;
        providers = new AIProviderRegistrar();
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

    public List<AIProvider> getProvidersList() {
        return new ArrayList<>( getProviders().getCacheMap().values());
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
        this.currentChat = canonicalChat(chat);
        pcs.firePropertyChange("currentChat", null, currentChat);
    }

    public void setCurrentCredential(APIKey<String> currentCredential) {
        this.currentCredential = currentCredential;
    }

    public void setCurrentModel(String currentModel) {
        this.currentModel = currentModel;
    }

    public void clearProviders() {
        providers.clear(false);
    }

    private AISkill canonicalSkill(AISkill s) {
        if(s == null) return null;
        String id = s.getGUID();
        if(id == null) return s;
        return skillCache.merge(id, s, (existing, incoming) -> existing);
    }

    public List<AISkill> getAllSkills() {
        List<AISkill> out = new ArrayList<>();
        for(AISkill s : repository.getAllSkills()) out.add(canonicalSkill(s));
        return out;
    }

    public void saveSkill(AISkill skill) {
        canonicalSkill(repository.saveSkill(skill));
    }

    public void deleteSkill(AISkill skill) {
        if(skill == null) return;
        repository.deleteSkill(skill);
        if(skill.getGUID() != null) skillCache.remove(skill.getGUID());
    }

    private AIChat canonicalChat(AIChat c) {
        if (c == null) return null;
        String id = c.getGUID();
        if (id == null) return c;
        return chatCache.merge(id, c, (existing, incoming) -> existing);
    }

    public List<AIChat> getAllChats() {
        List<AIChat> out = new ArrayList<>();
        for (AIChat c : repository.getAllChats()) out.add(canonicalChat(c));
        return out;
    }

    public AIChat saveChat(AIChat chat) {
        return canonicalChat(repository.saveChat(chat));
    }

    public void deleteChat(AIChat chat) {
        if (chat == null) return;
        repository.deleteChat(chat);
        if (chat.getGUID() != null) chatCache.remove(chat.getGUID());
        if (currentChat != null
                && (chat == currentChat
                || (chat.getGUID() != null && chat.getGUID().equals(currentChat.getGUID())))) {
            AIChat old = currentChat;
            currentChat = null;
            pcs.firePropertyChange("currentChat", old, null);
        }
    }

    public void resetContext() {
        AIChat old = currentChat;
        currentChat = null;
        currentCredential = null;
        currentModel = null;
        chatCache.clear();
        skillCache.clear();
        pcs.firePropertyChange("currentChat", old, null);
    }
}
