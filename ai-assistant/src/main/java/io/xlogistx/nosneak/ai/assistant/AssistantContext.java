package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AIProviderRegistrar;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.data.ReferenceIDDAO;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.util.SUS;

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
    private final Map<String, AIProviderConfig> configCache = new ConcurrentHashMap<>();

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

    /**
     * Resolves what an {@link AIChat} is bound to. Chats saved before providers became their own
     * record hold a provider <em>name</em>, so a miss on the id falls back to a label match.
     *
     * @return the provider, or null when nothing matches
     */
    public AIProvider lookupProvider(String ref) {
        if (SUS.isEmpty(ref)) return null;
        AIProvider byID = providers.lookup(ref);
        if (byID != null) return byID;
        for (AIProvider p : providers.getCacheMap().values()) {
            if (ref.equals(p.getName())) return p;
        }
        return null;
    }

    public APIKey<String> getCurrentCredential() {
        return currentCredential;
    }

    public String getCurrentModel() {
        return currentModel;
    }

    public void setCurrentChat(AIChat chat) {
        this.currentChat = canonical(chatCache, chat);
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

    /**
     * The canonical-cache rule shared by chats, skills, and provider configs: the first instance
     * seen for a GUID stays the one everyone gets, so list refreshes don't hand out duplicates.
     */
    private static <T extends ReferenceIDDAO> T canonical(Map<String, T> cache, T dao) {
        if (dao == null) return null;
        String id = dao.getGUID();
        if (id == null) return dao;
        return cache.merge(id, dao, (existing, incoming) -> existing);
    }

    public List<AISkill> getAllSkills() {
        List<AISkill> out = new ArrayList<>();
        for(AISkill s : repository.getAllSkills()) out.add(canonical(skillCache, s));
        return out;
    }

    public void saveSkill(AISkill skill) {
        canonical(skillCache, repository.saveSkill(skill));
    }

    public void deleteSkill(AISkill skill) {
        if(skill == null) return;
        repository.deleteSkill(skill);
        if(skill.getGUID() != null) skillCache.remove(skill.getGUID());
    }

    public List<AIProviderConfig> getAllProviderConfigs() {
        List<AIProviderConfig> out = new ArrayList<>();
        for (AIProviderConfig c : repository.getAllProviderConfigs()) out.add(canonical(configCache, c));
        return out;
    }

    public AIProviderConfig saveProviderConfig(AIProviderConfig config) {
        return canonical(configCache, repository.saveProviderConfig(config));
    }

    /**
     * Drops the config from the store and the cache. Unregistering the built provider is the
     * caller's job — this runs off the EDT, and the registrar backs a plain map the UI is reading.
     */
    public void deleteProviderConfig(AIProviderConfig config) {
        if (config == null) return;
        repository.deleteProviderConfig(config);
        if (config.getGUID() != null) configCache.remove(config.getGUID());
    }

    /**
     * @return how many stored configs borrow the given credential, registered or not
     */
    public int configsUsing(String keyGUID) {
        if (keyGUID == null) return 0;
        int count = 0;
        for (AIProviderConfig cfg : repository.getAllProviderConfigs()) {
            if (keyGUID.equals(cfg.getKeyGUID())) count++;
        }
        return count;
    }

    public List<AIChat> getAllChats() {
        List<AIChat> out = new ArrayList<>();
        for (AIChat c : repository.getAllChats()) out.add(canonical(chatCache, c));
        return out;
    }

    public AIChat saveChat(AIChat chat) {
        return canonical(chatCache, repository.saveChat(chat));
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
        configCache.clear();
        pcs.firePropertyChange("currentChat", old, null);
    }
}
