package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.CaptureAreaSet;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.model.*;
import okhttp3.OkHttpClient;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.data.ReferenceIDImpl;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.util.SUS;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Swing-free state holder for the assistant: the injected services (credential source, repository,
 * provider registrar) plus the current selection and a few caches. Panels subscribe with
 * {@link #onChange(String, java.beans.PropertyChangeListener)} and re-render, so no page decides
 * <i>which</i> chat to load — each renders whatever {@link #currentChat()} is.
 * <p>
 * <b>The GUID-keyed caches are why identity comparisons work.</b> The store hands out a fresh
 * instance on every read, so without deduping, a chat fetched twice would be two objects and
 * {@code ==} against the current selection would silently fail. {@code canonical(...)} keeps the
 * <i>first</i> instance seen for a GUID, so an in-memory edit survives a list refresh — with the
 * trade-off that a row changed elsewhere is not picked up until the cache is cleared.
 */
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

    private final CaptureAreaSet captureAreaSet = new CaptureAreaSet();
    /** Whether the assistant's window is hidden while the capture areas are shot (2026-10-29); a session preference, kept across sign-out. */
    private volatile boolean hideWindowOnCapture = true;

    /** The reply timeout a host starts with when it has no stored value: zoxweb's own 40 s, which is right for a responsive endpoint. */
    public static final long DEFAULT_CALL_TIMEOUT_SECONDS = 40;
    /**
     * How long one request to a provider may wait for its reply, in seconds (2026-10-31); the
     * host's Settings page sets it, to stretch the limit for a congested endpoint. 0 leaves the
     * http library's own limit in force.
     */
    private volatile long callTimeoutSeconds = DEFAULT_CALL_TIMEOUT_SECONDS;
    /**
     * The one http client every provider sends through, built from {@link #callTimeoutSeconds}
     * and rebuilt only when it changes; null when the timeout is 0, which leaves the endpoints on
     * zoxweb's shared default client.
     * <p>
     * <b>Why a client and not {@code HTTPMessageConfig.setTimeout}:</b> zoxweb's
     * {@code OkHTTPCall} honours the message config's timeout only when the call has a proxy or
     * redirects off; on the ordinary path it uses one shared {@code OkHttpClient} whose 40 s
     * cannot be changed from here, and a congested endpoint needs longer. An endpoint does
     * take a dedicated client, and {@code HTTPAPICaller.updateOkHttpClient} hands one to every
     * endpoint of an {@code AIAPI} — {@code setOkHttpClient} on the caller itself is a field
     * nothing reads — so the setting is applied by pushing this client to every registered
     * {@link AIAPIProvider} ({@link #applyHttpClient}), never per call.
     */
    private volatile OkHttpClient httpClient = buildHttpClient(DEFAULT_CALL_TIMEOUT_SECONDS);

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
        return new ArrayList<>(getProviders().getCacheMap().values());
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
    private static <T extends ReferenceIDImpl> T canonical(Map<String, T> cache, T dao) {
        if (dao == null) return null;
        String id = dao.getGUID();
        if (id == null) return dao;
        return cache.merge(id, dao, (existing, incoming) -> existing);
    }

    public List<AISkill> getAllSkills() {
        List<AISkill> out = new ArrayList<>();
        for (AISkill s : repository.getAllSkills()) out.add(canonical(skillCache, s));
        return out;
    }

    public void saveSkill(AISkill skill) {
        canonical(skillCache, repository.saveSkill(skill));
    }

    public void deleteSkill(AISkill skill) {
        if (skill == null) return;
        repository.deleteSkill(skill);
        if (skill.getGUID() != null) skillCache.remove(skill.getGUID());
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

    public CaptureAreaSet getCaptureAreaSet() {
        return captureAreaSet;
    }

    public boolean isHideWindowOnCapture() {
        return hideWindowOnCapture;
    }

    public void setHideWindowOnCapture(boolean hide) {
        hideWindowOnCapture = hide;
    }

    /** Seconds a provider may take to answer one request; 0 means the http library's default. */
    public long getCallTimeoutSeconds() {
        return callTimeoutSeconds;
    }

    /**
     * Sets the reply timeout: builds the shared client once for the new value and hands it to
     * every registered provider, so their next request uses it. Negative values read as 0.
     */
    public void setCallTimeoutSeconds(long seconds) {
        callTimeoutSeconds = Math.max(0, seconds);
        httpClient = buildHttpClient(callTimeoutSeconds);
        for (AIProvider p : getProvidersList()) applyHttpClient(p);
    }

    /** The client built for the current timeout, or null when it is 0. */
    public OkHttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Hands the current client to a provider's endpoints; a no-op for a provider that is not an
     * {@link AIAPIProvider}. Called for every registered provider when the timeout changes and
     * by the code that registers a provider, so one built later gets the current value too.
     */
    public void applyHttpClient(AIProvider provider) {
        if (provider instanceof AIAPIProvider p && p.getHTTPAPICaller() != null)
            p.getHTTPAPICaller().updateOkHttpClient(httpClient);
    }

    /** zoxweb's own builder with the timeout on connect, read and write; SSL checks and redirects on, no proxy. */
    static OkHttpClient buildHttpClient(long seconds) {
        if (seconds <= 0) return null;
        return OkHTTPCall.createOkHttpBuilder(null, true, null, seconds, true, 20, 20).build();
    }

    public List<AICapture> getAllCaptures() {
        return repository.getAllCaptures();
    }

    public AICapture getCapture(String guid) {
        return repository.getCapture(guid);
    }

    public AICapture saveCapture(AICapture c) {
        return repository.saveCapture(c);
    }

    public void deleteCapture(AICapture c) {
        repository.deleteCapture(c);
    }


    public void resetContext() {
        AIChat old = currentChat;
        currentChat = null;
        currentCredential = null;
        currentModel = null;
        chatCache.clear();
        skillCache.clear();
        configCache.clear();
        captureAreaSet.clearCaptureAreas();
        pcs.firePropertyChange("currentChat", old, null);
    }
}
