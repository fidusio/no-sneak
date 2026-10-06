package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.data.ReportContent;
import io.xlogistx.shiro.SubjectSwap;
import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import io.xlogistx.shiro.ds.DSAuthorizingRealm;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.*;

import javax.crypto.SecretKey;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Supplier;


/**
 * Authentication and account state for the signed-in subject, backed by a
 * {@link ShiroDSDomainSecurityManager}. Tracks the current principalID (login identifier) and its
 * subject, and fires an {@code "authenticated"} property-change event on every login/logout.
 *
 * <p><b>The login is a Shiro subject login, kept unbound (2026-10-05).</b> The h2p store checks
 * every read and write against the subject bound to the calling thread, and the panels run their
 * work on {@code SwingWorker} pool threads — a thread-bound login would leave a subject on
 * whichever pool thread happened to run it. So {@link #loginUsernamePassword} logs the Shiro
 * {@link Subject} in without binding it ({@link #subject}), and every datastore call made through
 * this class goes through {@link #getDataStore()} — a view of the store that binds that subject
 * for the duration of the call with xlogistx-shiro's {@link SubjectSwap} and restores the thread's
 * previous state afterwards. {@link #asSubject} does the same for arbitrary work. The manager's
 * own calls (credentials, principals, profile) need no binding: the manager runs its store access
 * in the system context and permission enforcement is off in a desktop store.</p>
 *
 * <p>Result convention: the account-edit methods throw {@link AccessSecurityException} with a
 * human-readable reason and return normally on success.</p>
 */
public class Session {
    private static final String PASSWORD_RULES_MESSAGE = """
            Your password must meet all of the following requirements:
            
            • Be at least 8 characters long.
            • Include at least one uppercase letter (A–Z).
            • Include at least one number (0–9).
            • Include at least one special character (such as !, @, #, $, %, &, *).
            • Cannot be empty or contain only spaces.""";
    private static final String ADDRESSES = "addresses";
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);
    /** The app no-sneak is in the app model: {@code xlogistx.com-nosneak} (user, 2026-10-05). */
    public static final String NO_SNEAK_DOMAIN_ID = "xlogistx.com";
    public static final String NO_SNEAK_APP_ID = "nosneak";

    private final ShiroDSDomainSecurityManager domainSecurityManager;
    /** The store as configured: what the manager uses, and what system-context work (backup) needs. */
    private final APIDataStore<?, ?> rawStore;
    /** The subject view of {@link #rawStore}: every call runs with {@link #subject} bound. */
    private final APIDataStore<?, ?> ds;
    /** The logged-in Shiro subject, never bound to a thread outside a {@link SubjectSwap}; null when signed out. */
    private volatile Subject subject;
    private boolean authenticated;
    private String principalID;
    private SubjectIdentifier subjectIdentifier;
    private NIOSocket nio;

    public ShiroDSDomainSecurityManager getDomainSecurityManager() {
        return domainSecurityManager;
    }

    /**
     * The datastore as the signed-in subject sees it: each call binds the Shiro subject to the
     * calling thread for its duration ({@link SubjectSwap}), so the store's access check and its
     * field encryption see the owner, on whatever worker thread the call lands. Signed out, the
     * calls go through unbound and the store returns nothing (and refuses writes). This is the
     * store every screen and {@code AssistantStorage} must use — never the manager's raw one.
     */
    public APIDataStore<?, ?> getDataStore() {
        return ds;
    }

    /** Runs {@code work} with the signed-in subject bound to the calling thread (a no-op binding when signed out). */
    public <V> V asSubject(Supplier<V> work) {
        try (SubjectSwap swap = new SubjectSwap(subject)) {
            return work.get();
        }
    }

    /** {@link #asSubject(Supplier)} for work without a result. */
    public void asSubject(Runnable work) {
        try (SubjectSwap swap = new SubjectSwap(subject)) {
            work.run();
        }
    }

    /**
     * Runs {@code work} in the store's system context — the datastore access checks are lifted
     * for it. For whole-store operations only (backup, restore), never for a screen's own reads.
     */
    public <V> V runAsSystem(Supplier<V> work) {
        APIConfigInfo cfg = rawStore.getAPIConfigInfo();
        SecurityController sc = cfg != null ? cfg.getSecurityController() : null;
        return sc != null ? sc.runAsSystem(work) : work.get();
    }

    /** A {@link Proxy} over the store's interfaces that wraps each call in a {@link SubjectSwap} of the current subject. */
    private APIDataStore<?, ?> subjectView(APIDataStore<?, ?> store) {
        Set<Class<?>> interfaces = new LinkedHashSet<>();
        for (Class<?> c = store.getClass(); c != null; c = c.getSuperclass()) {
            Collections.addAll(interfaces, c.getInterfaces());
        }
        interfaces.add(APIDataStore.class);
        return (APIDataStore<?, ?>) Proxy.newProxyInstance(store.getClass().getClassLoader(),
                interfaces.toArray(new Class<?>[0]),
                (proxy, method, args) -> {
                    try (SubjectSwap swap = new SubjectSwap(subject)) {
                        return method.invoke(store, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    /**
     * The scanning socket, shared by every scan and opened on first use — a subject who never
     * opens the scan screen never pays for a selector or its reader threads.
     * <p>
     * Callers run off the EDT, so a failure to open surfaces as an {@link IllegalStateException}
     * that {@code BackgroundTask} turns into a dialog, rather than leaving a null field for a
     * later NPE somewhere unrelated.
     *
     * @see #closeNio()
     */
    public synchronized NIOSocket getNio() {
        if (nio == null) {
            try {
                nio = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            } catch (Exception e) {
                throw new IllegalStateException("Could not open the scanning socket: " + e.getMessage(), e);
            }
        }
        return nio;
    }

    /**
     * Closes the scanning socket if it was ever opened; a later {@link #getNio()} reopens it.
     * Called from the frame's window-closing handler beside the datastore close — not on logout,
     * since the store stays open across sign-outs too.
     */
    public synchronized void closeNio() {
        SharedIOUtil.close(nio);
        nio = null;
    }

    /**
     * Keys for the AI-assistant metadata kept on an API key's property bag.
     * <p>
     * <b>Only some of these are live.</b> {@code PROVIDER} and {@code BASE_URL} seed a new
     * {@code AIProviderConfig} when a key is first linked, and {@code ASSISTANT_ENABLED} records
     * whether the subject has linked the key at all.
     * <p>
     * {@code AUTH_SCHEME} and {@code HEADER_NAME} are <b>vestigial</b>: they are still written by
     * the Add/Edit key forms and round-tripped unchanged, but nothing reads them when building a
     * request — the provider resolves everything from its {@code AIProviderConfig} now. Setting
     * them has no effect on what goes over the wire.
     */
    public enum APIKeyInfo implements GetName {
        PROVIDER("provider"),
        BASE_URL("base-url"),
        AUTH_SCHEME("auth-type"),
        HEADER_NAME("header-name"),
        ASSISTANT_ENABLED("assistant-enabled"),
        /**
         * The vendor's domain and app of an <b>external</b> key, kept as metadata (2026-10-05): the
         * key's own {@code app_id} field is an app-model scope that the Shiro manager resolves to
         * an app record of this store, which a third party's app never is.
         */
        VENDOR_DOMAIN("vendor-domain"),
        VENDOR_APP("vendor-app");

        private final String name;

        APIKeyInfo(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public String getSubjectGUID() {
        return subjectIdentifier != null ? subjectIdentifier.getSubjectGUID() : null;
    }

    /**
     * Creates a session over the given security manager; starts signed out.
     */
    public Session(ShiroDSDomainSecurityManager domainSecurityManager) {
        this.domainSecurityManager = domainSecurityManager;
        rawStore = domainSecurityManager.getDataStore();
        ds = subjectView(rawStore);
    }


    /**
     * @return {@code true} if a subject is currently signed in.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }


    /**
     * @return the signed-in principalID (login identifier), or {@code null} when signed out.
     */
    public String getPrincipalID() {
        return principalID;
    }


    /**
     * Logs in with a username/password as a Shiro subject scoped to the no-sneak app
     * ({@code xlogistx.com-nosneak}). The subject is logged in <b>unbound</b> — the same thing the
     * manager's {@code loginUnboundSubjectJWT} does for a token, built here for a password because
     * the manager has no password variant: a {@link Subject} from the manager's security manager,
     * logged in with a {@link DomainUsernamePasswordToken}, never put on the calling thread. It is
     * bound per call by {@link #getDataStore()} / {@link #asSubject}.
     *
     * @throws AccessSecurityException {@code "Invalid Credentials"} on any authentication failure
     */
    public void loginUsernamePassword(String subject, char[] password) throws AccessSecurityException {
        if (SUS.isEmpty(subject) || password == null) throw new AccessSecurityException("Invalid Credentials");

        Subject shiro = new Subject.Builder(domainSecurityManager.getSecurityManager()).buildSubject();
        SubjectIdentifier si;
        try {
            shiro.login(new DomainUsernamePasswordToken(subject.trim(), new String(password), false, null,
                    NO_SNEAK_DOMAIN_ID, NO_SNEAK_APP_ID));
            si = domainSecurityManager.lookupSubjectByGUID(DSAuthorizingRealm.subjectGUIDOf(shiro.getPrincipals()));
        } catch (RuntimeException e) {
            // AuthenticationException (unknown or inactive principal, bad password) or an invalid
            // principal id from the manager: one answer for all
            throw new AccessSecurityException("Invalid Credentials", e);
        }
        if (si == null) {
            shiro.logout();
            throw new AccessSecurityException("Invalid Credentials");
        }

        Subject previous = this.subject;
        this.subject = shiro;
        this.subjectIdentifier = si;
        Object principal = shiro.getPrincipal();
        this.principalID = principal != null ? principal.toString() : subject.trim();
        if (previous != null) endSubject(previous);
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    private static void endSubject(Subject s) {
        try {
            s.logout();
        } catch (RuntimeException ignore) {
            // the session may already be gone; the subject is dropped either way
        }
    }

    /**
     * Mock passkey login; not implemented yet. @return {@code false}.
     */
    public void loginPasskey() {

    }


    /**
     * Creates a new username/password account (does not log in). @return {@code null} on success, else an error message.
     */
    public void registerUsernamePassword(String subject, char[] password) throws AccessSecurityException {
        // TBD change the signature to void explicitly declare thrown exception
        if (!FilterType.PASSWORD.isValid(new String(password))) throw new AccessSecurityException(PASSWORD_RULES_MESSAGE);
        try {
            domainSecurityManager.createSubjectID(subject, HashUtil.toBCryptPassword(new String(password)));
        } catch (AccessSecurityException e) {
            // only a duplicate principal reads as "taken"; a store failure keeps its own reason
            String reason = e.getMessage() == null ? "" : e.getMessage();
            if (reason.contains("already exists")) throw new AccessSecurityException("That username is already taken", e);
            throw new AccessSecurityException("Registration failed: " + rootMessage(e), e);
        } catch (RuntimeException e) {
            throw new AccessSecurityException("Registration failed: " + rootMessage(e), e);
        }
    }

    /** The innermost message of a cause chain: what a dialog should show for a store failure. */
    private static String rootMessage(Throwable t) {
        Throwable root = t;
        while (root.getCause() != null && root.getCause() != root) root = root.getCause();
        return root.getMessage() != null ? root.getMessage() : root.toString();
    }

    /**
     * Generates a fresh AES-256 key as a URL-Base64 string (not stored). @return the key, or {@code null} when signed out or generation fails.
     */
    public SubjectAPIKey generateAPIKey() throws AccessSecurityException {
        // TBD return api key, or null if it cannot
        // principalID should be changed to support security model of logged-in user
        // refer to MN
        if (principalID == null) throw new AccessSecurityException("Not signed in");
        SecretKey secretKey;

        try {
            secretKey = CryptoUtil.generateSecretKey(CryptoConst.CryptoAlgo.AES, 256);
        } catch (NoSuchAlgorithmException e) {
            throw new AccessSecurityException("Could not generate a key", e);
        }

        SubjectAPIKey sak = new SubjectAPIKey();
        sak.setAPIKeyAsBytes(secretKey.getEncoded());
        return sak;
    }

    /**
     * Stores a new API key (plain) with an optional label/description.
     *
     * @return the created credential
     */
    public SubjectAPIKey storeAPIKey(String label, String description, String domainID, String appID, String rawKey,
                                     String provider, String baseURI, String authScheme, String headerName, Boolean external) throws AccessSecurityException {


        if (principalID == null) throw new AccessSecurityException("Not signed in");
        if (rawKey == null || rawKey.isBlank()) throw new AccessSecurityException("Key cannot be empty");

        SubjectAPIKey key = new SubjectAPIKey();
        NVGenericMap props = key.getProperties();

        if (external) {
            // external is stamped unconditionally: a vendor key stored without a domain/app-id
            // pair must still read as external, or rotate could overwrite its real secret
            props.build(new NVBoolean("external", true));
            // the vendor's domain/app is metadata, never the key's app-model scope (see APIKeyInfo)
            putVendor(props, domainID, appID);
        } else {
            AppIDDefault noSneakAppID = new AppIDDefault();
            noSneakAppID.setDomainAppID(NO_SNEAK_DOMAIN_ID, NO_SNEAK_APP_ID);
            props.build(new NVBoolean("external", false));
            key.setAppID(noSneakAppID);
        }

        key.setAPIKey(rawKey);
        key.setCredentialStatus(SecConst.SecStatus.ACTIVE);

        putIfPresent(props, APIKeyInfo.PROVIDER, provider);
        putIfPresent(props, APIKeyInfo.BASE_URL, baseURI);
        putIfPresent(props, APIKeyInfo.AUTH_SCHEME, authScheme);
        putIfPresent(props, APIKeyInfo.HEADER_NAME, headerName);

        if (label != null && !label.isBlank()) key.setName(label.trim());
        if (description != null && !description.isBlank()) key.setDescription(description.trim());
        domainSecurityManager.createCredential(subjectIdentifier, key);
        pcs.firePropertyChange("credentials", null, key);
        return key;
    }

    private static void putIfPresent(NVGenericMap props, GetName name, String value) {
        if (value != null && !value.isBlank()) props.build(name, value.trim());
    }

    /**
     * Stores a vendor's domain and app on an external key's property bag when both are given,
     * normalized and validated through the same filters an {@link AppIDDefault} applies (lower
     * case, {@code FilterType.DOMAIN}, the app-id name filter); one part alone is ignored.
     *
     * @throws AccessSecurityException {@code "Invalid domain or app ID"} when a part fails its filter
     */
    private static void putVendor(NVGenericMap props, String domainID, String appID) throws AccessSecurityException {
        if (appID == null || appID.isBlank() || domainID == null || domainID.isBlank()) return;
        AppIDDefault vendor;
        try {
            vendor = new AppIDDefault(domainID.trim(), appID.trim());
        } catch (IllegalArgumentException e) {
            throw new AccessSecurityException("Invalid domain or app ID", e);
        }
        props.build(APIKeyInfo.VENDOR_DOMAIN, vendor.getDomainID());
        props.build(APIKeyInfo.VENDOR_APP, vendor.getAppID());
    }

    /** @return the vendor domain recorded on an external key, or null. */
    public String vendorDomainOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.VENDOR_DOMAIN);
        return v == null ? null : v.toString();
    }

    /** @return the vendor app id recorded on an external key, or null. */
    public String vendorAppOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.VENDOR_APP);
        return v == null ? null : v.toString();
    }

    private static NVGenericMap propertiesOf(APIKey<String> key) throws AccessSecurityException {
        NVGenericMap props = key.getProperties();
        if (props == null) {
            if (!(key instanceof PropertyDAO dao)) throw new AccessSecurityException("Key cannot store properties");
            props = new NVGenericMap();
            dao.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        return props;
    }

    /**
     * Permanently deletes an API key. @return {@code null} on success, else an error message.
     */
    public void deleteAPIKey(APIKey<String> key) throws AccessSecurityException {

        // signature to void, throw security exception
        if (subjectIdentifier == null) throw new AccessSecurityException("Not signed in");
        if (key == null) throw new AccessSecurityException("Empty Key");

        domainSecurityManager.deleteCredential(key);
        pcs.firePropertyChange("credentials", null, key);
    }


    public void rotateAPIKey(APIKey<String> key) throws AccessSecurityException {

        if (subjectIdentifier == null) throw new AccessSecurityException("Not signed in");
        if (key == null) throw new AccessSecurityException("Empty Key");

        if (isExternalKey(key)) throw new AccessSecurityException("Cannot rotate external key");

        SubjectAPIKey fresh = generateAPIKey();

        key.setAPIKey(fresh.getAPIKey());

        domainSecurityManager.updateCredential(subjectIdentifier, key);
        pcs.firePropertyChange("credentials", null, key);
    }

    public boolean isExternalKey(APIKey<String> key) {
        if (key == null) return false;
        NVGenericMap p = key.getProperties();
        return p != null && Boolean.TRUE.equals(p.getValue("external"));
    }


    /**
     * @return the stored AI provider type (e.g. "anthropic"), or null.
     */
    public String providerOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.PROVIDER);
        return v == null ? null : v.toString();
    }

    public boolean isAssistantEnabled(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.ASSISTANT_ENABLED);
        return v != null && Boolean.parseBoolean(v.toString());
    }

    public void setAssistantEnabled(APIKey<String> key, boolean enabled) throws AccessSecurityException {
        if (subjectIdentifier == null) throw new AccessSecurityException("Not signed in");
        if (key == null) throw new AccessSecurityException("Empty Key");

        propertiesOf(key).build(APIKeyInfo.ASSISTANT_ENABLED, Boolean.toString(enabled));
        domainSecurityManager.updateCredential(subjectIdentifier, key);
    }

    /**
     * @return the stored AI endpoint base URL, or null.
     */
    public String baseUrlOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.BASE_URL);
        return v == null ? null : v.toString();
    }

    /**
     * @return the stored auth scheme name (e.g. "Bearer"), or null.
     */
    public String authTypeOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.AUTH_SCHEME);
        return v == null ? null : v.toString();
    }

    public String headerNameOf(APIKey<String> key) {
        NVGenericMap p = key == null ? null : key.getProperties();
        Object v = p == null ? null : p.getValue(APIKeyInfo.HEADER_NAME);
        return v == null ? null : v.toString();
    }

    /**
     * Mock passkey registration; not implemented yet. @return {@code false}.
     */
    public void registerPasskey() {
        //loginPasskey();

    }

    /**
     * Signs the subject out and fires the {@code "authenticated"} change event. @return {@code true}.
     */
    public void logout() {
        boolean old = this.authenticated;
        Subject s = this.subject;
        this.subject = null;
        this.authenticated = false;
        this.principalID = null;
        this.subjectIdentifier = null;
        if (s != null) endSubject(s); // the kept subject can do nothing from here on
        pcs.firePropertyChange("authenticated", old, false);
    }

    /**
     * @return the signed-in subject's identifiers, or an empty list when signed out.
     */
    public List<PrincipalIdentifier> getAllPrincipalIDForLoggedInUser() {
        if (subjectIdentifier == null) return List.of();
        return Arrays.asList(domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID()));
    }

    /**
     * @return the signed-in subject's credentials, or an empty list when signed out.
     */
    public List<CredentialInfo> getAllCredentialForLoggedInUser() {
        if (principalID == null) return List.of();
        return Arrays.asList(domainSecurityManager.lookupAllPrincipalCredentials(principalID));
    }

    /**
     * @return the signed-in subject's credentials of the given type, or an empty list when signed out or {@code type} is null.
     */
    public List<CredentialInfo> getAllCredentialForUserByType(CredentialInfo.Type type) {
        if (subjectIdentifier == null) return List.of();
        if (type == null) return List.of();

        return Arrays.asList(domainSecurityManager.lookupCredentialsBySubjectGUID(subjectIdentifier.getSubjectGUID(), type));
    }

    /**
     * Adds a new identifier to the signed-in subject (rejects blank/duplicate). @return {@code null} on success, else an error message.
     */
    public void addIdentifier(String principalID) throws AccessSecurityException {
//        if (subjectIdentifier == null) throw new AccessSecurityException("Not signed in");
//        if (principalID == null || principalID.isBlank()) throw new AccessSecurityException("Identifier cannot be empty");
//        if (domainSecurityManager.lookupPrincipalID(principalID) != null) {
//            throw new AccessSecurityException("That identifier is already in use");
//        }
        domainSecurityManager.addPrincipalID(subjectIdentifier, principalID);
    }


    /**
     * Removes an identifier (never the last one); if it was the identifier you logged in as,
     * the active principalID is repointed to a survivor. @return {@code null} on success, else an error message.
     */
    public void removeIdentifier(PrincipalIdentifier principal) throws AccessSecurityException {

        if (principal == null) throw new AccessSecurityException("Identifier cannot be empty");
        if (subjectIdentifier == null) throw new AccessSecurityException("Not Signed in");

        if (!domainSecurityManager.deletePrincipalID(principal)) {
            throw new AccessSecurityException("Could not remove identifier");
        }

        if (principal.getPrincipalID().equals(principalID)) {
            List<PrincipalIdentifier> remaining = getAllPrincipalIDForLoggedInUser();
            if (!remaining.isEmpty()) {
                principalID = remaining.getFirst().getPrincipalID();
            }
        }
    }


    /**
     * Verifies the current password and replaces it in place. @return {@code null} on success, else an error message.
     */
    public void changePassword(char[] current, char[] next) throws AccessSecurityException {
        if (principalID == null) throw new AccessSecurityException("Not Logged in");

        // 1. verify the current password (no login: works while a password reset is pending too)
        if (!domainSecurityManager.verifyPassword(principalID, new String(current))) {
            throw new AccessSecurityException("Current password is incorrect");
        }

        // 2. validate the new password against the policy
        if (!FilterType.PASSWORD.isValid(new String(next))) {
            throw new AccessSecurityException("New password does not meet requirements");
        }

        // 3. replace the PASSWORD credential. Hash first, then update the existing entity
        // in place (single update, keyed by GUID) so the subject is never left password-less.
        CIPassword fresh = HashUtil.toBCryptPassword(new String(next));
        CredentialInfo existing = domainSecurityManager.lookupCredential(principalID, CredentialInfo.Type.PASSWORD);
        if (existing instanceof CIPassword existingPw) {

            existingPw.setCanonicalID(fresh.getCanonicalID());
            existingPw.setAlgorithm(fresh.getAlgorithm());
            existingPw.setRounds(fresh.getRounds());
            existingPw.setSalt(fresh.getSalt());
            existingPw.setHash(fresh.getHash());
            // the store's MetaUtil only stamps creation, never updates — stamp here so
            // "last changed" on the credentials list reflects this change
            existingPw.setLastTimeUpdated(System.currentTimeMillis());
            domainSecurityManager.updateCredential(subjectIdentifier, existingPw);
        } else {
            // No existing password credential (shouldn't happen for a normal account) — create one.
            domainSecurityManager.createCredential(principalID, fresh);
        }
    }

    /**
     * Updates an API key's label, description, and AI-assistant metadata (provider, base URL,
     * and whether it appears in the AI assistant). Blanks clear the text fields.
     */
    public void changeAPIDetails(APIKey<String> apiKey, String label, String description,
                                 String domainID, String appID,
                                 String provider, String baseURI, String authScheme, String headerName) throws AccessSecurityException {

        if (principalID == null) throw new AccessSecurityException("Not Logged in");
        if (apiKey == null) throw new AccessSecurityException("Invalid API Key");

        if (label != null) apiKey.setName(label.trim());
        if (description != null) apiKey.setDescription(description.trim());

        NVGenericMap props = propertiesOf(apiKey);
        // only an external key carries a vendor domain/app; a key no-sneak issued keeps its
        // xlogistx.com-nosneak scope, which is not editable
        if (isExternalKey(apiKey)) putVendor(props, domainID, appID);
        props.build(APIKeyInfo.PROVIDER, provider == null ? "" : provider.trim());
        props.build(APIKeyInfo.BASE_URL, baseURI == null ? "" : baseURI.trim());
        props.build(APIKeyInfo.AUTH_SCHEME, authScheme == null ? "" : authScheme.trim());
        props.build(APIKeyInfo.HEADER_NAME, headerName == null ? "" : headerName.trim());

        domainSecurityManager.updateCredential(subjectIdentifier, apiKey);
        pcs.firePropertyChange("credentials", null, apiKey);
    }

    /**
     * Saves the given profile fields into the subject's property bag. @return {@code null} on success, else an error message.
     */
    public void saveProfile(Map<String, String> fields) throws AccessSecurityException {
        if (subjectIdentifier == null) throw new AccessSecurityException("Not Logged in");
        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) {
            props = new NVGenericMap();
            subjectIdentifier.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        NVGenericMap finalProps = props;
        fields.forEach((k, v) -> finalProps.build(k, v == null ? "" : v));
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }


    /**
     * @return the given profile keys mapped to their stored values (empty string when unset or signed out).
     */
    public Map<String, String> loadProfile(String... keys) {
        Map<String, String> out = new LinkedHashMap<>();
        NVGenericMap props = subjectIdentifier == null ? null : subjectIdentifier.getProperties();
        for (String key : keys) {
            Object v = (props == null) ? null : props.getValue(key);
            out.put(key, v == null ? "" : v.toString());
        }
        return out;
    }


    public List<NVGenericMap> getAllAddresses() {
        if (subjectIdentifier == null) return new ArrayList<>();
        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) return new ArrayList<>();

        NVGenericMapList list = props.lookup(ADDRESSES);
        if (list == null) return new ArrayList<>();

        return new ArrayList<>(list.getValue());
    }


    public void changeAddressDetails(NVGenericMap address) throws AccessSecurityException {
        if (subjectIdentifier == null) throw new AccessSecurityException("Not Logged in");
        if (address == null) throw new AccessSecurityException("Invalid address");

        NVGenericMap props = subjectIdentifier.getProperties();
        NVGenericMapList list = props == null ? null : props.lookup(ADDRESSES);
        boolean stored = list != null && list.getValue().stream().anyMatch(a -> a == address);
        if (!stored) throw new AccessSecurityException("Address not found");

        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    public void addAddress(NVGenericMap address) throws AccessSecurityException {
        if (subjectIdentifier == null) throw new AccessSecurityException("Not Logged in");
        if (address == null) throw new AccessSecurityException("Invalid address");

        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) {
            props = new NVGenericMap();
            subjectIdentifier.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        NVGenericMapList list = props.lookup(ADDRESSES);
        if (list == null) {
            list = new NVGenericMapList(ADDRESSES);
            props.add(list);
        }
        list.add(address);
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    public void deleteAddress(NVGenericMap address) throws AccessSecurityException {
        if (subjectIdentifier == null) throw new AccessSecurityException("Not Logged in");
        if (address == null) throw new AccessSecurityException("Invalid address");

        NVGenericMap props = subjectIdentifier.getProperties();
        NVGenericMapList list = props == null ? null : props.lookup(ADDRESSES);
        if (list == null) throw new AccessSecurityException("No addresses to delete");

        list.getValue().remove(address);
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    /**
     * Registers a listener for the {@code "authenticated"} login/logout change event.
     */
    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }

    /**
     * Registers a listener for the {@code "credentials"} change event, fired after an API key is
     * stored, edited, rotated, or deleted — including through the AI assistant's credential
     * source. Mutators run off the EDT, so listeners touching Swing must hop to it themselves.
     */
    public void onCredentialsChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("credentials", l);
    }

    /**
     * Upsert by GUID: an existing row is updated (and stamped as modified, since the store only
     * ever sets a timestamp when it is still 0), a new one gets the owner and is inserted with the
     * store assigning its GUID.
     *
     * @throws IllegalStateException if asked to update a row with no content — that means it came
     *                               from {@link #getAllScanResults()}, and saving it would write
     *                               the missing body over the stored one.
     */
    public ReportContent saveScanResult(ReportContent reportContent) {
        if (SUS.isNotEmpty(reportContent.getGUID())) {
            if (SUS.isEmpty(reportContent.getContent())) {
                throw new IllegalStateException("Refusing to save a scan result with no content — "
                        + "re-read it with getScanResult(guid) before saving a row that came from getAllScanResults()");
            }
            reportContent.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(reportContent);
        }
        reportContent.setSubjectGUID(getSubjectGUID());
        return ds.insert(reportContent);
    }

    public void deleteScanResult(ReportContent reportContent) {
        ds.delete(reportContent, true);
    }

    public ReportContent getScanResult(String guid) {
        List<ReportContent> found = ds.userSearchByID(getSubjectGUID(), ReportContent.NVC_REPORT_CONTENT, guid);
        return found.isEmpty() ? null : found.getFirst();
    }

    /**
     * <b>A projected read — it omits {@code content}.</b> A single /24 report is ~53 KB of JSON and
     * the list only renders a name, the command and a timestamp, so pulling bodies would mean
     * loading every scan in the account to draw a list.
     * <p>
     * Rows from here are therefore <b>not saveable</b>: {@link #saveScanResult} throws rather than
     * letting {@code ds.update} write the missing content over the stored row. Anything that needs
     * the body — viewing, sending to a chat — must re-read through {@link #getScanResult(String)}
     * and handle a null (deleted meanwhile, or signed out).
     */
    public List<ReportContent> getAllScanResults() {
        String o = getSubjectGUID();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(o, ReportContent.NVC_REPORT_CONTENT,
                List.of("subject_guid", "name", "description", "creation_ts", "last_update_ts", "properties"));
    }


    public ProbeContent saveProbe(ProbeContent probeContent) {
        if (SUS.isNotEmpty(probeContent.getGUID())) {
            probeContent.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(probeContent);
        }
        probeContent.setSubjectGUID(getSubjectGUID());
        return ds.insert(probeContent);
    }

    public void deleteProbe(ProbeContent probeContent) {
        ds.delete(probeContent, true);
    }

    public ProbeContent getProbe(String guid) {
        List<ProbeContent> found = ds.userSearchByID(getSubjectGUID(), ProbeContent.NVC_PROBE_CONTENT, guid);
        return found.isEmpty() ? null : found.getFirst();
    }

    public List<ProbeContent> getAllProbes() {
        String o = getSubjectGUID();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(o, ProbeContent.NVC_PROBE_CONTENT, null);
    }

}
