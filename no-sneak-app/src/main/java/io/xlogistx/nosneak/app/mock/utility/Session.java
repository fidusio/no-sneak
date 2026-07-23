package io.xlogistx.nosneak.app.mock.utility;

import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;

import javax.crypto.SecretKey;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Authentication and account state for the signed-in subject, backed by a
 * {@link DomainSecurityManager}. Tracks the current principalID (login identifier) and its
 * subject, and fires an {@code "authenticated"} property-change event on every login/logout.
 *
 * <p>Result convention: the account-edit methods return a reason {@link String} where
 * {@code null} means success and a non-null value is a human-readable error to show the user.
 * The plain login methods return a {@code boolean} instead.</p>
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
    private final DomainSecurityManager domainSecurityManager;
    private boolean authenticated;
    private String principalID;
    private SubjectIdentifier subjectIdentifier;

    public DomainSecurityManager getDomainSecurityManager() {
        return domainSecurityManager;
    }

    public enum APIKeyInfo implements GetName {
        PROVIDER("provider"),
        BASE_URL("base-url"),
        AUTH_SCHEME("auth-type"),
        HEADER_NAME("header-name");

        private final String name;

        APIKeyInfo(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    /**
     * Creates a session over the given security manager; starts signed out.
     */
    public Session(DomainSecurityManager domainSecurityManager) {
        this.domainSecurityManager = domainSecurityManager;
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
     * Logs in with a username/password. @return {@code true} on success, {@code false} otherwise.
     */
    public void loginUsernamePassword(String subject, char[] password) throws SecurityException {

        try {
            subjectIdentifier = domainSecurityManager.login(subject, new String(password));
        } catch (SecurityException e) {
            throw new SecurityException("Invalid Credentials", e);
        }

        this.principalID = subject;
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }


    /**
     * Logs in with a (plain-stored) API key. @return {@code null} on success, else an error message.
     */
    public void loginAPIKey(char[] apiKey) throws SecurityException {

        try {
            // Stored plain (see storeAPIKey), so look it up as-is — no hashing.
            subjectIdentifier = domainSecurityManager.loginApiKey(new String(apiKey));
        } catch (SecurityException p) {
            throw new SecurityException("API Key Invalid", p);
        }

        if (subjectIdentifier == null) throw new SecurityException("Could not log in");

        PrincipalIdentifier[] principals = domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID());
        this.principalID = (principals.length > 0) ? principals[0].getPrincipalID() : null;

        if (principals.length == 0) {
            subjectIdentifier = null;
            throw new SecurityException("Could not log in");
        }

        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    /**
     * Mock passkey login; not implemented yet. @return {@code false}.
     */
    //@TODO
    public void loginPasskey() {

    }


    /**
     * Creates a new username/password account (does not log in). @return {@code null} on success, else an error message.
     */
    public void registerUsernamePassword(String subject, char[] password) throws SecurityException {
        // TBD change the signature to void explicitly declare thrown exception
        if (!FilterType.PASSWORD.isValid(new String(password))) throw new SecurityException(PASSWORD_RULES_MESSAGE);
        try {
            domainSecurityManager.createSubjectID(subject, HashUtil.toBCryptPassword(new String(password)));
        } catch (SecurityException e) {
            throw new SecurityException("That username is already taken", e);
        }
    }

    /**
     * Generates a fresh AES-256 key as a URL-Base64 string (not stored). @return the key, or {@code null} when signed out or generation fails.
     */
    public SubjectAPIKey generateAPIKey() throws SecurityException {
        // TBD return api key, or null if it cannot
        // principalID should be changed to support security model of logged-in user
        // refer to MN
        if (principalID == null) throw new SecurityException("Not signed in");
        SecretKey secretKey;

        try {
            secretKey = CryptoUtil.generateKey(CryptoConst.CryptoAlgo.AES, 256);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Could not generate a key", e);
        }

        SubjectAPIKey sak = new SubjectAPIKey();
        sak.setAPIKeyAsBytes(secretKey.getEncoded());
        return sak;
    }

    /**
     * Stores a new API key (plain) with an optional label/description. @return {@code null} on success, else an error message.
     */
    public void storeAPIKey(String label, String description, String domainID, String appID, String rawKey,
                            String provider, String baseURI, String authScheme, String headerName, Boolean external) throws SecurityException {


        if (principalID == null) throw new SecurityException("Not signed in");
        if (rawKey == null || rawKey.isBlank()) throw new SecurityException("Key cannot be empty");

        APIKey<String> key = new SubjectAPIKey();
        NVGenericMap props = key.getProperties();

        if (external) {
            if (appID != null && !appID.isBlank() && domainID != null && !domainID.isBlank()) {
                try {
                    key.setAppID(new AppIDDefault(domainID.trim(), appID.trim()));
                } catch (IllegalArgumentException e) {
                    throw new SecurityException("Invalid domain or app ID", e);
                }
                props.build(new NVBoolean("external", true));
            }
        } else {
            AppIDDefault noSneakAppID = new AppIDDefault();
            noSneakAppID.setDomainAppID("xlogistx.io", "nosneak");
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
    }

    private static void putIfPresent(NVGenericMap props, GetName name, String value) {
        if (value != null && !value.isBlank()) props.build(name, value.trim());
    }

    /**
     * Permanently deletes an API key. @return {@code null} on success, else an error message.
     */
    public void deleteAPIKey(APIKey<String> key) throws SecurityException {

        // signature to void, throw security exception
        if (subjectIdentifier == null) throw new SecurityException("Not signed in");
        if (key == null) throw new SecurityException("Empty Key");

        domainSecurityManager.deleteCredential(key);
    }


    public void rotateAPIKey(APIKey<String> key) throws SecurityException {

        if (subjectIdentifier == null) throw new SecurityException("Not signed in");
        if (key == null) throw new SecurityException("Empty Key");

        if (isExternalKey(key)) throw new SecurityException("Cannot rotate external key");

        SubjectAPIKey fresh = generateAPIKey();

        key.setAPIKey(fresh.getAPIKey());

        domainSecurityManager.updateCredential(subjectIdentifier, key);
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
    //@TODO
    public void registerPasskey() {
        //loginPasskey();

    }


    /**
     * Signs the subject out and fires the {@code "authenticated"} change event. @return {@code true}.
     */
    public void logout() {
        boolean old = this.authenticated;
        this.authenticated = false;
        this.principalID = null;
        this.subjectIdentifier = null;
        pcs.firePropertyChange("authenticated", old, false);
    }

    /**
     * @return the signed-in subject's identifiers, or an empty array when signed out.
     */
    public PrincipalIdentifier[] getAllPrincipalIDForLoggedInUser() {
        if (subjectIdentifier == null) return new PrincipalIdentifier[0];
        return domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID());
    }

    /**
     * @return the signed-in subject's credentials, or an empty array when signed out.
     */
    public CredentialInfo[] getAllCredentialForLoggedInUser() {
        if (principalID == null) return new CredentialInfo[0];
        return domainSecurityManager.lookupAllPrincipalCredentials(principalID);
    }

    /**
     * @return the signed-in subject's credentials of the given type, or an empty array when signed out or {@code type} is null.
     */
    public CredentialInfo[] getAllCredentialForUserByType(CredentialInfo.Type type) {
        if (subjectIdentifier == null) return new CredentialInfo[0];
        if (type == null) return new CredentialInfo[0];

        return domainSecurityManager.lookupCredentialsBySubjectGUID(subjectIdentifier.getSubjectGUID(), type);
    }

    /**
     * Adds a new identifier to the signed-in subject (rejects blank/duplicate). @return {@code null} on success, else an error message.
     */
    public void addIdentifier(String principalID) throws SecurityException {
//        if (subjectIdentifier == null) throw new SecurityException("Not signed in");
//        if (principalID == null || principalID.isBlank()) throw new SecurityException("Identifier cannot be empty");
//        if (domainSecurityManager.lookupPrincipalID(principalID) != null) {
//            throw new SecurityException("That identifier is already in use");
//        }
        domainSecurityManager.addPrincipalID(subjectIdentifier, principalID);
    }


    /**
     * Removes an identifier (never the last one); if it was the identifier you logged in as,
     * the active principalID is repointed to a survivor. @return {@code null} on success, else an error message.
     */
    public void removeIdentifier(PrincipalIdentifier principal) throws SecurityException {

        if (principal == null) throw new SecurityException("Identifier cannot be empty");
        if (subjectIdentifier == null) throw new SecurityException("Not Signed in");

        if (!domainSecurityManager.deletePrincipalID(principal)) {
            throw new SecurityException("Could not remove identifier");
        }

        if (principal.getPrincipalID().equals(principalID)) {
            PrincipalIdentifier[] remaining = getAllPrincipalIDForLoggedInUser();
            if (remaining.length > 0) {
                principalID = remaining[0].getPrincipalID();
            }
        }
    }


    /**
     * Verifies the current password and replaces it in place. @return {@code null} on success, else an error message.
     */
    public void changePassword(char[] current, char[] next) throws SecurityException {
        if (principalID == null) throw new SecurityException("Not Logged in");

        // 1. verify the current password
        try {
            domainSecurityManager.login(principalID, new String(current));
        } catch (SecurityException e) {
            throw new SecurityException("Current password is incorrect", e);
        }

        // 2. validate the new password against the policy
        if (!FilterType.PASSWORD.isValid(new String(next))) {
            throw new SecurityException("New password does not meet requirements");
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
                                 String provider, String baseURI, String authScheme, String headerName) throws SecurityException {

        if (principalID == null) throw new SecurityException("Not Logged in");
        if (apiKey == null) throw new SecurityException("Invalid API Key");

        if (label != null) apiKey.setName(label.trim());
        if (description != null) apiKey.setDescription(description.trim());

        if (appID != null && !appID.isBlank() && domainID != null && !domainID.isBlank()) {
            try {
                apiKey.setAppID(new AppIDDefault(domainID.trim(), appID.trim()));
            } catch (IllegalArgumentException e) {
                throw new SecurityException("Invalid domain or app ID", e);
            }
        }

        apiKey.getProperties().build(APIKeyInfo.PROVIDER, provider == null ? "" : provider.trim());
        apiKey.getProperties().build(APIKeyInfo.BASE_URL, baseURI == null ? "" : baseURI.trim());
        apiKey.getProperties().build(APIKeyInfo.AUTH_SCHEME, authScheme == null ? "" : authScheme.trim());
        apiKey.getProperties().build(APIKeyInfo.HEADER_NAME, headerName == null ? "" : headerName.trim());

        domainSecurityManager.updateCredential(subjectIdentifier, apiKey);
    }

    /**
     * Saves the given profile fields into the subject's property bag. @return {@code null} on success, else an error message.
     */
    public void saveProfile(Map<String, String> fields) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
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


    public void changeAddressDetails(NVGenericMap address) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        if (address == null) throw new SecurityException("Invalid address");

        NVGenericMap props = subjectIdentifier.getProperties();
        NVGenericMapList list = props == null ? null : props.lookup(ADDRESSES);
        boolean stored = list != null && list.getValue().stream().anyMatch(a -> a == address);
        if (!stored) throw new SecurityException("Address not found");

        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    public void addAddress(NVGenericMap address) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        if (address == null) throw new SecurityException("Invalid address");

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

    public void deleteAddress(NVGenericMap address) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        if (address == null) throw new SecurityException("Invalid address");

        NVGenericMap props = subjectIdentifier.getProperties();
        NVGenericMapList list = props == null ? null : props.lookup(ADDRESSES);
        if (list == null) throw new SecurityException("No addresses to delete");

        list.getValue().remove(address);
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    /**
     * Registers a listener for the {@code "authenticated"} login/logout change event.
     */
    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }
}