package io.xlogistx.nosneak.app.mock.utility;

import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;

import javax.crypto.SecretKey;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.security.NoSuchAlgorithmException;
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
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);
    private final DomainSecurityManager domainSecurityManager;
    private boolean authenticated;
    private String principalID;
    private SubjectIdentifier subjectIdentifier;

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
            // Stored plain (see createAPIKey), so look it up as-is — no hashing.
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
    public void createAPIKey(String label, String description, String domainID, String appID, String rawKey) throws SecurityException {

        // TBD change the name, throw exception, signature to void

        if (principalID == null) throw new SecurityException("Not signed in");
        if (rawKey == null || rawKey.isBlank()) throw new SecurityException("Key cannot be empty");

        APIKey<String> key = new SubjectAPIKey();

        if (appID != null && !appID.isBlank() && domainID != null && !domainID.isBlank()) {
            String trimmedAppID = appID.trim();
            String trimmedDomainID = domainID.trim();
            AppIDDefault tempAppID = new AppIDDefault(trimmedDomainID, trimmedAppID);
            try {
                key.setAppID(tempAppID);
            } catch (IllegalArgumentException e) {
                throw new SecurityException("Invalid domain or app ID", e);
            }
        }


        key.setAPIKey(rawKey);
        key.setCredentialStatus(SecConst.SecStatus.ACTIVE);

        if (label != null && !label.isBlank()) key.setName(label.trim());
        if (description != null && !description.isBlank()) key.setDescription(description.trim());
        domainSecurityManager.createCredential(subjectIdentifier, key);
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

        SubjectAPIKey fresh = generateAPIKey();

        key.setAPIKey(fresh.getAPIKey());

        domainSecurityManager.updateCredential(subjectIdentifier, key);
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
        if (subjectIdentifier == null) throw new SecurityException("Not signed in");
        if (principalID == null || principalID.isBlank()) throw new SecurityException("Identifier cannot be empty");
        if (domainSecurityManager.lookupPrincipalID(principalID) != null) {
            throw new SecurityException("That identifier is already in use");
        }
        domainSecurityManager.addPrincipalID(subjectIdentifier, principalID);
    }


    /**
     * Removes an identifier (never the last one); if it was the identifier you logged in as,
     * the active principalID is repointed to a survivor. @return {@code null} on success, else an error message.
     */
    public void removeIdentifier(PrincipalIdentifier principal) throws SecurityException {

        if (principal == null) throw new SecurityException("Identifier cannot be empty");
        if (subjectIdentifier == null) throw new SecurityException("Not Signed in");
        if (!((getAllPrincipalIDForLoggedInUser().length - 1) > 0))
            throw new SecurityException("Cannot remove the last identifier");

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
     * Updates an API key's label and description (blanks clear them). @return {@code null} on success, else an error message.
     */
    public void changeAPIDetails(APIKey<String> apiKey, String label, String description) throws SecurityException {

        if (principalID == null) throw new SecurityException("Not Logged in");
        if (apiKey == null) throw new SecurityException("Invalid API Key");

        apiKey.setName(label.trim());
        apiKey.setDescription(description.trim());

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

    private NVGenericMapList addressList(boolean create) {
        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) {
            if (!create) return null;
            props = new NVGenericMap();
            subjectIdentifier.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        NVGenericMapList list = props.lookup("addresses");
        if (list == null && create) { list = new NVGenericMapList("addresses"); props.add(list); }
        return list;
    }

    public List<NVGenericMap> getAddresses() {
        if (subjectIdentifier == null) return java.util.List.of();
        NVGenericMapList list = addressList(false);
        return list == null ? java.util.List.of() : list.getValue();
    }

    public void addAddress(NVGenericMap address) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        addressList(true).add(address);
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    // call after mutating an address in place (edit)
    public void saveAddresses() throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

    public void removeAddress(NVGenericMap address) throws SecurityException {
        if (subjectIdentifier == null) throw new SecurityException("Not Logged in");
        NVGenericMapList list = addressList(false);
        if (list != null) list.getValue().remove(address); // remove by reference
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

    /**
     * Registers a listener for the {@code "authenticated"} login/logout change event.
     */
    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }
}
