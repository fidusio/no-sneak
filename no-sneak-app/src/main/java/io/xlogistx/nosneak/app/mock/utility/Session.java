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
import org.zoxweb.shared.util.SharedBase64;

import javax.crypto.SecretKey;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
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
    private static final String PASSWORD_RULES_MESSAGE = "Your password must meet all of the following requirements:\n\n" +
            "• Be at least 8 characters long.\n" +
            "• Include at least one uppercase letter (A–Z).\n" +
            "• Include at least one number (0–9).\n" +
            "• Include at least one special character (such as !, @, #, $, %, &, *).\n" +
            "• Cannot be empty or contain only spaces.";
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
    public boolean loginUsernamePassword(String subject, char[] password) {

        try {
            subjectIdentifier = domainSecurityManager.login(subject, new String(password));
        } catch (SecurityException e) {
            return false;
        }

        // Keep the principalID (the username the user typed) — SubjectIdentifier.getSubjectID()
        // returns the numeric GUID, and the backend's credential lookups are keyed by principalID.
        this.principalID = subject;
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);

        return true;
    }


    /**
     * Logs in with a (plain-stored) API key. @return {@code null} on success, else an error message.
     */
    public String loginAPIKey(char[] apiKey) {

        try {
            // Stored plain (see createAPIKey), so look it up as-is — no hashing.
            subjectIdentifier = domainSecurityManager.loginApiKey(new String(apiKey));
        } catch (SecurityException p) {
            return "API Key Invalid";
        }

        if (subjectIdentifier == null) return "Not Logged in";

        PrincipalIdentifier[] principals = domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID());
        this.principalID = (principals.length > 0) ? principals[0].getPrincipalID() : null;

        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);

        return null;
    }

    /**
     * Mock passkey login; not implemented yet. @return {@code false}.
     */
    //@TODO
    public boolean loginPasskey() {
        /*
        this.subject = "";
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
        */
        return false;
    }


    /**
     * Creates a new username/password account (does not log in). @return {@code null} on success, else an error message.
     */
    public String registerUsernamePassword(String subject, char[] password) {
        if (!FilterType.PASSWORD.isValid(new String(password))) return PASSWORD_RULES_MESSAGE;
        try {
            domainSecurityManager.createSubjectID(subject, HashUtil.toBCryptPassword(new String(password)));
            return null;
        } catch (SecurityException e) {
            return "That username is already taken";
        }

    }

    /**
     * Generates a fresh AES-256 key as a URL-Base64 string (not stored). @return the key, or {@code null} when signed out or generation fails.
     */
    public String generateAPIKey() {
        if (principalID == null) return null;
        SecretKey secretKey;

        try {
            secretKey = CryptoUtil.generateKey(CryptoConst.CryptoAlgo.AES, 256);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        byte[] raw = secretKey.getEncoded();

        return SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, raw);
    }

    /**
     * Stores a new API key (plain) with an optional label/description. @return {@code null} on success, else an error message.
     */
    public String createAPIKey(String label, String description, String domainID, String appID, String rawKey) {

        // no hash, store as bytes

        if (principalID == null) return "Not signed in";
        if (rawKey == null || rawKey.isBlank()) return "Key cannot be empty";

        APIKey<String> key = new SubjectAPIKey();

        if(appID != null && !appID.isBlank() && domainID != null && !domainID.isBlank()) {
            String trimmedAppID = appID.trim();
            String trimmedDomainID = domainID.trim();
            AppIDDefault tempAppID = new AppIDDefault(trimmedDomainID, trimmedAppID);
            key.setAppID(tempAppID);
        }


        key.setAPIKey(rawKey);
        key.setCredentialStatus(SecConst.SecStatus.ACTIVE);

        if (label != null && !label.isBlank()) key.setName(label.trim());
        if (description != null && !description.isBlank()) key.setDescription(description.trim());
        domainSecurityManager.createCredential(subjectIdentifier, key);

        return null;
    }

    /**
     * Permanently deletes an API key. @return {@code null} on success, else an error message.
     */
    public String revokeAPIKey(APIKey<String> key) {

        if (subjectIdentifier == null) return "Not signed in";
        if (key == null) return "Empty Key";

        domainSecurityManager.deleteCredential(key);

        return null;
    }


    /**
     * Issues a fresh secret for {@code key}, invalidating the old one. Follows the
     * {@code null == success} convention so it works with {@code BackgroundTask.runReason}.
     * On success the new secret is available from {@code key.getAPIKey()} (the passed
     * key is mutated in place), so the caller can show/copy it.
     */
    public String rotateAPIKey(APIKey<String> key) {

        if (subjectIdentifier == null) return "Not signed in";
        if (key == null) return "Empty Key";

        String fresh = generateAPIKey();
        if (fresh == null) return "Could not generate a new key";

        key.setAPIKey(fresh);

        domainSecurityManager.updateCredential(subjectIdentifier, key);
        return null;
    }

    /**
     * Mock passkey registration; not implemented yet. @return {@code false}.
     */
    //@TODO
    public boolean registerPasskey() {
        //loginPasskey();

        return false;
    }


    /**
     * Signs the subject out and fires the {@code "authenticated"} change event. @return {@code true}.
     */
    public boolean logout() {
        boolean old = this.authenticated;
        this.authenticated = false;
        this.principalID = null;
        this.subjectIdentifier = null;
        pcs.firePropertyChange("authenticated", old, false);

        return true;
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
    public String addIdentifier(String principalID) {
        if (subjectIdentifier == null) return "Not signed in";
        if (principalID == null || principalID.isBlank()) return "Identifier cannot be empty";
        if (domainSecurityManager.lookupPrincipalID(principalID) != null) {
            return "That identifier is already in use";
        }
        domainSecurityManager.addPrincipalID(subjectIdentifier, principalID);
        return null;
    }


    /**
     * Removes an identifier (never the last one); if it was the identifier you logged in as,
     * the active principalID is repointed to a survivor. @return {@code null} on success, else an error message.
     */
    public String removeIdentifier(PrincipalIdentifier principal) {

        if (!((getAllPrincipalIDForLoggedInUser().length - 1) > 0)) return "Cannot remove the last identifier";
        if (principal == null) return "Identifier cannot be empty";

        if (!domainSecurityManager.deletePrincipalID(principal)) {
            return "Could not remove identifier";
        }

        if (principal.getPrincipalID().equals(principalID)) {
            PrincipalIdentifier[] remaining = getAllPrincipalIDForLoggedInUser();
            if (remaining.length > 0) {
                principalID = remaining[0].getPrincipalID();
            }
        }

        return null;
    }


    /**
     * Verifies the current password and replaces it in place. @return {@code null} on success, else an error message.
     */
    public String changePassword(char[] current, char[] next) {
        if (principalID == null) return "Not signed in";

        // 1. verify the current password
        try {
            domainSecurityManager.login(principalID, new String(current));
        } catch (SecurityException e) {
            return "Current password is incorrect";
        }

        // 2. validate the new password against the policy
        if (!FilterType.PASSWORD.isValid(new String(next))) {
            return "New password does not meet requirements";
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
        return null;
    }

    /**
     * Updates an API key's label and description (blanks clear them). @return {@code null} on success, else an error message.
     */
    public String changeAPIDetails(APIKey<String> apiKey, String label, String description) {

        if (principalID == null) return "Not signed in";

        apiKey.setName(label.trim());
        apiKey.setDescription(description.trim());

        domainSecurityManager.updateCredential(subjectIdentifier, apiKey);

        return null;
    }

    /**
     * Saves the given profile fields into the subject's property bag. @return {@code null} on success, else an error message.
     */
    public String saveProfile(Map<String, String> fields) {
        if (subjectIdentifier == null) return "Not Logged in";
        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) {
            props = new NVGenericMap();
            subjectIdentifier.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        NVGenericMap finalProps = props;
        fields.forEach((k, v) -> finalProps.build(k, v == null ? "" : v));
        domainSecurityManager.updateSubjectID(subjectIdentifier);

        return null;
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
