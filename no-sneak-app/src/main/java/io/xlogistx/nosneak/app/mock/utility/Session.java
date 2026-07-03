package io.xlogistx.nosneak.app.mock.utility;

import io.xlogistx.nosneak.app.mock.SubjectPanel;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SharedBase64;

import javax.crypto.SecretKey;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Mock authentication/session state. Tracks whether a subject is signed in and
 * fires an {@code "authenticated"} property-change event on every login/logout so
 * the UI can react. All login/register methods are stubs for now.
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
    private String subject;
    private SubjectIdentifier subjectIdentifier;

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
     * @return the signed-in subject's id, or {@code null} when logged out.
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Mock username/password login; marks the session authenticated and fires the change event.
     *
     * @param subject  the subject id
     * @param password the password (unused by the mock)
     */
    //@TODO
    public boolean loginUsernamePassword(String subject, char[] password) {

        try {
            subjectIdentifier = domainSecurityManager.login(subject, new String(password));
        } catch (SecurityException e) {
            return false;
        }

        // Keep the principalID (the username the user typed) — SubjectIdentifier.getSubjectID()
        // returns the numeric GUID, and the backend's credential lookups are keyed by principalID.
        this.subject = subject;
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);

        return true;
    }

    /**
     * Mock API-key login; marks the session authenticated and fires the change event.
     *
     * @param apiKey the API key (unused by the mock)
     */
    //@TODO
    public boolean loginAPIKey(char[] apiKey) {

        try {
            byte[] raw = SharedBase64.decode(SharedBase64.Base64Type.URL, new String(apiKey));
            String hashed = HashUtil.hashAsBase64(CryptoConst.HashType.SHA_256, raw);
            subjectIdentifier = domainSecurityManager.loginApiKey(hashed);
        } catch (ArrayIndexOutOfBoundsException | SecurityException | NoSuchAlgorithmException p) {
            return false;
        }

        if (subjectIdentifier == null) return false;

        PrincipalIdentifier[] principals = domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID());
        this.subject = (principals.length > 0) ? principals[0].getPrincipalID() : null;

        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);

        return true;
    }

    /**
     * Mock passkey login; marks the session authenticated and fires the change event.
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
     * Mock registration: validates the password through {@code FilterType.PASSWORD},
     * then delegates to {@link #loginUsernamePassword}. Does nothing if validation fails.
     *
     * @param subject  the subject id
     * @param password the candidate password
     */
    //@TODO maybe need swing worker
    public String registerUsernamePassword(String subject, char[] password) {
        if (!FilterType.PASSWORD.isValid(new String(password))) return PASSWORD_RULES_MESSAGE;
        try {
            domainSecurityManager.createSubjectID(subject, HashUtil.toBCryptPassword(new String(password)));
            return null;
        } catch (SecurityException e) {
            return "That username is already taken";
        }

    }


    //@TODO
    public String createAPIKey() {

        if (subject == null) return null;
        SecretKey secretKey;

        try {
            secretKey = CryptoUtil.generateKey(CryptoConst.CryptoAlgo.AES, 256);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        byte[] raw = secretKey.getEncoded();
        String rawKey = SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, raw);
        String stored;
        try {
            stored = HashUtil.hashAsBase64(CryptoConst.HashType.SHA_256, raw);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        SubjectAPIKey key = new SubjectAPIKey();
        key.setValue(SubjectAPIKey.Param.API_KEY, stored);
        key.setPrincipalID(subject);
        key.setStatus(Const.Status.ACTIVE);
        domainSecurityManager.createCredential(subject, key);

        return rawKey;
    }

    /**
     * Mock passkey registration; currently just delegates to {@link #loginPasskey}.
     */
    //@TODO
    public boolean registerPasskey() {
        //loginPasskey();

        return false;
    }

    /**
     * Signs the subject out and fires the {@code "authenticated"} change event.
     */
    public boolean logout() {
        boolean old = this.authenticated;
        this.authenticated = false;
        this.subject = null;
        this.subjectIdentifier = null;
        pcs.firePropertyChange("authenticated", old, false);

        return true;
    }

    public PrincipalIdentifier[] getAllPrincipalIDForLoggedInUser() {
        if (subjectIdentifier == null) return new PrincipalIdentifier[0];
        return domainSecurityManager.lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID());
    }

    public CredentialInfo[] getAllCredentialForLoggedInUser() {
        if (subject == null) return new CredentialInfo[0];
        return domainSecurityManager.lookupAllPrincipalCredentials(subject);
    }

    /**
     * Registers an additional identifier (email/username/handle) for the signed-in subject.
     * Rejects blank identifiers and any that already exist (for this or another subject),
     * since the backend does not enforce uniqueness.
     *
     * @param principalID the new identifier
     * @return {@code null} on success, otherwise the failure reason
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
     * Removes an identifier from the signed-in subject.
     *
     * @param principal the identifier to remove
     * @return {@code true} if removed
     */
    public String removeIdentifier(PrincipalIdentifier principal) {

        if (!((getAllPrincipalIDForLoggedInUser().length - 1) > 0)) return "Cannot remove the last identifier";
        if (principal == null) return "Identifier cannot be empty";

        if (!domainSecurityManager.deletePrincipalID(principal)) {
            return "Could not remove identifier";
        }

        if (principal.getPrincipalID().equals(subject)) {
            PrincipalIdentifier[] remaining = getAllPrincipalIDForLoggedInUser();
            if (remaining.length > 0) {
                subject = remaining[0].getPrincipalID();
            }
        }

        return null;
    }

    /**
     * Replaces the signed-in subject's password. Returns {@code null} on success, or a
     * human-readable reason on failure (wrong current password, or weak new password).
     *
     * @param current the current password (verified before any change)
     * @param next    the new password (validated against {@code FilterType.PASSWORD})
     * @return {@code null} on success, otherwise the failure reason
     */
    public String changePassword(char[] current, char[] next) {
        if (subject == null) return "Not signed in";

        // 1. verify the current password
        try {
            domainSecurityManager.login(subject, new String(current));
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
        CredentialInfo existing = domainSecurityManager.lookupCredential(subject, CredentialInfo.Type.PASSWORD);
        if (existing instanceof CIPassword existingPw) {
            existingPw.setAlgorithm(fresh.getAlgorithm());
            existingPw.setRounds(fresh.getRounds());
            existingPw.setSalt(fresh.getSalt());
            existingPw.setHash(fresh.getHash());
            domainSecurityManager.updateCredential(existingPw);
        } else {
            // No existing password credential (shouldn't happen for a normal account) — create one.
            domainSecurityManager.createCredential(subject, fresh);
        }
        return null;
    }

    public void saveProfile(Map<String, String> fields) {
        if (subjectIdentifier == null) return;
        NVGenericMap props = subjectIdentifier.getProperties();
        if (props == null) {
            props = new NVGenericMap();
            subjectIdentifier.setValue(PropertyDAO.Param.PROPERTIES, props);
        }
        NVGenericMap finalProps = props;
        fields.forEach((k, v) -> finalProps.build(k, v == null ? "" : v));
        domainSecurityManager.updateSubjectID(subjectIdentifier);
    }

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
     * Subscribes a listener to {@code "authenticated"} changes (login/logout).
     *
     * @param l the listener to notify
     */
    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }
}
