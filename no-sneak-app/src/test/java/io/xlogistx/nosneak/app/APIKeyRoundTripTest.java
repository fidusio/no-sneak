package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the split API-key flow: {@link Session#generateAPIKey()} produces a fresh
 * {@link SubjectAPIKey} (its {@code getAPIKey()} is the raw secret),
 *  stores it (with a label and
 * description), and {@link Session#loginAPIKey(char[])} logs in with it.
 * Also covers the label/description round-trip, editing the metadata via
 * {@link Session#changeAPIDetails}, and the creation/validation failure paths.
 *
 * <p>Failure is signalled by a thrown {@link SecurityException} (business-rule guards and
 * AppID-filter rejections alike); success returns normally.</p>
 */
public class APIKeyRoundTripTest {

    private static Session mockSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class)
                        .addCredentialType(SubjectAPIKey.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        return new Session(dsm);
    }

    /** Returns the first stored API-key credential for the signed-in user, or {@code null}. */
    private static SubjectAPIKey firstApiKey(Session s) {
        for (CredentialInfo ci : s.getAllCredentialForLoggedInUser()) {
            if (ci.getCredentialType() == CredentialInfo.Type.API_KEY) return (SubjectAPIKey) ci;
        }
        return null;
    }

    @Test
    public void createThenLoginWithApiKey() {
        Session s = mockSession();
        assertDoesNotThrow(() -> s.loginUsernamePassword("kailen", "Password1!".toCharArray()), "password login");

        String apiKey = s.generateAPIKey().getAPIKey();
        assertNotNull(apiKey, "generateAPIKey returned null");
        assertDoesNotThrow(() -> s.storeAPIKey("prod-key", "for production", null, null, apiKey, null, null, null, null, false),
                "storeAPIKey should succeed");

        s.logout();
        assertFalse(s.isAuthenticated());

        assertDoesNotThrow(() -> s.loginAPIKey(apiKey.toCharArray()), "API-key login should succeed");
        assertTrue(s.isAuthenticated(), "session should be authenticated after API-key login");
        assertEquals("kailen", s.getPrincipalID(), "API-key login should resolve the owning principal");
    }

    @Test
    public void labelRoundTripsIntoCredentialList() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("prod-key", "for production", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored, "the API key should appear in the credential list");
        assertEquals("prod-key", stored.getName(), "the label must round-trip as the credential name");
        assertEquals("for production", stored.getDescription(), "the description must round-trip");
    }

    @Test
    public void changeApiDetailsUpdatesLabelAndDescription() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("old-label", "old desc", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored, "the API key should exist before editing");

        assertDoesNotThrow(() -> s.changeAPIDetails(stored, "new-label", "new desc", null, null, null, null, null, null), "changeAPIDetails should succeed");

        // Re-read from the store to confirm the edit persisted, not just mutated in memory.
        SubjectAPIKey reloaded = firstApiKey(s);
        assertNotNull(reloaded);
        assertEquals("new-label", reloaded.getName(), "label should be updated");
        assertEquals("new desc", reloaded.getDescription(), "description should be updated");
    }

    @Test
    public void changeApiDetailsCanClearMetadata() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("label", "desc", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        // Unlike storeAPIKey (which skips blank label/description), the edit path sets
        // whatever it's handed — so passing blanks clears the fields.
        assertDoesNotThrow(() -> s.changeAPIDetails(stored, "", "", null, null, null, null, null, null), "clearing metadata should succeed");

        SubjectAPIKey reloaded = firstApiKey(s);
        assertNotNull(reloaded);
        assertTrue(reloaded.getName() == null || reloaded.getName().isBlank(),
                "blank label should clear the name");
        assertTrue(reloaded.getDescription() == null || reloaded.getDescription().isBlank(),
                "blank description should clear the description");
    }

    @Test
    public void changeApiDetailsUpdatesAppID() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("label", "desc", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        assertDoesNotThrow(() -> s.changeAPIDetails(stored, "label", "desc", "example.com", "myapp123", null, null, null, null),
                "changeAPIDetails should persist the app id");

        SubjectAPIKey reloaded = firstApiKey(s);
        assertNotNull(reloaded.getAppID(), "app id should be stored after edit");
        assertEquals("example.com", reloaded.getAppID().getDomainID());
        assertEquals("myapp123", reloaded.getAppID().getAppID());
    }

    @Test
    public void changeApiDetailsRejectedWhenSignedOut() {
        Session s = mockSession();
        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.changeAPIDetails(new SubjectAPIKey(), "label", "desc", null, null, null, null, null, null),
                "editing metadata must be refused when no subject is signed in");
        assertEquals("Not Logged in", ex.getMessage());
    }

    @Test
    public void revokeRemovesKeyAndBlocksLogin() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        String secret = s.generateAPIKey().getAPIKey();
        assertDoesNotThrow(() -> s.storeAPIKey("doomed", "desc", null, null, secret, null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        assertDoesNotThrow(() -> s.deleteAPIKey(stored), "revoke should succeed");
        assertNull(firstApiKey(s), "the revoked key must be gone from the credential list");

        s.logout();
        assertThrows(SecurityException.class, () -> s.loginAPIKey(secret.toCharArray()), "a revoked key must not log in");
        assertFalse(s.isAuthenticated());
    }

    @Test
    public void revokeRejectsBadInput() {
        Session s = mockSession();
        assertEquals("Not signed in",
                assertThrows(SecurityException.class, () -> s.deleteAPIKey(new SubjectAPIKey())).getMessage(),
                "refused when signed out");

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertEquals("Empty Key",
                assertThrows(SecurityException.class, () -> s.deleteAPIKey(null)).getMessage(),
                "refused with a null key");
    }

    @Test
    public void rotateInvalidatesOldKeyAndNewOneWorks() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        String oldSecret = s.generateAPIKey().getAPIKey();
        assertDoesNotThrow(() -> s.storeAPIKey("rotate-me", "desc", null, null, oldSecret, null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        assertDoesNotThrow(() -> s.rotateAPIKey(stored), "rotate should succeed");
        String newSecret = stored.getAPIKey();   // rotate mutates the key in place
        assertNotNull(newSecret, "the rotated key should hold a fresh secret");
        assertNotEquals(oldSecret, newSecret, "rotate must issue a different secret");

        s.logout();
        assertThrows(SecurityException.class, () -> s.loginAPIKey(oldSecret.toCharArray()),
                "the old secret must stop working after rotate");
        assertFalse(s.isAuthenticated());

        assertDoesNotThrow(() -> s.loginAPIKey(newSecret.toCharArray()), "the new secret must work after rotate");
        assertEquals("kailen", s.getPrincipalID(), "rotated-key login should resolve the owning principal");
    }

    @Test
    public void rotateRejectsBadInput() {
        Session s = mockSession();
        assertEquals("Not signed in",
                assertThrows(SecurityException.class, () -> s.rotateAPIKey(new SubjectAPIKey())).getMessage(),
                "refused when signed out");

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertEquals("Empty Key",
                assertThrows(SecurityException.class, () -> s.rotateAPIKey(null)).getMessage(),
                "refused with a null key");
    }

    @Test
    public void createApiKeyRejectsBadInput() {
        Session s = mockSession();

        // Not signed in: both generate and create are refused.
        assertEquals("Not signed in",
                assertThrows(SecurityException.class, s::generateAPIKey).getMessage(),
                "generateAPIKey is refused when signed out");
        assertEquals("Not signed in",
                assertThrows(SecurityException.class,
                        () -> s.storeAPIKey("label", "desc", null, null, "anything", null, null, null, null, false)).getMessage());

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertEquals("Key cannot be empty",
                assertThrows(SecurityException.class,
                        () -> s.storeAPIKey("label", "desc", null, null, "   ", null, null, null, null, false)).getMessage());
        // NOTE: the "Invalid API key format" branch is not asserted here — SharedBase64.decode
        // is lenient and does not throw on arbitrary junk, so a malformed key is currently
        // accepted (it just never matches at login). See the review note.
    }

    @Test
    public void loginApiKeyRejectsUnknownKey() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        s.storeAPIKey("real", "desc", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false);
        String phantom = s.generateAPIKey().getAPIKey();   // validly formatted, but never stored
        s.logout();

        assertThrows(SecurityException.class, () -> s.loginAPIKey(phantom.toCharArray()),
                "a key that was never stored must not log in");
        assertFalse(s.isAuthenticated());
    }

    @Test
    public void createStoresDomainAndAppIDWhenBothProvided() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("labelled", "desc", "example.com", "myapp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "create with a valid domain + app id should succeed");

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertNotNull(stored.getAppID(), "an app id should be stored when both parts are provided");
        assertEquals("example.com", stored.getAppID().getDomainID(), "the domain must round-trip");
        assertEquals("myapp123", stored.getAppID().getAppID(), "the app id must round-trip");
    }

    @Test
    public void createNormalizesDomainAndAppIDCase() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        // The domain and app-id filters lower-case their input, so mixed-case entry is normalized.
        assertDoesNotThrow(() -> s.storeAPIKey("labelled", "desc", "Example.COM", "MyApp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertEquals("example.com", stored.getAppID().getDomainID(), "domain should be lower-cased");
        assertEquals("myapp123", stored.getAppID().getAppID(), "app id should be lower-cased");
    }

    @Test
    public void createSkipsAppIDWhenOnlyOnePartProvided() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        // Only a domain (no app id): the app-id block requires both, so it is skipped and the
        // key is still created without an app-id association.
        assertDoesNotThrow(() -> s.storeAPIKey("dom-only", "desc", "example.com", "  ", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "a domain with a blank app id should still create the key");
        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored, "the key must be created even though the app id was skipped");
    }

    @Test
    public void createRejectsInvalidDomain() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        // "not a domain" fails FilterType.DOMAIN, which throws rather than returning a reason.
        assertThrows(SecurityException.class,
                () -> s.storeAPIKey("bad-domain", "desc", "not a domain", "myapp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "an invalid domain must be rejected");
    }

    @Test
    public void createRejectsNonAlphanumericAppID() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        // AppIDNameFilter only accepts letters and digits, so "my-app" (a dash) is rejected.
        assertThrows(SecurityException.class,
                () -> s.storeAPIKey("bad-app", "desc", "example.com", "my-app", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "a non-alphanumeric app id must be rejected");
    }

    @Test
    public void externalKeyStoresMetadataAndMarksExternal() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("ext", "desc", "example.com", "myapp123",
                s.generateAPIKey().getAPIKey(), "anthropic", "https://api.anthropic.com", "Bearer", "x-api-key", true));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertTrue(s.isExternalKey(stored), "an external key must be marked external");
        assertEquals("anthropic", s.providerOf(stored), "provider must round-trip");
        assertEquals("https://api.anthropic.com", s.baseUrlOf(stored), "base URL must round-trip");
        assertEquals("Bearer", s.authTypeOf(stored), "auth scheme must round-trip");
        assertEquals("x-api-key", s.headerNameOf(stored), "header name must round-trip");
    }

    @Test
    public void internalKeyIsNotMarkedExternal() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("local", "desc", null, null,
                s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertFalse(s.isExternalKey(stored), "a locally generated key must not be external");
    }
}
