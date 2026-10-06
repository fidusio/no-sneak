package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.security.CredentialInfo;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the API-key flow as it is since 2026-10-05: {@link Session#generateAPIKey()} produces a
 * fresh {@link SubjectAPIKey} (its {@code getAPIKey()} is the raw secret), {@link Session#storeAPIKey}
 * stores it (with a label and description) as the subject's credential — <b>never a login</b>:
 * the Shiro manager refuses {@code loginApiKey} and the session has no API-key login any more.
 * Also covers the label/description round-trip, editing the metadata via
 * {@link Session#changeAPIDetails}, the vendor domain/app of an external key (metadata on the
 * property bag, not the key's app-model scope), and the creation/validation failure paths.
 *
 * <p>Failure is signalled by a thrown {@link AccessSecurityException} (business-rule guards and
 * AppID-filter rejections alike); success returns normally.</p>
 */
public class APIKeyRoundTripTest {

    private static Session mockSession() {
        ShiroDSDomainSecurityManager dsm =
                TestSecurity.newManager();
        dsm.createSubjectID("kailen01", HashUtil.toBCryptPassword("Password1!"));
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
    public void createdKeyIsACredentialNotALogin() {
        Session s = mockSession();
        assertDoesNotThrow(() -> s.loginUsernamePassword("kailen01", "Password1!".toCharArray()), "password login");

        String apiKey = s.generateAPIKey().getAPIKey();
        assertNotNull(apiKey, "generateAPIKey returned null");
        assertDoesNotThrow(() -> s.storeAPIKey("prod-key", "for production", null, null, apiKey, null, null, null, null, false),
                "storeAPIKey should succeed");

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertEquals(Session.NO_SNEAK_DOMAIN_ID, stored.getAppID().getDomainID(), "a key no-sneak issues is scoped to its app");
        assertEquals(Session.NO_SNEAK_APP_ID, stored.getAppID().getAppID());

        s.logout();
        assertFalse(s.isAuthenticated());
        assertTrue(s.getAllCredentialForLoggedInUser().isEmpty(), "signed out, no credential is readable");

        // an API key is the subject's credential for a third-party API, never a login (user rule 2026-10-03)
        assertThrows(AccessSecurityException.class, () -> s.getDomainSecurityManager().loginApiKey(apiKey),
                "the manager refuses an API key as a login credential");
        assertFalse(s.isAuthenticated());

        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertEquals(apiKey, firstApiKey(s).getAPIKey(), "the owner reads the secret back in clear");
    }

    @Test
    public void labelRoundTripsIntoCredentialList() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("prod-key", "for production", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored, "the API key should appear in the credential list");
        assertEquals("prod-key", stored.getName(), "the label must round-trip as the credential name");
        assertEquals("for production", stored.getDescription(), "the description must round-trip");
    }

    @Test
    public void assistantEnabledFlagRoundTrips() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("ai-key", "desc", null, null, s.generateAPIKey().getAPIKey(), "openai", null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertFalse(s.isAssistantEnabled(stored), "keys start disabled for the assistant");

        assertDoesNotThrow(() -> s.setAssistantEnabled(stored, true), "enabling should succeed");
        assertTrue(s.isAssistantEnabled(firstApiKey(s)), "enabled flag must round-trip");

        assertDoesNotThrow(() -> s.setAssistantEnabled(firstApiKey(s), false), "disabling should succeed");
        assertFalse(s.isAssistantEnabled(firstApiKey(s)), "disabled flag must round-trip");
    }

    @Test
    public void setAssistantEnabledRejectedWhenSignedOut() {
        Session s = mockSession();
        AccessSecurityException ex = assertThrows(AccessSecurityException.class,
                () -> s.setAssistantEnabled(new SubjectAPIKey(), true));
        assertEquals("Not signed in", ex.getMessage());
    }

    @Test
    public void changeApiDetailsUpdatesLabelAndDescription() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
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
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
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
    public void changeApiDetailsUpdatesVendorOfExternalKey() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("label", "desc", null, null, "sk-vendor", null, null, null, null, true));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertNull(s.vendorDomainOf(stored), "no vendor recorded yet");

        assertDoesNotThrow(() -> s.changeAPIDetails(stored, "label", "desc", "example.com", "myapp123", null, null, null, null),
                "changeAPIDetails should persist the vendor domain/app");

        SubjectAPIKey reloaded = firstApiKey(s);
        assertEquals("example.com", s.vendorDomainOf(reloaded), "vendor domain should be stored after edit");
        assertEquals("myapp123", s.vendorAppOf(reloaded), "vendor app should be stored after edit");
        assertNull(reloaded.getAppID(), "a vendor's app is never the key's app-model scope");
    }

    @Test
    public void changeApiDetailsKeepsScopeOfInternalKey() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("label", "desc", null, null, s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertDoesNotThrow(() -> s.changeAPIDetails(stored, "label", "desc", "example.com", "myapp123", null, null, null, null));

        SubjectAPIKey reloaded = firstApiKey(s);
        assertEquals(Session.NO_SNEAK_APP_ID, reloaded.getAppID().getAppID(), "the no-sneak scope is not editable");
        assertNull(s.vendorDomainOf(reloaded), "an internal key has no vendor");
    }

    @Test
    public void changeApiDetailsRejectedWhenSignedOut() {
        Session s = mockSession();
        AccessSecurityException ex = assertThrows(AccessSecurityException.class,
                () -> s.changeAPIDetails(new SubjectAPIKey(), "label", "desc", null, null, null, null, null, null),
                "editing metadata must be refused when no subject is signed in");
        assertEquals("Not Logged in", ex.getMessage());
    }

    @Test
    public void revokeRemovesKey() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        String secret = s.generateAPIKey().getAPIKey();
        assertDoesNotThrow(() -> s.storeAPIKey("doomed", "desc", null, null, secret, null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        assertDoesNotThrow(() -> s.deleteAPIKey(stored), "revoke should succeed");
        assertNull(firstApiKey(s), "the revoked key must be gone from the credential list");
        assertTrue(s.getAllCredentialForUserByType(CredentialInfo.Type.API_KEY).isEmpty());
    }

    @Test
    public void revokeRejectsBadInput() {
        Session s = mockSession();
        assertEquals("Not signed in",
                assertThrows(AccessSecurityException.class, () -> s.deleteAPIKey(new SubjectAPIKey())).getMessage(),
                "refused when signed out");

        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertEquals("Empty Key",
                assertThrows(AccessSecurityException.class, () -> s.deleteAPIKey(null)).getMessage(),
                "refused with a null key");
    }

    @Test
    public void rotateIssuesAFreshSecret() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        String oldSecret = s.generateAPIKey().getAPIKey();
        assertDoesNotThrow(() -> s.storeAPIKey("rotate-me", "desc", null, null, oldSecret, null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);

        assertDoesNotThrow(() -> s.rotateAPIKey(stored), "rotate should succeed");
        String newSecret = stored.getAPIKey();   // rotate mutates the key in place
        assertNotNull(newSecret, "the rotated key should hold a fresh secret");
        assertNotEquals(oldSecret, newSecret, "rotate must issue a different secret");
        assertEquals(newSecret, firstApiKey(s).getAPIKey(), "the fresh secret is what the store holds");
    }

    @Test
    public void rotateRejectsBadInput() {
        Session s = mockSession();
        assertEquals("Not signed in",
                assertThrows(AccessSecurityException.class, () -> s.rotateAPIKey(new SubjectAPIKey())).getMessage(),
                "refused when signed out");

        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertEquals("Empty Key",
                assertThrows(AccessSecurityException.class, () -> s.rotateAPIKey(null)).getMessage(),
                "refused with a null key");
    }

    @Test
    public void createApiKeyRejectsBadInput() {
        Session s = mockSession();

        // Not signed in: both generate and create are refused.
        assertEquals("Not signed in",
                assertThrows(AccessSecurityException.class, s::generateAPIKey).getMessage(),
                "generateAPIKey is refused when signed out");
        assertEquals("Not signed in",
                assertThrows(AccessSecurityException.class,
                        () -> s.storeAPIKey("label", "desc", null, null, "anything", null, null, null, null, false)).getMessage());

        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertEquals("Key cannot be empty",
                assertThrows(AccessSecurityException.class,
                        () -> s.storeAPIKey("label", "desc", null, null, "   ", null, null, null, null, false)).getMessage());
        // NOTE: the "Invalid API key format" branch is not asserted here — SharedBase64.decode
        // is lenient and does not throw on arbitrary junk, so a malformed key is currently
        // accepted. See the review note.
    }

    @Test
    public void createStoresVendorDomainAndAppWhenBothProvided() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("labelled", "desc", "example.com", "myapp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "create with a valid domain + app id should succeed");

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertEquals("example.com", s.vendorDomainOf(stored), "the vendor domain must round-trip");
        assertEquals("myapp123", s.vendorAppOf(stored), "the vendor app id must round-trip");
        assertNull(stored.getAppID(), "a vendor's app is metadata, never the key's app-model scope");
    }

    @Test
    public void createNormalizesVendorDomainAndAppCase() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        // The domain and app-id filters lower-case their input, so mixed-case entry is normalized.
        assertDoesNotThrow(() -> s.storeAPIKey("labelled", "desc", "Example.COM", "MyApp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertEquals("example.com", s.vendorDomainOf(stored), "domain should be lower-cased");
        assertEquals("myapp123", s.vendorAppOf(stored), "app id should be lower-cased");
    }

    @Test
    public void createSkipsVendorWhenOnlyOnePartProvided() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());

        // Only a domain (no app id): the vendor block requires both, so it is skipped and the
        // key is still created without a vendor.
        assertDoesNotThrow(() -> s.storeAPIKey("dom-only", "desc", "example.com", "  ", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "a domain with a blank app id should still create the key");
        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored, "the key must be created even though the vendor was skipped");
        assertNull(s.vendorDomainOf(stored));
        assertTrue(s.isExternalKey(stored),
                "an external key without a domain/app-id pair must still be marked external — "
                        + "otherwise rotate could overwrite a real vendor secret");
    }

    @Test
    public void createRejectsInvalidDomain() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        // "not a domain" fails FilterType.DOMAIN, which throws rather than returning a reason.
        assertThrows(AccessSecurityException.class,
                () -> s.storeAPIKey("bad-domain", "desc", "not a domain", "myapp123", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "an invalid domain must be rejected");
    }

    @Test
    public void createRejectsNonAlphanumericAppID() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        // AppIDNameFilter only accepts letters and digits, so "my-app" (a dash) is rejected.
        assertThrows(AccessSecurityException.class,
                () -> s.storeAPIKey("bad-app", "desc", "example.com", "my-app", s.generateAPIKey().getAPIKey(), null, null, null, null, true),
                "a non-alphanumeric app id must be rejected");
    }

    @Test
    public void externalKeyStoresMetadataAndMarksExternal() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("ext", "desc", "example.com", "myapp123",
                s.generateAPIKey().getAPIKey(), "anthropic", "https://api.anthropic.com", "Bearer", "x-api-key", true));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertTrue(s.isExternalKey(stored), "an external key must be marked external");
        assertEquals("example.com", s.vendorDomainOf(stored));
        assertEquals("myapp123", s.vendorAppOf(stored));
        assertEquals("anthropic", s.providerOf(stored), "provider must round-trip");
        assertEquals("https://api.anthropic.com", s.baseUrlOf(stored), "base URL must round-trip");
        assertEquals("Bearer", s.authTypeOf(stored), "auth scheme must round-trip");
        assertEquals("x-api-key", s.headerNameOf(stored), "header name must round-trip");
    }

    @Test
    public void internalKeyIsNotMarkedExternal() {
        Session s = mockSession();
        s.loginUsernamePassword("kailen01", "Password1!".toCharArray());
        assertDoesNotThrow(() -> s.storeAPIKey("local", "desc", null, null,
                s.generateAPIKey().getAPIKey(), null, null, null, null, false));

        SubjectAPIKey stored = firstApiKey(s);
        assertNotNull(stored);
        assertFalse(s.isExternalKey(stored), "a locally generated key must not be external");
    }
}
