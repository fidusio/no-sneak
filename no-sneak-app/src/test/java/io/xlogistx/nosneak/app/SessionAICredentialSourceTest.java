package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.assistant.SessionAICredentialSource;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.data.ReferenceIDDAO;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the assistant-facing credential source, in particular the Providers-page add-key
 * path ({@link SessionAICredentialSource#addAPIKey}): the key materializes as an ordinary
 * NoSneak credential (the assistant stores nothing), is marked <em>external</em> even with no
 * domain/app-id scope (so rotate can never overwrite the vendor secret), carries the AI
 * metadata on its property bag, and comes back already assistant-enabled.
 */
public class SessionAICredentialSourceTest {

    private static Session loggedInSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class)
                        .addCredentialType(SubjectAPIKey.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        return s;
    }

    @Test
    public void addAPIKeyCreatesEnabledExternalCredential() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);

        APIKey<String> key = source.addAPIKey("claude prod", "assistant key",
                "anthropic", "https://api.anthropic.com", "Bearer", "x-api-key", "sk-test-123");

        assertNotNull(key);
        assertEquals("claude prod", key.getName());
        assertEquals("sk-test-123", key.getAPIKey(), "the raw secret is stored as presented");

        assertEquals(1, source.APIKeys().size(), "the key lands in the one credential store");
        assertEquals(1, source.enabledAPIKeys().size(), "a key added here is enabled immediately");

        assertTrue(s.isExternalKey(key), "a vendor key must read external even with no app-id scope");
        assertEquals("anthropic", s.providerOf(key));
        assertEquals("https://api.anthropic.com", s.baseUrlOf(key));
        assertEquals("Bearer", s.authTypeOf(key));
        assertEquals("x-api-key", s.headerNameOf(key));
    }

    @Test
    public void addedKeyCanLogIn() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);
        source.addAPIKey("k", "", "openai", "", "", "", "sk-login-me");
        s.logout();

        assertDoesNotThrow(() -> s.loginAPIKey("sk-login-me".toCharArray()),
                "a key added from the assistant is a full credential — API-key login included");
    }

    @Test
    public void blankSecretRejected() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);

        SecurityException ex = assertThrows(SecurityException.class,
                () -> source.addAPIKey("label", "", "openai", "", "", "", "   "));
        assertEquals("Key cannot be empty", ex.getMessage());
        assertTrue(source.APIKeys().isEmpty(), "nothing may be stored on a rejected add");
    }

    @Test
    public void signedOutRejected() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);
        s.logout();

        assertThrows(SecurityException.class,
                () -> source.addAPIKey("label", "", "openai", "", "", "", "sk-x"));
    }

    /**
     * A provider config stores the credential's GUID, so the key handed back by {@code addAPIKey}
     * must already carry one — a null there would save a provider that can never resolve its key.
     */
    @Test
    public void addedKeyIsResolvableByGuid() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);
        APIKey<String> key = source.addAPIKey("k", "", "openai", "", "", "", "sk-guid");

        assertInstanceOf(ReferenceIDDAO.class, key);
        String guid = ((ReferenceIDDAO) key).getGUID();
        assertNotNull(guid, "the created key must come back carrying its GUID");
        assertFalse(guid.isEmpty());

        APIKey<String> found = source.getKey(guid);
        assertNotNull(found, "a provider config must be able to resolve its key by GUID");
        assertEquals("sk-guid", found.getAPIKey());
    }

    @Test
    public void getKeyMissesReturnNull() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);
        source.addAPIKey("k", "", "openai", "", "", "", "sk-x");

        assertNull(source.getKey("no-such-guid"), "a deleted credential must resolve to null");
        assertNull(source.getKey(null));
        assertNull(source.getKey("  "));
    }

    @Test
    public void setEnabledTogglesMembership() {
        Session s = loggedInSession();
        SessionAICredentialSource source = new SessionAICredentialSource(s);
        APIKey<String> key = source.addAPIKey("k", "", "openai", "", "", "", "sk-toggle");

        source.setEnabled(key, false);
        assertTrue(source.enabledAPIKeys().isEmpty(), "disable must drop it from the enabled set");
        assertEquals(1, source.APIKeys().size(), "disable must not delete the credential");

        source.setEnabled(key, true);
        assertEquals(1, source.enabledAPIKeys().size());
    }
}
