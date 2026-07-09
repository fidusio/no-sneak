package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.PrincipalIdentifier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers {@link Session#addIdentifier(String)} / {@link Session#removeIdentifier} — the
 * add rules (blank/duplicate), the "can't remove the last one" guard, and the repoint of
 * the active subject when you remove the identifier you logged in as.
 *
 * <p>Failure is signalled by a thrown {@link SecurityException} (message = the reason);
 * success returns normally.</p>
 */
public class IdentifierRoundTripTest {

    private static Session loggedInSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        return s;
    }

    private static PrincipalIdentifier find(Session s, String id) {
        for (PrincipalIdentifier p : s.getAllPrincipalIDForLoggedInUser()) {
            if (p.getPrincipalID().equals(id)) return p;
        }
        return null;
    }

    @Test
    public void addSecondIdentifierThenListed() {
        Session s = loggedInSession();
        assertDoesNotThrow(() -> s.addIdentifier("kailen@example.com"), "adding a fresh identifier should succeed");

        assertEquals(2, s.getAllPrincipalIDForLoggedInUser().length);
        assertNotNull(find(s, "kailen"));
        assertNotNull(find(s, "kailen@example.com"));
    }

    @Test
    public void addRejectsBlankAndDuplicate() {
        Session s = loggedInSession();
        assertEquals("Identifier cannot be empty",
                assertThrows(SecurityException.class, () -> s.addIdentifier("   ")).getMessage());
        assertEquals("That identifier is already in use",
                assertThrows(SecurityException.class, () -> s.addIdentifier("kailen")).getMessage());
        assertEquals(1, s.getAllPrincipalIDForLoggedInUser().length, "no identifier should have been added");
    }

    @Test
    public void cannotRemoveLastIdentifier() {
        Session s = loggedInSession();
        PrincipalIdentifier only = find(s, "kailen");
        assertEquals("Cannot remove the last identifier",
                assertThrows(SecurityException.class, () -> s.removeIdentifier(only)).getMessage());
        assertEquals(1, s.getAllPrincipalIDForLoggedInUser().length);
    }

    @Test
    public void removeNullIdentifierRejected() {
        Session s = loggedInSession();
        s.addIdentifier("kailen@example.com");   // 2 identifiers, so the "last one" guard passes

        assertEquals("Identifier cannot be empty",
                assertThrows(SecurityException.class, () -> s.removeIdentifier(null)).getMessage());
        assertEquals(2, s.getAllPrincipalIDForLoggedInUser().length, "nothing should have been removed");
    }

    @Test
    public void removingNonActiveIdentifierKeepsSubject() {
        Session s = loggedInSession();
        s.addIdentifier("alt@example.com");

        // remove the identifier we did NOT authenticate with; the active subject must be untouched
        PrincipalIdentifier alt = find(s, "alt@example.com");
        assertDoesNotThrow(() -> s.removeIdentifier(alt));
        assertEquals("kailen", s.getPrincipalID(),
                "removing a non-active identifier must not repoint the subject");
        assertEquals(1, s.getAllPrincipalIDForLoggedInUser().length);
    }

    @Test
    public void removingLoginIdentifierRepointsSubject() {
        Session s = loggedInSession();
        s.addIdentifier("kailen@example.com");

        // remove the identifier we authenticated with; subject should repoint to the survivor
        PrincipalIdentifier active = find(s, "kailen");
        assertDoesNotThrow(() -> s.removeIdentifier(active));
        assertEquals("kailen@example.com", s.getPrincipalID(),
                "removing the active identifier must repoint the subject to a survivor");

        // credential lookups (keyed off the subject) must keep working after the repoint
        assertEquals(1, s.getAllCredentialForLoggedInUser().length,
                "the password credential should still be reachable via the new subject");
    }
}
