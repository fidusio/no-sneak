package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers {@link Session#registerUsernamePassword(String, char[])}: the password-policy
 * gate, the duplicate-username gate, and the success path (the new subject can then log
 * in). Note that register does NOT auto-login — it only creates the subject.
 *
 * <p>Failure is signalled by a thrown {@link SecurityException} (message = the reason);
 * success returns normally.</p>
 */
public class RegisterRoundTripTest {

    /** Store already seeded with an existing "kailen" so duplicates can be exercised. */
    private static Session sessionWithExistingUser() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        return new Session(dsm);
    }

    @Test
    public void registerThenLoginSucceeds() {
        Session s = sessionWithExistingUser();

        assertDoesNotThrow(() -> s.registerUsernamePassword("bob", "Password9!".toCharArray()),
                "registering a fresh username with a valid password should succeed");
        assertFalse(s.isAuthenticated(), "register must not auto-login the new subject");

        assertDoesNotThrow(() -> s.loginUsernamePassword("bob", "Password9!".toCharArray()),
                "the freshly registered user must be able to log in");
        assertEquals("bob", s.getPrincipalID());
    }

    @Test
    public void weakPasswordRejectedAndUserNotCreated() {
        Session s = sessionWithExistingUser();

        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.registerUsernamePassword("bob", "weak".toCharArray()),
                "a password failing the policy must be rejected");
        assertTrue(ex.getMessage().startsWith("Your password must meet"), "should return the policy message");

        assertThrows(SecurityException.class,
                () -> s.loginUsernamePassword("bob", "weak".toCharArray()),
                "a rejected registration must not have created the subject");
    }

    @Test
    public void duplicateUsernameRejected() {
        Session s = sessionWithExistingUser();
        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.registerUsernamePassword("kailen", "Password9!".toCharArray()),
                "registering an existing username must be refused");
        assertEquals("That username is already taken", ex.getMessage());
    }
}
