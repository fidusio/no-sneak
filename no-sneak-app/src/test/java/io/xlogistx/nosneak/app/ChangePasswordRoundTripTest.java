package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Reproduces the change-password round trip: after changing the password and a
 * logout/login cycle, the OLD password must stop working and the NEW one must work.
 *
 * <p>Failure is signalled by a thrown {@link SecurityException} (message = the reason);
 * success returns normally.</p>
 */
public class ChangePasswordRoundTripTest {

    private static final String OLD = "Password1!";
    private static final String NEW = "Password2@";

    private static Session freshSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword(OLD));
        return new Session(dsm);
    }

    @Test
    public void newPasswordWorksAfterChange() {
        Session s = freshSession();
        assertDoesNotThrow(() -> s.loginUsernamePassword("kailen", OLD.toCharArray()), "login with old password");

        assertDoesNotThrow(() -> s.changePassword(OLD.toCharArray(), NEW.toCharArray()), "changePassword should succeed");
        s.logout();

        assertDoesNotThrow(() -> s.loginUsernamePassword("kailen", NEW.toCharArray()), "NEW password must work after change");
    }

    @Test
    public void oldPasswordRejectedAfterChange() {
        Session s = freshSession();
        s.loginUsernamePassword("kailen", OLD.toCharArray());

        assertDoesNotThrow(() -> s.changePassword(OLD.toCharArray(), NEW.toCharArray()), "changePassword should succeed");
        s.logout();

        assertThrows(SecurityException.class,
                () -> s.loginUsernamePassword("kailen", OLD.toCharArray()),
                "OLD password must be rejected after change");
    }

    @Test
    public void wrongCurrentPasswordRejected() {
        Session s = freshSession();
        s.loginUsernamePassword("kailen", OLD.toCharArray());

        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.changePassword("NotMyPassword9!".toCharArray(), NEW.toCharArray()),
                "a wrong current password must be rejected");
        assertEquals("Current password is incorrect", ex.getMessage());

        // and the original password must still work
        s.logout();
        assertDoesNotThrow(() -> s.loginUsernamePassword("kailen", OLD.toCharArray()),
                "the password must be unchanged after a rejected change");
    }

    @Test
    public void weakNewPasswordRejected() {
        Session s = freshSession();
        s.loginUsernamePassword("kailen", OLD.toCharArray());

        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.changePassword(OLD.toCharArray(), "weak".toCharArray()),
                "a new password failing the policy must be rejected");
        assertEquals("New password does not meet requirements", ex.getMessage());
    }

    @Test
    public void notSignedInRejected() {
        Session s = freshSession();   // never logged in
        SecurityException ex = assertThrows(SecurityException.class,
                () -> s.changePassword(OLD.toCharArray(), NEW.toCharArray()));
        assertEquals("Not Logged in", ex.getMessage());
    }
}
