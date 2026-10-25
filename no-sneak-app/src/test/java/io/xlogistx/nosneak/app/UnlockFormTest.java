package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.UnlockPanel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The unlock screen's decisions without a display: when step 1 creates rather than opens, what
 * each step refuses to run with, and the password rules reported by the register path.
 */
public class UnlockFormTest {

    private static final char[] GOOD = "Password9!".toCharArray();

    @Test
    void createsOnlyWhenTheDirectoryHasNoVault(@TempDir Path dir) throws IOException {
        String location = dir.toString();
        assertTrue(UnlockPanel.Form.creates(location), "an empty directory is a first run");
        assertEquals(UnlockPanel.Form.CREATE_HINT, UnlockPanel.Form.storeHint(location));

        Files.createFile(dir.resolve(NoSneakStore.VAULT_NAME));
        assertFalse(UnlockPanel.Form.creates(location), "a vault means open");
        assertEquals(UnlockPanel.Form.OPEN_HINT, UnlockPanel.Form.storeHint(location));

        assertFalse(UnlockPanel.Form.creates(null), "no location decides nothing");
        assertFalse(UnlockPanel.Form.creates("  "));
        assertNull(UnlockPanel.Form.storeHint(null));
        assertNull(UnlockPanel.Form.storeHint(""));
    }

    @Test
    void storeStepRequiresLocationVaultPasswordAndOnFirstRunTheOperator() {
        assertEquals("Please choose a location.", UnlockPanel.Form.validateStore(null, GOOD, false, null, null, null));
        assertEquals("The vault password is required.", UnlockPanel.Form.validateStore("D:/x", new char[0], false, null, null, null));
        assertNull(UnlockPanel.Form.validateStore("D:/x", GOOD, false, null, null, null), "opening needs nothing else");

        assertEquals("The operator's username and password are required to create the store.",
                UnlockPanel.Form.validateStore("D:/x", GOOD, true, "", GOOD, GOOD));
        assertEquals("The operator's username and password are required to create the store.",
                UnlockPanel.Form.validateStore("D:/x", GOOD, true, "operator", new char[0], new char[0]));
        assertEquals("The operator passwords do not match.",
                UnlockPanel.Form.validateStore("D:/x", GOOD, true, "operator", GOOD, "Password8@".toCharArray()));
        String weak = UnlockPanel.Form.validateStore("D:/x", GOOD, true, "operator", "short".toCharArray(), "short".toCharArray());
        assertNotNull(weak, "the operator password is checked against the rules before the store is created");
        assertTrue(weak.startsWith("Operator password: "), weak);
        assertNull(UnlockPanel.Form.validateStore("D:/x", GOOD, true, "operator", GOOD, GOOD.clone()));
    }

    @Test
    void signInNeedsBothFields() {
        assertEquals("Username and password are required.", UnlockPanel.Form.validateSignIn("", GOOD));
        assertEquals("Username and password are required.", UnlockPanel.Form.validateSignIn("alice", new char[0]));
        assertEquals("Username and password are required.", UnlockPanel.Form.validateSignIn("alice", null));
        assertNull(UnlockPanel.Form.validateSignIn("alice", GOOD));
    }

    @Test
    void registerChecksBlankMismatchThenRules() {
        assertEquals("A username is required.", UnlockPanel.Form.validateRegister(" ", GOOD, GOOD));
        assertEquals("A password is required.", UnlockPanel.Form.validateRegister("alice", new char[0], new char[0]));
        assertEquals("Passwords do not match.", UnlockPanel.Form.validateRegister("alice", GOOD, "Password8@".toCharArray()));
        assertNotNull(UnlockPanel.Form.validateRegister("alice", "short".toCharArray(), "short".toCharArray()),
                "a matching but weak password is refused with the rule's reason");
        assertNull(UnlockPanel.Form.validateRegister("alice", GOOD, GOOD.clone()));
    }

    @Test
    void passwordRuleFailureIsNullForAnAcceptedPassword() {
        assertNull(UnlockPanel.Form.passwordRuleFailure(GOOD));
        String reason = UnlockPanel.Form.passwordRuleFailure("abc".toCharArray());
        assertNotNull(reason);
        assertFalse(reason.isBlank());
    }
}
