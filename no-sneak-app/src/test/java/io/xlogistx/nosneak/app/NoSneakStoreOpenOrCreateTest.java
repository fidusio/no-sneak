package io.xlogistx.nosneak.app;

import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link NoSneakStore#openOrCreate}, the one call the unlock screen makes: an empty directory
 * with first-run answers is created, a directory with a vault is opened whatever answers come
 * with it, and an empty directory without answers is refused with a reason. Runs on a real
 * encrypted H2 file under {@code target/} for the same reason {@link DataStoreSetupFlowTest} does.
 */
public class NoSneakStoreOpenOrCreateTest {

    private static final String OPERATOR = "operator.local";
    private static final char[] OPERATOR_PWD = "Operat0r-pass!".toCharArray();

    private static File freshDirectory() {
        File ret = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(ret.mkdirs() || ret.isDirectory(), "cannot create " + ret);
        return ret;
    }

    @Test
    public void createsThenOpensAndNeverRecreates() throws Exception {
        File dir = freshDirectory();
        char[] vaultPassword = "V4ult-pass!".toCharArray();

        // no vault, no answers: refused, nothing written
        IOException refused = assertThrows(IOException.class,
                () -> NoSneakStore.openOrCreate(dir.getPath(), vaultPassword.clone(), null));
        assertTrue(refused.getMessage().contains("no vault"), refused.getMessage());
        assertFalse(NoSneakStore.vaultExists(dir.getPath()));

        // no vault, answers: created
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.clone(), "", null, null);
        ShiroDSDomainSecurityManager created = NoSneakStore.openOrCreate(dir.getPath(), vaultPassword.clone(), firstRun);
        try {
            assertTrue(NoSneakStore.vaultExists(dir.getPath()));
            assertEquals(OPERATOR, created.getSuperAdminPrincipalID());
        } finally {
            created.getDataStore().close();
        }

        // vault present: opened, with or without answers, and the operator is unchanged
        ShiroDSDomainSecurityManager opened = NoSneakStore.openOrCreate(dir.getPath(), vaultPassword.clone(), null);
        try {
            assertEquals(OPERATOR, opened.getSuperAdminPrincipalID());
            assertFalse(opened.isSelfManaged(), "opened through the INI realm");
        } finally {
            opened.getDataStore().close();
        }
        NoSneakStore.FirstRun other = new NoSneakStore.FirstRun("someone-else", "Other-pass1!".toCharArray(), "", null, null);
        ShiroDSDomainSecurityManager reopened = NoSneakStore.openOrCreate(dir.getPath(), vaultPassword.clone(), other);
        try {
            assertEquals(OPERATOR, reopened.getSuperAdminPrincipalID(), "first-run answers are ignored once a vault exists");
        } finally {
            reopened.getDataStore().close();
        }

        // the wrong vault password is an IOException with a reason, as before
        assertThrows(IOException.class, () -> NoSneakStore.openOrCreate(dir.getPath(), "wrong".toCharArray(), null));
    }
}
