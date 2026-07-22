package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.security.DomainSecurityManager;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the data-store setup path that {@link Main#showSetup} wires the setup panel to:
 * {@link Main#createDataStore} → {@code connect()} → {@link Main#createDomainSecManager}, run
 * against a real encrypted H2 file store in a temp directory (not the {@code MockAPIDataStore}
 * the other round-trip tests use). Confirms the setup output is a usable security manager and
 * that the {@code CIPHER=AES} encryption the feature relies on actually protects the file.
 */
public class DataStoreSetupFlowTest {

    /** The setup factory must yield a security manager that drives the real register/login flow. */
    @Test
    public void setupProducesUsableStore(@TempDir Path dir) throws Exception {
        APIDataStore<?, ?> ds = Main.createDataStore("nsuser", "Password1!", "filepass", dir.toString());
        ds.connect();
        DomainSecurityManager dsm = Main.createDomainSecManager(ds);
        try {
            assertNotNull(dsm, "setup must produce a DomainSecurityManager");

            Session session = new Session(dsm);
            assertDoesNotThrow(() -> session.registerUsernamePassword("bob", "Password9!".toCharArray()),
                    "the store produced by setup must accept a registration");
            assertDoesNotThrow(() -> session.loginUsernamePassword("bob", "Password9!".toCharArray()),
                    "the freshly registered user must be able to log in against the setup store");
            assertEquals("bob", session.getPrincipalID());
        } finally {
            ds.close();
        }
    }

    /** Reopening an existing encrypted store with the wrong encryption password must fail. */
    @Test
    public void wrongEncryptionPasswordCannotReopenStore(@TempDir Path dir) throws Exception {
        APIDataStore<?, ?> created = Main.createDataStore("nsuser", "Password1!", "right-file-pass", dir.toString());
        created.connect(); // materializes the encrypted file store on disk
        created.close();

        APIDataStore<?, ?> reopened = Main.createDataStore("nsuser", "Password1!", "wrong-file-pass", dir.toString());
        assertThrows(Exception.class, reopened::connect,
                "an existing encrypted store must reject the wrong encryption password");
    }
}