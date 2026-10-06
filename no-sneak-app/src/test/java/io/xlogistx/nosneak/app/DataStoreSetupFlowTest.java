package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.nosneak.data.ReportContent;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the installation path {@link Main#showSetup} wires the setup panel to — a real
 * encrypted H2 file store in a temp directory, opened through its vault the way the app opens
 * it ({@link NoSneakStore#create} on the first run, {@link NoSneakStore#open} afterwards), with
 * the Shiro controller and the key maker on the store, so the per-row access check and the
 * encryption at rest are on. The other round-trip tests use the {@code MockAPIDataStore}, which
 * checks nothing; this is where the session's subject binding is proven against the store that
 * enforces it:
 * <ol>
 * <li>register, log in, save a scan report and a third-party key <b>from a pool thread</b> (as a
 *     {@code SwingWorker} would) and read them back — the subject is bound per call;</li>
 * <li>a second user sees none of the first user's rows or keys;</li>
 * <li>after logout the kept subject can do nothing and no thread is left with a subject bound;</li>
 * <li>the vault's password is the one secret: wrong password, no store;</li>
 * <li>reopened through the vault, the persisted data is still the first user's.</li>
 * </ol>
 */
public class DataStoreSetupFlowTest {

    private static final String ALICE_PWD = "Password9!";
    private static final String BOB_PWD = "Password8@";

    /** Runs {@code work} on a fresh pool thread, as the panels' {@code BackgroundTask} does. */
    private static <V> V onWorker(ExecutorService pool, java.util.concurrent.Callable<V> work) throws Exception {
        Future<V> f = pool.submit(work);
        return f.get();
    }

    @Test
    public void vaultOpensStoreAndEverySubjectSeesOnlyItsOwnRows(@TempDir Path dir) throws Exception {
        char[] vaultPassword = "V4ult-pass!".toCharArray();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        ShiroDSDomainSecurityManager dsm = NoSneakStore.create(dir.toString(), vaultPassword.clone(), "nsuser", "Password1!", "filepass");
        String reportGUID;
        try {
            assertTrue(NoSneakStore.vaultExists(dir.toString()), "create must leave the vault behind");
            assertTrue(dsm.getDataStore().getAPIConfigInfo().getSecurityController() != null, "the store runs with the controller");
            assertNotNull(dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID), "bootstrap creates the no-sneak app");

            Session session = new Session(dsm);
            assertDoesNotThrow(() -> session.registerUsernamePassword("alice-tester", ALICE_PWD.toCharArray()));
            assertDoesNotThrow(() -> session.registerUsernamePassword("bob-tester", BOB_PWD.toCharArray()));
            assertThrows(AccessSecurityException.class, () -> session.loginUsernamePassword("alice-tester", "wrong-Pass1!".toCharArray()));
            assertFalse(session.isAuthenticated());

            // 1. alice, working from pool threads
            assertDoesNotThrow(() -> session.loginUsernamePassword("alice-tester", ALICE_PWD.toCharArray()));
            assertEquals("alice-tester", session.getPrincipalID());
            assertNull(ThreadContext.getSubject(), "the login leaves the calling thread unbound");

            ReportContent report = new ReportContent();
            report.setName("10.0.0.0/24");
            report.setContent("{\"hosts\":[]}");
            ReportContent saved = onWorker(pool, () -> session.saveScanResult(report));
            reportGUID = saved.getGUID();
            assertNotNull(reportGUID, "the store assigns the GUID");
            assertEquals(session.getSubjectGUID(), saved.getSubjectGUID(), "the row is alice's");

            List<ReportContent> listed = onWorker(pool, session::getAllScanResults);
            assertEquals(1, listed.size(), "alice reads her own report back from another pool thread");
            assertEquals("{\"hosts\":[]}", onWorker(pool, () -> session.getScanResult(reportGUID)).getContent());

            SubjectAPIKey key = onWorker(pool, () -> session.storeAPIKey("claude", "assistant", null, null, "sk-alice-secret",
                    "anthropic", null, null, null, true));
            assertNotNull(key.getGUID());
            SubjectAPIKey readBack = (SubjectAPIKey) onWorker(pool, () -> session.getAllCredentialForUserByType(
                    org.zoxweb.shared.security.CredentialInfo.Type.API_KEY)).getFirst();
            assertEquals("sk-alice-secret", readBack.getAPIKey(), "the owner reads the sealed secret back in clear");
            assertNull(ThreadContext.getSubject(), "nothing is bound on the test thread");

            // 2. bob sees none of it
            session.logout();
            assertDoesNotThrow(() -> session.loginUsernamePassword("bob-tester", BOB_PWD.toCharArray()));
            assertTrue(onWorker(pool, session::getAllScanResults).isEmpty(), "bob sees no report of alice's");
            assertNull(onWorker(pool, () -> session.getScanResult(reportGUID)), "not even by GUID");
            assertTrue(session.getAllCredentialForLoggedInUser().stream()
                    .noneMatch(c -> c instanceof SubjectAPIKey), "bob has no key");

            // 3. after logout the session can do nothing, and no worker thread holds a subject
            session.logout();
            assertFalse(session.isAuthenticated());
            assertTrue(session.getAllScanResults().isEmpty());
            assertThrows(AccessSecurityException.class, () -> session.saveScanResult(new ReportContent()));
            for (int i = 0; i < 4; i++) {
                assertNull(onWorker(pool, ThreadContext::getSubject), "no pool thread keeps a subject bound");
            }
        } finally {
            pool.shutdownNow();
            dsm.getDataStore().close();
        }

        // 4. the vault password is the one secret
        assertThrows(IOException.class, () -> NoSneakStore.open(dir.toString(), "not-the-password".toCharArray()),
                "a wrong vault password must not open the store");
        assertThrows(IOException.class, () -> NoSneakStore.create(dir.toString(), vaultPassword.clone(), "x", "y", "z"),
                "create refuses a directory that already holds a vault");

        // 5. reopened through the vault: the data is still alice's
        ShiroDSDomainSecurityManager reopened = NoSneakStore.open(dir.toString(), vaultPassword);
        try {
            Session session = new Session(reopened);
            assertDoesNotThrow(() -> session.loginUsernamePassword("alice-tester", ALICE_PWD.toCharArray()));
            List<ReportContent> listed = session.getAllScanResults();
            assertEquals(1, listed.size(), "alice's report survived the reopen");
            assertEquals(reportGUID, listed.getFirst().getGUID());
            assertEquals("{\"hosts\":[]}", session.getScanResult(reportGUID).getContent());
            session.logout();
        } finally {
            reopened.getDataStore().close();
        }
    }
}
