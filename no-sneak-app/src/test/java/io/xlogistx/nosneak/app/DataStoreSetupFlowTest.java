package io.xlogistx.nosneak.app;

import io.xlogistx.datastore.h2p.H2PSetup;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.nosneak.data.ReportContent;
import io.xlogistx.opsec.SecretStore;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the installation path {@link NoSneakMain#showSetup} wires the setup panel to — a real
 * encrypted H2 file store, set up the way the datastore's deployment model says
 * ({@link NoSneakStore#create} = {@code H2PSetup command=create}: vault with every mandatory
 * entry, H2 file, super-admin = the operator, the no-sneak app, {@code shiro.ini}) and opened
 * through its vault and INI afterwards ({@link NoSneakStore#open}: manager attached to the INI
 * realm), with the Shiro controller and the key maker on the store, so the per-row access check
 * and the encryption at rest are on. The other round-trip tests use the {@code MockAPIDataStore},
 * which checks nothing; this is where the session's subject binding is proven against the store
 * that enforces it, and where the app login gate is crossed on a real realm:
 * <ol>
 * <li>the operator (super-admin) logs in scoped to the app through its wildcard; a registered
 *     user through the {@code app_user} grant sign-up gives; a subject created without the grant
 *     is refused;</li>
 * <li>register, log in, save a scan report and a third-party key <b>from a pool thread</b> (as a
 *     {@code SwingWorker} would) and read them back — the subject is bound per call;</li>
 * <li>a second user sees none of the first user's rows or keys;</li>
 * <li>after logout the kept subject can do nothing and no thread is left with a subject bound;</li>
 * <li>the vault's password is the one secret: wrong password, no store;</li>
 * <li>reopened through the vault, the persisted data is still the first user's.</li>
 * </ol>
 * The H2 URL the set-up writes carries {@code DB_CLOSE_DELAY=-1}, so the database stays open in
 * the JVM after the store closes: each run gets a fresh directory under {@code target/} rather
 * than a {@code @TempDir}, whose cleanup would fail on the locked file.
 */
public class DataStoreSetupFlowTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";
    private static final String ALICE_PWD = "Password9!";
    private static final String BOB_PWD = "Password8@";

    private static File freshDirectory() {
        File ret = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(ret.mkdirs() || ret.isDirectory(), "cannot create " + ret);
        return ret;
    }

    /** Runs {@code work} on a fresh pool thread, as the panels' {@code BackgroundTask} does. */
    private static <V> V onWorker(ExecutorService pool, java.util.concurrent.Callable<V> work) throws Exception {
        Future<V> f = pool.submit(work);
        return f.get();
    }

    @Test
    public void vaultOpensStoreAndEverySubjectSeesOnlyItsOwnRows() throws Exception {
        File dir = freshDirectory();
        char[] vaultPassword = "V4ult-pass!".toCharArray();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        ShiroDSDomainSecurityManager dsm = NoSneakStore.create(dir.getPath(), vaultPassword.clone(), firstRun);
        String reportGUID;
        try {
            // what the set-up left behind: vault with every mandatory entry, generated db secrets, H2 file, INI
            assertTrue(NoSneakStore.vaultExists(dir.getPath()), "create must leave the vault behind");
            assertTrue(NoSneakStore.iniFile(dir.getPath()).isFile(), "create must write shiro.ini");
            assertTrue(new File(dir, NoSneakStore.DB_NAME + ".mv.db").isFile(), "create must create the H2 file");
            try (SecretStore vault = SecretStore.open(NoSneakStore.vaultFile(dir.getPath()), vaultPassword.clone())) {
                assertTrue(vault.missingMandatory().isEmpty(), "missing " + vault.missingMandatory());
                assertEquals(OPERATOR, vault.getSuperAdminID(), "the operator is the super-admin");
                assertEquals(NoSneakStore.DEFAULT_DB_USER, vault.get(SecretStore.StoreParam.DB_USER.getName()));
                assertEquals(H2PSetup.GENERATED_PASSWORD_LENGTH, vault.get(SecretStore.StoreParam.DB_PASSWORD.getName()).length());
                assertEquals(H2PSetup.GENERATED_PASSWORD_LENGTH, vault.get(SecretStore.StoreParam.DB_ENC_PASSWORD.getName()).length());
                assertEquals(NoSneakStore.APP_ID, vault.get(H2PSetup.APP_ID_ENTRY), "the no-sneak app is the deployment's default app");
                assertTrue(vault.get(SecretStore.StoreParam.DB_URL.getName()).contains(";CIPHER=AES"));
            }
            assertFalse(dsm.isSelfManaged(), "the manager is attached to the INI realm");
            assertEquals(OPERATOR, dsm.getSuperAdminPrincipalID());
            assertNotNull(dsm.getDataStore().getAPIConfigInfo().getSecurityController(), "the store runs with the controller");
            assertNotNull(dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID), "the set-up creates the no-sneak app");
            assertNotNull(dsm.commonApp(), "the set-up creates the common app");

            Session session = new Session(dsm);
            // 1. the app login gate: the operator's wildcard, a sign-up's app_user grant, nothing else
            assertDoesNotThrow(() -> session.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray()), "the operator logs into the app");
            assertEquals(OPERATOR, session.getPrincipalID());
            assertTrue(dsm.isSuperAdminSubject(session.getSubjectGUID()));
            session.logout();
            // the app's registrar (its owner + app_admin) got the operator's password beside its JWT login
            String registrar = NoSneakStore.registrarPrincipal(dsm);
            assertEquals("registrar." + NoSneakStore.APP_ID, registrar);
            assertDoesNotThrow(() -> session.loginUsernamePassword(registrar, OPERATOR_PWD.toCharArray()), "the registrar logs into the app by password");
            assertEquals(dsm.lookupRegistrar(dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID)).getGUID(),
                    session.getSubjectGUID(), "the login is the registrar subject");
            assertFalse(dsm.isSuperAdminSubject(session.getSubjectGUID()));
            session.logout();
            assertDoesNotThrow(() -> NoSneakStore.setRegistrarPassword(dsm, "Other-pass1!".toCharArray()), "a second call keeps the password");
            assertThrows(AccessSecurityException.class, () -> session.loginUsernamePassword(registrar, "Other-pass1!".toCharArray()));
            dsm.createSubjectID("nogrant-tester", org.zoxweb.server.security.HashUtil.toBCryptPassword(ALICE_PWD));
            assertThrows(AccessSecurityException.class, () -> session.loginUsernamePassword("nogrant-tester", ALICE_PWD.toCharArray()),
                    "a subject without app:login is refused by the realm");

            assertDoesNotThrow(() -> session.registerUsernamePassword("alice-tester", ALICE_PWD.toCharArray()));
            assertDoesNotThrow(() -> session.registerUsernamePassword("bob-tester", BOB_PWD.toCharArray()));
            assertThrows(AccessSecurityException.class, () -> session.loginUsernamePassword("alice-tester", "wrong-Pass1!".toCharArray()));
            assertFalse(session.isAuthenticated());

            // 2. alice, working from pool threads
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

            // 3. bob sees none of it
            session.logout();
            assertDoesNotThrow(() -> session.loginUsernamePassword("bob-tester", BOB_PWD.toCharArray()));
            assertTrue(onWorker(pool, session::getAllScanResults).isEmpty(), "bob sees no report of alice's");
            assertNull(onWorker(pool, () -> session.getScanResult(reportGUID)), "not even by GUID");
            assertTrue(session.getAllCredentialForLoggedInUser().stream()
                    .noneMatch(c -> c instanceof SubjectAPIKey), "bob has no key");

            // 4. after logout the session can do nothing, and no worker thread holds a subject
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

        // 5. the vault password is the one secret
        assertThrows(IOException.class, () -> NoSneakStore.open(dir.getPath(), "not-the-password".toCharArray()),
                "a wrong vault password must not open the store");
        assertThrows(IOException.class, () -> NoSneakStore.create(dir.getPath(), vaultPassword.clone(), firstRun),
                "create refuses a directory that already holds a vault");

        // 6. reopened through the vault and the INI: the data is still alice's
        ShiroDSDomainSecurityManager reopened = NoSneakStore.open(dir.getPath(), vaultPassword);
        try {
            assertFalse(reopened.isSelfManaged());
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

    @Test
    public void createRefusesABadOperatorAndWritesNothing() throws Exception {
        File dir = freshDirectory();
        char[] vaultPassword = "V4ult-pass!".toCharArray();
        assertThrows(IllegalArgumentException.class, () -> NoSneakStore.create(dir.getPath(), vaultPassword,
                new NoSneakStore.FirstRun(OPERATOR, "weak".toCharArray(), null, null, null)), "the operator's password follows the rules");
        assertThrows(IllegalArgumentException.class, () -> NoSneakStore.create(dir.getPath(), vaultPassword,
                new NoSneakStore.FirstRun("  ", OPERATOR_PWD.toCharArray(), null, null, null)), "an operator id is required");
        assertFalse(NoSneakStore.vaultExists(dir.getPath()), "nothing written");
        assertFalse(NoSneakStore.iniFile(dir.getPath()).exists(), "nothing written");
        assertThrows(IOException.class, () -> NoSneakStore.open(dir.getPath(), vaultPassword), "no vault, no store");
    }
}
