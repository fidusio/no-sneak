package io.xlogistx.nosneak.app;

import io.xlogistx.datastore.h2p.H2PDSCreator;
import io.xlogistx.datastore.h2p.H2PDataStore;
import io.xlogistx.datastore.h2p.H2PSetup;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.SecretStore;
import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import io.xlogistx.shiro.mgt.ShiroSecurityController;
import io.xlogistx.shiro.mgt.ShiroSecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.RoleInfo;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.SUS;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * How no-sneak sets up and opens its data store, following the h2p datastore's deployment model
 * (zoxweb-datastore {@code h2p-datastore/CLAUDE.md}, {@code H2PSetup} and the runnable
 * {@code ShiroIniRealmMain}; user, 2026-10-21: <i>the model how to set up the local H2 database
 * changed, read it from the datastore project</i>).
 *
 * <p>A no-sneak installation is one directory ({@code location}) holding three files, all written
 * by the first run and never by a later one:</p>
 * <ul>
 * <li>{@value #VAULT_NAME} — an opsec {@link SecretStore} (BCFKS, one password) with every
 *     mandatory {@link SecretStore.StoreParam}: the AES <b>master key</b> every subject key is
 *     wrapped under ({@code master-key}), the <b>super-admin</b> ({@code super-admin-id} and its
 *     initial {@code super-admin-password}), the database settings ({@code db.url}, {@code db.user},
 *     {@code db.password}, {@code db.enc-password}) and the deployment's default app
 *     ({@code app-id} = {@value #APP_ID});</li>
 * <li>{@value #DB_NAME}{@code .mv.db} — the encrypted H2 database the vault's {@code db.url} names;</li>
 * <li>{@value #SHIRO_INI_NAME} — the Shiro INI the realm is built from (realm, matcher, cache,
 *     session manager; the data store and the super-admin id are not in it).</li>
 * </ul>
 *
 * <p>{@link #create} is the first run (the setup screen): it is {@code H2PSetup command=create}
 * run in-process with every answer given, so the vault is written, the H2 file created, the
 * database set up by {@code SecurityAdminTool bootstrap-super-admin} (catalog, super-admin,
 * common app with its registrar) and {@code create-app} (the no-sneak app with its starter
 * catalog and its registrar), and the INI written and loaded once — the one sanctioned way to
 * create a super-admin. The <b>operator is the super-admin</b>: a desktop store has one operator,
 * who types their own account on the setup screen and logs in with it from then on (the
 * {@code super_admin} role's wildcard applies in every login, so the app login gate lets them in).
 * The app's registrar {@code registrar.xlogistx.com-nosneak} — the app's owner and admin — gets
 * the <b>same password</b> ({@link #setRegistrarPassword}), so the operator can also log in as the
 * app admin; its signing key, printed once by the set-up, is discarded here: no-sneak signs
 * subjects up directly ({@link Session#registerUsernamePassword}), never through a registrar JWT.</p>
 *
 * <p>{@link #open} is every later run and sets nothing up: the vault password is the only secret
 * the subject enters. The master key goes into the {@link KeyMakerProvider}, the store is
 * configured with the {@link ShiroSecurityController} and that key maker ({@link #secure} —
 * the h2p store will not connect otherwise), registered under
 * {@code ResourceManager.Resource.DATA_STORE}, the INI's security manager is loaded and installed
 * as the global one, and the manager is attached to the INI's realm
 * ({@link ShiroDSDomainSecurityManager#fromGlobal(APIDataStore)}) with the super-admin id from the
 * vault. An installation whose vault lacks a mandatory entry (one written before this model) or
 * whose database has no no-sneak app is refused with the reason.</p>
 *
 * <p><b>Logging in.</b> Since the app login gate (upstream, 2026-10-20) a login scoped to
 * {@value #APP_ID} succeeds only for a subject whose grants in that app imply {@code app:login}:
 * the super-admin through its wildcard, every other subject through the app's {@code app_user}
 * role, which {@link #grantAppUser} gives a subject no-sneak signs up.</p>
 */
public final class NoSneakStore {

    /** The H2 database name inside the location directory. */
    public static final String DB_NAME = "no-sneak";
    /** The vault file inside the location directory. */
    public static final String VAULT_NAME = "no-sneak.store";
    /** The Shiro INI inside the location directory, written by {@link #create}. */
    public static final String SHIRO_INI_NAME = "shiro.ini";
    /** The deployment's default app, {@code <domain>-<app>} of {@link Session#NO_SNEAK_DOMAIN_ID} / {@link Session#NO_SNEAK_APP_ID}. */
    public static final String APP_ID = Session.NO_SNEAK_DOMAIN_ID + "-" + Session.NO_SNEAK_APP_ID;
    /** The H2 user a first run gets when the setup screen leaves it empty. */
    public static final String DEFAULT_DB_USER = H2PSetup.DEFAULT_H2_USER;

    /**
     * The answers of a first run that are not the vault password: the operator's account (the
     * store's super-admin) and the database settings. A null or empty database password or
     * encryption password is generated by the set-up and lives only in the vault; an empty user
     * is {@value #DEFAULT_DB_USER}.
     */
    public record FirstRun(String adminID, char[] adminPassword, String dbUser, String dbPassword, String dbEncPassword) {
        public FirstRun {
            SUS.checkIfNulls("operator id and password can't be null", adminID, adminPassword);
        }
    }

    private NoSneakStore() {
    }

    /** The vault file of an installation directory. */
    public static File vaultFile(String location) {
        SUS.checkIfNulls("location can't be null", location);
        return new File(location.trim(), VAULT_NAME);
    }

    /** The Shiro INI of an installation directory. */
    public static File iniFile(String location) {
        SUS.checkIfNulls("location can't be null", location);
        return new File(location.trim(), SHIRO_INI_NAME);
    }

    /** True when {@code location} already holds a vault, i.e. {@link #open} is the right call. */
    public static boolean vaultExists(String location) {
        return !SUS.isEmpty(location) && vaultFile(location).isFile();
    }

    /**
     * First run: {@code H2PSetup command=create} in-process — vault, encrypted H2 file, database
     * set-up (super-admin = the operator, common app, the no-sneak app) and Shiro INI — then
     * {@link #open}.
     *
     * @param location      an existing directory; receives the vault, the database files and the INI
     * @param vaultPassword the password of the vault — the one secret every later run needs
     * @param firstRun      the operator's account and the database settings
     * @throws IOException              when a vault or an INI already exists there, the directory
     *                                  is missing, or the set-up fails (its own message)
     * @throws GeneralSecurityException when the vault can't be read back
     * @throws IllegalArgumentException when the operator's password fails the password rules
     */
    public static ShiroDSDomainSecurityManager create(String location, char[] vaultPassword, FirstRun firstRun)
            throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("location, vault password and first-run answers can't be null", location, vaultPassword, firstRun);
        if (SUS.isEmpty(firstRun.adminID())) {
            throw new IllegalArgumentException("the operator's username is required");
        }
        if (!FilterType.PASSWORD.isValid(new String(firstRun.adminPassword()))) {
            throw new IllegalArgumentException("the operator's password does not meet the password rules");
        }
        OPSecUtil.singleton();
        File dir = new File(location.trim());
        if (!dir.isDirectory()) {
            throw new IOException(dir + " is not a directory");
        }
        File vault = vaultFile(location);
        if (vault.exists()) {
            throw new IOException("a vault already exists at " + vault + ": open it instead");
        }
        File ini = iniFile(location);
        if (ini.exists()) {
            throw new IOException("a Shiro INI already exists at " + ini + " without a vault: move it away first");
        }
        // the set-up prints the registrar keys once; no-sneak does not keep them, so the output is dropped
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = H2PSetup.run(new PrintStream(out, true), new PrintStream(err, true),
                H2PSetup.Param.COMMAND.getName() + "=" + H2PSetup.Command.CREATE.getName(),
                H2PSetup.Param.STORE.getName() + "=" + vault.getPath(),
                H2PSetup.Param.STORE_PASSWORD.getName() + "=" + new String(vaultPassword),
                H2PSetup.Param.DB_TYPE.getName() + "=" + H2PSetup.DBType.H2.getName(),
                H2PSetup.Param.DB_PATH.getName() + "=" + dir.getAbsolutePath(),
                H2PSetup.Param.DB_NAME.getName() + "=" + DB_NAME,
                H2PSetup.Param.DB_ENCRYPT.getName() + "=yes",
                H2PSetup.Param.DB_USER.getName() + "=" + (SUS.isEmpty(firstRun.dbUser()) ? DEFAULT_DB_USER : firstRun.dbUser().trim()),
                H2PSetup.Param.DB_PASSWORD.getName() + "=" + nullToEmpty(firstRun.dbPassword()),
                H2PSetup.Param.DB_ENC_PASSWORD.getName() + "=" + nullToEmpty(firstRun.dbEncPassword()),
                H2PSetup.Param.SUPER_ADMIN_ID.getName() + "=" + firstRun.adminID().trim(),
                H2PSetup.Param.SUPER_ADMIN_PASSWORD.getName() + "=" + new String(firstRun.adminPassword()),
                H2PSetup.Param.APP_ID.getName() + "=" + APP_ID,
                H2PSetup.Param.SHIRO_INI.getName() + "=" + ini.getPath());
        if (code != H2PSetup.EXIT_OK) {
            String reason = err.toString(StandardCharsets.UTF_8).trim();
            throw new IOException("the data store set-up failed (exit " + code + ")" + (reason.isEmpty() ? "" : ": " + reason));
        }
        ShiroDSDomainSecurityManager dsm = open(location, vaultPassword);
        try {
            setRegistrarPassword(dsm, firstRun.adminPassword());
        } catch (RuntimeException e) {
            dsm.getDataStore().close();
            throw e;
        }
        return dsm;
    }

    /**
     * The principal of the no-sneak app's registrar, {@code registrar.xlogistx.com-nosneak}: the
     * app's owner subject and its admin ({@code app_registrar} + {@code app_admin}), created by
     * the set-up with a JWT login only (user, 2026-10-21: <i>this is the app super-admin and he
     * should have a password too</i>).
     */
    public static String registrarPrincipal(ShiroDSDomainSecurityManager dsm) {
        return ShiroDSDomainSecurityManager.registrarPrincipal(requireApp(dsm));
    }

    /**
     * Gives the app's registrar a password login beside its JWT one — the operator's password on
     * a first run, so the one operator can log in as the app admin with what they typed
     * ({@code createCredential(registrar, CIPassword)}, the upstream way to add it). A registrar
     * that already holds a password keeps it.
     *
     * @throws IllegalStateException when the app or its registrar is missing
     */
    public static void setRegistrarPassword(ShiroDSDomainSecurityManager dsm, char[] password) {
        SUS.checkIfNulls("manager and password can't be null", dsm, password);
        SubjectIdentifier registrar = dsm.lookupRegistrar(requireApp(dsm));
        if (registrar == null) {
            throw new IllegalStateException("app " + APP_ID + " has no registrar");
        }
        for (CredentialInfo existing : dsm.lookupCredentialsBySubjectGUID(registrar.getSubjectGUID(), CredentialInfo.Type.PASSWORD)) {
            if (existing != null) {
                return;
            }
        }
        dsm.createCredential(registrar, HashUtil.toBCryptPassword(new String(password)));
    }

    private static AppIDDefault requireApp(ShiroDSDomainSecurityManager dsm) {
        SUS.checkIfNulls("manager can't be null", dsm);
        AppIDDefault app = dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID);
        if (app == null) {
            throw new IllegalStateException("the data store holds no " + APP_ID + " app");
        }
        return app;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    /**
     * Every run: opens the vault, loads its master key into the {@link KeyMakerProvider}, opens
     * the database it names with the controller and the key maker, builds the realm from the
     * installation's {@value #SHIRO_INI_NAME} and attaches the manager to it. Nothing is set up.
     *
     * @throws IOException              when there is no vault or no INI at {@code location}, or the
     *                                  password is wrong (the keystore's integrity check fails)
     * @throws GeneralSecurityException when the keystore can't be read
     * @throws IllegalStateException    when the vault lacks a mandatory entry (an installation
     *                                  written before the 2026-10-21 model) or the database holds
     *                                  no no-sneak app
     */
    public static ShiroDSDomainSecurityManager open(String location, char[] vaultPassword)
            throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("location and vault password can't be null", location, vaultPassword);
        OPSecUtil.singleton();
        File file = vaultFile(location);
        if (!file.isFile()) {
            throw new IOException("no vault at " + file);
        }
        File ini = iniFile(location);
        if (!ini.isFile()) {
            throw new IOException("no " + SHIRO_INI_NAME + " at " + ini + ": the installation was not set up by this version");
        }
        String url, user, password, encPassword, superAdminID;
        SecretKey masterKey;
        try (SecretStore vault = SecretStore.open(file, vaultPassword)) {
            List<SecretStore.StoreParam> missing = vault.missingMandatory();
            if (!missing.isEmpty()) {
                throw new IllegalStateException(file + " lacks the mandatory entries " + missing
                        + ": the installation predates the current set-up model, create a new one");
            }
            SecretKey stored = vault.getSecretKey(SecretStore.StoreParam.MASTER_KEY.getName());
            // detach from the keystore entry: the key outlives the vault handle
            masterKey = new SecretKeySpec(stored.getEncoded(), stored.getAlgorithm());
            url = vault.get(SecretStore.StoreParam.DB_URL.getName());
            user = vault.get(SecretStore.StoreParam.DB_USER.getName());
            password = vault.get(SecretStore.StoreParam.DB_PASSWORD.getName());
            encPassword = vault.get(SecretStore.StoreParam.DB_ENC_PASSWORD.getName());
            superAdminID = vault.getSuperAdminID();
        }
        return openStore(url, user, password, encPassword, masterKey, ini.getPath(), superAdminID);
    }

    /**
     * Opens the database with the master key and builds the realm from the INI: the key goes into
     * the {@link KeyMakerProvider} (the JVM-wide key maker the store and the manager use), the
     * configuration gets the {@link ShiroSecurityController} and that key maker ({@link #secure}),
     * the store connects and is registered under {@code ResourceManager.Resource.DATA_STORE}, the
     * INI's security manager becomes the global one, and the manager is attached to its realm
     * with the super-admin id. The manager's Shiro sessions never time out: the desktop subject
     * stays logged in for the life of the window, which can be hours, and nothing here
     * re-authenticates a timed-out subject.
     *
     * @param shiroIni the INI in Shiro resource syntax (a file path, {@code classpath:…}, {@code file:…})
     * @throws IllegalStateException when the database holds no no-sneak app
     */
    public static ShiroDSDomainSecurityManager openStore(String jdbcURL, String user, String password, String encPassword,
                                                         SecretKey masterKey, String shiroIni, String superAdminID) {
        SUS.checkIfNulls("jdbc url, master key and shiro ini can't be null", jdbcURL, masterKey, shiroIni);
        OPSecUtil.singleton();
        KeyMakerProvider.SINGLETON.setMasterSecretKey(masterKey);
        APIConfigInfo cfg = secure(H2PDSCreator.toAPIConfigInfo(jdbcURL, user, password, encPassword));
        H2PDataStore store = new H2PDSCreator().createAPI(null, cfg);
        try {
            store.connect();
            ResourceManager.SINGLETON.register(ResourceManager.Resource.DATA_STORE, store);
            SecurityManager sm = ShiroUtil.loadSecurityManager(shiroIni);
            SecurityUtils.setSecurityManager(sm);
            ThreadContext.remove();
            ShiroDSDomainSecurityManager dsm = ShiroDSDomainSecurityManager.fromGlobal(store);
            dsm.setSuperAdminPrincipalID(superAdminID); // never in the INI: the vault names the super-admin
            if (sm instanceof SessionsSecurityManager sessions
                    && sessions.getSessionManager() instanceof DefaultSessionManager manager) {
                manager.setGlobalSessionTimeout(-1); // never expire
            }
            if (dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID) == null) {
                throw new IllegalStateException("the data store holds no " + APP_ID + " app: run H2PSetup command=setup on its vault");
            }
            return dsm;
        } catch (RuntimeException | Error e) {
            SecurityUtils.setSecurityManager(null);
            store.close();
            throw e;
        }
    }

    /**
     * {@code cfg} as every no-sneak store is opened: the {@link ShiroSecurityController} (access
     * check per row, sealing of ENCRYPT fields and files) and the {@link KeyMakerProvider}
     * (whose master key must already be loaded). Without both the h2p store refuses to connect.
     */
    public static APIConfigInfo secure(APIConfigInfo cfg) {
        SUS.checkIfNulls("config can't be null", cfg);
        cfg.setSecurityController(new ShiroSecurityController());
        cfg.setKeyMaker(KeyMakerProvider.SINGLETON);
        return cfg;
    }

    /**
     * Makes a store that was <b>not</b> set up by {@link #create} usable by no-sneak, idempotently —
     * the test suites over a mock store, and {@link NoSneakMain#createDomainSecManager}: the
     * catalog of the common app is seeded (the manager's catalog rows belong to
     * {@code xlogistx.com-common}, which must exist), the no-sneak app is created when missing
     * (its starter catalog and registrar with it), and a self-managed manager's Shiro sessions
     * never time out. An installation on disk gets all of this from {@link #create} instead and
     * never runs this.
     *
     * @return {@code dsm}
     */
    public static ShiroDSDomainSecurityManager bootstrap(ShiroDSDomainSecurityManager dsm) {
        SUS.checkIfNulls("manager can't be null", dsm);
        dsm.seedCatalog();
        if (dsm.lookupApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID) == null) {
            dsm.createApp(Session.NO_SNEAK_DOMAIN_ID, Session.NO_SNEAK_APP_ID);
        }
        ShiroSecurityManager sm = dsm.getShiroSecurityManager();
        if (sm != null && sm.getSessionManager() instanceof DefaultSessionManager sessions) {
            sessions.setGlobalSessionTimeout(-1); // never expire
        }
        return dsm;
    }

    /**
     * Grants {@code subject} the no-sneak app's {@code app_user} role — the grant that carries
     * {@code app:login}, without which the realm refuses a login scoped to the app (user rule
     * 2026-10-20). What the manager's own sign-up ({@code registerSubject}) gives a subject,
     * done here because no-sneak signs up directly. Idempotent.
     *
     * @throws IllegalStateException when the app or its {@code app_user} role is missing
     */
    public static void grantAppUser(ShiroDSDomainSecurityManager dsm, SubjectIdentifier subject) {
        SUS.checkIfNulls("manager and subject can't be null", dsm, subject);
        AppIDDefault app = requireApp(dsm);
        RoleInfo appUser = dsm.lookupRole(ShiroUtil.scopeLabel(app), SecurityModel.Role.APP_USER.getName());
        if (appUser == null) {
            throw new IllegalStateException("app " + APP_ID + " has no " + SecurityModel.Role.APP_USER.getName() + " role");
        }
        for (var grant : dsm.getRoleGrants(subject.getGUID(), app)) {
            if (appUser.getGUID().equals(grant.getRoleGUID())) {
                return;
            }
        }
        dsm.addRoleGrant(subject, appUser, app);
    }

    /** The one message the login screen shows for a store that was opened without its vault. */
    public static AccessSecurityException notOpened() {
        return new AccessSecurityException("The data store is not open: load the vault first");
    }
}
