package io.xlogistx.nosneak.app;

import io.xlogistx.datastore.h2p.H2PDSCreator;
import io.xlogistx.datastore.h2p.H2PUtil;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.SecretStore;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import io.xlogistx.shiro.mgt.ShiroSecurityController;
import io.xlogistx.shiro.mgt.ShiroSecurityManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.util.SUS;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * How no-sneak opens its data store since the h2p datastore refuses a connection without a
 * master key (user rule 2026-10-02: <i>the prerequisite of any run is to load the keystore with
 * its password and take the db info and the master key from it</i>).
 *
 * <p>A no-sneak installation is one directory ({@code location}) holding two files:</p>
 * <ul>
 * <li>{@value #VAULT_NAME} — an opsec {@link SecretStore} (BCFKS, one password) with the AES
 *     <b>master key</b> every subject key is wrapped under ({@code master-key}) and the database
 *     settings ({@code db.url}, {@code db.user}, {@code db.password}, {@code db.enc-password} —
 *     the {@link SecretStore.StoreParam} names);</li>
 * <li>{@value #DB_NAME}{@code .mv.db} — the encrypted H2 database the vault's {@code db.url} names.</li>
 * </ul>
 *
 * <p>{@link #create} is the first run (the setup screen): it writes the vault with a fresh master
 * key and the database settings the subject typed, then opens the store. {@link #open} is every
 * later run: the vault password is the only secret the subject enters. Both end in
 * {@link #openStore}: the master key goes into the {@link KeyMakerProvider}, the store is
 * configured with the {@link ShiroSecurityController} and that key maker (encryption at rest and
 * the per-row access check are on — the store will not connect otherwise), and
 * {@link #bootstrap} makes the store usable: the catalog of the common app is seeded and the
 * no-sneak app ({@code xlogistx.com-nosneak}, the scope every login and every issued key carries)
 * exists. Both steps are idempotent, so they run on every open.</p>
 *
 * <p>No super-admin is created and the vault carries no {@code super-admin-id}: a desktop store
 * has one operator, who registers from the login screen, and the manager's permission enforcement
 * stays off (its default), so nothing here needs an administrator. The registrar subject that
 * {@code createApp} makes for the app is left in the store, its key sealed and unused — sign-up is
 * the direct {@code createSubjectID} the app always did, not the registrar path.</p>
 */
public final class NoSneakStore {

    /** The H2 database name inside the location directory. */
    public static final String DB_NAME = "no-sneak";
    /** The vault file inside the location directory. */
    public static final String VAULT_NAME = "no-sneak.store";

    private static final String MASTER_KEY_ALIAS = SecretStore.StoreParam.MASTER_KEY.getName();

    private NoSneakStore() {
    }

    /** The vault file of an installation directory. */
    public static File vaultFile(String location) {
        SUS.checkIfNulls("location can't be null", location);
        return new File(location.trim(), VAULT_NAME);
    }

    /** True when {@code location} already holds a vault, i.e. {@link #open} is the right call. */
    public static boolean vaultExists(String location) {
        return !SUS.isEmpty(location) && vaultFile(location).isFile();
    }

    /**
     * First run: writes the vault with a fresh AES-256 master key and the database settings, then
     * opens the store ({@link #open}). The database is created by the first connection.
     *
     * @param location      an existing directory; receives the vault and the database files
     * @param vaultPassword the password of the vault — the one secret every later run needs
     * @param dbUser        H2 user of the new database
     * @param dbPassword    its password
     * @param dbEncPassword the H2 file-encryption password ({@code CIPHER=AES})
     * @throws IOException              when a vault already exists there, or the file can't be written
     * @throws GeneralSecurityException when the keystore can't be built
     */
    public static ShiroDSDomainSecurityManager create(String location, char[] vaultPassword,
                                                      String dbUser, String dbPassword, String dbEncPassword)
            throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("location, vault password and database settings can't be null",
                location, vaultPassword, dbUser, dbPassword, dbEncPassword);
        if (SUS.isEmpty(dbUser) || SUS.isEmpty(dbPassword) || SUS.isEmpty(dbEncPassword)) {
            throw new IllegalArgumentException("database user, password and encryption password are required");
        }
        OPSecUtil.singleton();
        File vault = vaultFile(location);
        if (vault.exists()) {
            throw new IOException("a vault already exists at " + vault + ": open it instead");
        }
        String jdbcURL = H2PUtil.defaultH2JdbcURL(location, DB_NAME); // validates the directory
        try (SecretStore created = SecretStore.create(vault, vaultPassword)) {
            created.createSecretKey(MASTER_KEY_ALIAS);
            created.put(SecretStore.StoreParam.DB_URL.getName(), jdbcURL);
            created.put(SecretStore.StoreParam.DB_USER.getName(), dbUser);
            created.put(SecretStore.StoreParam.DB_PASSWORD.getName(), dbPassword);
            created.put(SecretStore.StoreParam.DB_ENC_PASSWORD.getName(), dbEncPassword);
            created.save();
        }
        return open(location, vaultPassword);
    }

    /**
     * Every run: opens the vault, loads its master key into the {@link KeyMakerProvider}, opens
     * the database it names and returns the bootstrapped manager.
     *
     * @throws IOException              when there is no vault at {@code location} or the password is wrong
     *                                  (the keystore's integrity check fails)
     * @throws GeneralSecurityException when the keystore can't be read
     * @throws IllegalStateException    when the vault lacks the master key or the database URL
     */
    public static ShiroDSDomainSecurityManager open(String location, char[] vaultPassword)
            throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("location and vault password can't be null", location, vaultPassword);
        OPSecUtil.singleton();
        File file = vaultFile(location);
        String url, user, password, encPassword;
        SecretKey masterKey;
        try (SecretStore vault = SecretStore.open(file, vaultPassword)) {
            SecretKey stored = vault.getSecretKey(MASTER_KEY_ALIAS);
            if (stored == null) {
                throw new IllegalStateException(file + " holds no " + MASTER_KEY_ALIAS + " secret key");
            }
            // detach from the keystore entry: the key outlives the vault handle
            masterKey = new SecretKeySpec(stored.getEncoded(), stored.getAlgorithm());
            url = vault.get(SecretStore.StoreParam.DB_URL.getName());
            user = vault.get(SecretStore.StoreParam.DB_USER.getName());
            password = vault.get(SecretStore.StoreParam.DB_PASSWORD.getName());
            encPassword = vault.get(SecretStore.StoreParam.DB_ENC_PASSWORD.getName());
        }
        if (SUS.isEmpty(url)) {
            throw new IllegalStateException(file + " holds no " + SecretStore.StoreParam.DB_URL.getName() + " entry");
        }
        return openStore(url, user, password, encPassword, masterKey);
    }

    /**
     * Opens the database with the master key: the key goes into the {@link KeyMakerProvider}
     * (the JVM-wide key maker the store and the manager use), the configuration gets the
     * {@link ShiroSecurityController} and that key maker ({@link #secure}), the store connects,
     * and the manager is {@link #bootstrap}ped.
     */
    public static ShiroDSDomainSecurityManager openStore(String jdbcURL, String user, String password,
                                                         String encPassword, SecretKey masterKey) {
        SUS.checkIfNulls("jdbc url and master key can't be null", jdbcURL, masterKey);
        OPSecUtil.singleton();
        KeyMakerProvider.SINGLETON.setMasterSecretKey(masterKey);
        APIConfigInfo cfg = secure(H2PDSCreator.toAPIConfigInfo(jdbcURL, user, password, encPassword));
        APIDataStore<?, ?> store = new H2PDSCreator().createAPI(null, cfg);
        try {
            store.connect();
            return bootstrap(new ShiroDSDomainSecurityManager(store));
        } catch (RuntimeException e) {
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
     * Makes a store usable by no-sneak, idempotently: the catalog of the common app is seeded (the
     * manager's catalog rows belong to {@code xlogistx.com-common}, which must exist), the no-sneak
     * app {@code xlogistx.com-nosneak} is created when missing (its registrar and key are created
     * with it and left alone), and the manager's own Shiro sessions never time out — the desktop
     * subject stays logged in for the life of the window, which can be hours, and nothing here
     * re-authenticates a timed-out subject.
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

    /** The one message the login screen shows for a store that was opened without its vault. */
    public static AccessSecurityException notOpened() {
        return new AccessSecurityException("The data store is not open: load the vault first");
    }
}
