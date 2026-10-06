package io.xlogistx.nosneak.app;

import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.SecretStore;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIConfigInfoImpl;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.util.UUID;

/**
 * Builds the security manager the no-sneak session tests run on since
 * {@link ShiroDSDomainSecurityManager} replaced {@code DomainSecurityManagerDefault} (user,
 * 2026-10-05). The manager creates every subject with its subject key, so it needs a
 * {@link org.zoxweb.shared.security.KeyMaker} holding a master key on the store configuration;
 * as every run does, the master key is taken from a {@link SecretStore} - here a throw-away vault
 * created once per JVM with a fresh key - and loaded into the {@link KeyMakerProvider}. The store
 * stays the in-memory {@link MockAPIDataStore} the tests used before, configured the way
 * {@link NoSneakStore#secure} configures the real one (it ignores the controller; the real
 * store's access check and encryption are covered by {@link DataStoreSetupFlowTest}).
 */
final class TestSecurity {

    private static final String MASTER_KEY_ALIAS = SecretStore.StoreParam.MASTER_KEY.getName();
    private static SecretKey masterKey;

    private TestSecurity() {
    }

    /** Creates the throw-away vault once, and loads its master key into the key maker. */
    static synchronized void loadMasterKey() {
        if (masterKey == null) {
            OPSecUtil.singleton();
            try {
                File vaultFile = File.createTempFile("no-sneak-test", ".store");
                if (!vaultFile.delete()) {
                    throw new IllegalStateException("cannot prepare " + vaultFile);
                }
                vaultFile.deleteOnExit();
                char[] password = ("T3st-" + UUID.randomUUID()).toCharArray();
                try (SecretStore created = SecretStore.create(vaultFile, password)) {
                    created.createSecretKey(MASTER_KEY_ALIAS);
                    created.save();
                }
                try (SecretStore vault = SecretStore.open(vaultFile, password)) {
                    SecretKey stored = vault.getSecretKey(MASTER_KEY_ALIAS);
                    masterKey = new SecretKeySpec(stored.getEncoded(), stored.getAlgorithm());
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("cannot create the test vault: " + e.getMessage(), e);
            }
        }
        KeyMakerProvider.SINGLETON.setMasterSecretKey(masterKey);
    }

    /**
     * A fresh manager on a fresh in-memory store whose configuration carries the controller and
     * the key maker, bootstrapped as a set-up store is ({@link NoSneakStore#bootstrap}: catalog
     * seeded, the no-sneak app {@code xlogistx.com-nosneak} created — the keys the app issues
     * are scoped to that app and the manager requires it to exist).
     */
    static ShiroDSDomainSecurityManager newManager() {
        loadMasterKey();
        MockAPIDataStore store = new MockAPIDataStore();
        APIConfigInfo cfg = NoSneakStore.secure(new APIConfigInfoImpl());
        store.setAPIConfigInfo(cfg);
        return NoSneakStore.bootstrap(new ShiroDSDomainSecurityManager(store));
    }
}
