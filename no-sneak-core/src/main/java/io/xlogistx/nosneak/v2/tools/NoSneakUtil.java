package io.xlogistx.nosneak.v2.tools;

import io.xlogistx.datastore.XlogistxMongoDSCreator;
import io.xlogistx.datastore.XlogistxMongoDataStore;
import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.util.ServerUtil;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.RegistrarMapDefault;

/**
 * Lazily builds and caches a {@link DomainSecurityManager} over the xlogistx datastore.
 * <p>
 * (v2 fix for v1 issue C2: the domain manager is now always constructed from the datastore —
 * cached or freshly created — instead of only when the datastore is also absent, which left a
 * cached-datastore-but-no-manager path returning {@code null}.)
 */
public final class NoSneakUtil {
    public static final NoSneakUtil SINGLETON = new NoSneakUtil();

    enum ObjName {
        DATA_STORE,
        DOMAIN_MANAGER,
    }

    private static final RegistrarMapDefault<String, Object> cache = new RegistrarMapDefault<>();

    private NoSneakUtil() {
        OPSecUtil.singleton();
    }

    public DomainSecurityManager createDomainSecManager(String dbURL) {
        ServerUtil.LOCK.lock();
        try {
            DomainSecurityManager dsm = cache.lookup(ObjName.DOMAIN_MANAGER.name());
            if (dsm == null) {
                APIDataStore<?, ?> dataStore = cache.lookup(ObjName.DATA_STORE.name());
                if (dataStore == null) {
                    XlogistxMongoDSCreator creator = new XlogistxMongoDSCreator();
                    APIConfigInfo configInfo = creator.toAPIConfigInfo(dbURL);
                    XlogistxMongoDataStore mongo = new XlogistxMongoDataStore();
                    mongo.setAPIConfigInfo(configInfo);
                    dataStore = mongo;
                    cache.put(ObjName.DATA_STORE.name(), dataStore);
                }
                // Build the manager from the datastore (cached or new) — fixes the C2 NPE-return.
                dsm = new DomainSecurityManagerDefault()
                        .setDataStore(dataStore)
                        .addCredentialType(CIPassword.class)
                        .addCredentialType(SubjectAPIKey.class);
                cache.put(ObjName.DOMAIN_MANAGER.name(), dsm);
            }
            return dsm;
        } finally {
            ServerUtil.LOCK.unlock();
        }
    }
}
