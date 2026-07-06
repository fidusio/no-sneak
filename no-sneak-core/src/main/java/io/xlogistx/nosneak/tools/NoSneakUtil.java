package io.xlogistx.nosneak.tools;

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

public final class NoSneakUtil {
    public static final NoSneakUtil SINGLETON = new NoSneakUtil();


    enum ObjName {
        DATA_STORE,
        DOMAIN_MANAGER,
    }


    //private static Map<String, Object> cache = new ConcurrentHashMap<>();
    private static final RegistrarMapDefault<String, Object> cache = new RegistrarMapDefault<>();

    private NoSneakUtil() {
        OPSecUtil.singleton();
    }

    public  DomainSecurityManager createDomainSecManager(String dbURL) {
        ServerUtil.LOCK.lock();
        DomainSecurityManager dsm = null;
        try {
            dsm = cache.lookup(ObjName.DOMAIN_MANAGER.name());
            if (dsm == null) {

                APIDataStore<?, ?> dataStore = cache.lookup(ObjName.DATA_STORE.name());

                if (dataStore == null) {
                    XlogistxMongoDSCreator creator = new XlogistxMongoDSCreator();
                    APIConfigInfo configInfo = creator.toAPIConfigInfo(dbURL);

                    dataStore = new XlogistxMongoDataStore();
                    dataStore.setAPIConfigInfo(configInfo);


                    dsm = new DomainSecurityManagerDefault()
                            .setDataStore(dataStore)
                            .addCredentialType(CIPassword.class)
                            .addCredentialType(SubjectAPIKey.class);
                    cache.put(ObjName.DOMAIN_MANAGER.name(), dsm);
                    cache.put(ObjName.DATA_STORE.name(), dataStore);

                }
            }
        } finally {
            ServerUtil.LOCK.unlock();
        }

        return dsm;
    }
}
