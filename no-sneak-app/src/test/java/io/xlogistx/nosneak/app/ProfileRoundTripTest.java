package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;

import java.util.LinkedHashMap;
import java.util.Map;


import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies the profile properties-bag round-trip: save → load, overwrite (replace not
 * append), and persistence across a logout/login cycle in the same store.
 */
public class ProfileRoundTripTest {

    private static Session freshSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        return new Session(dsm);
    }

    private static Map<String, String> map(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    @Test
    public void saveThenLoad() {
        Session s = freshSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        s.saveProfile(map("firstName", "Jane", "city", "NYC"));

        Map<String, String> p = s.loadProfile("firstName", "city", "country");
        assertEquals("Jane", p.get("firstName"));
        assertEquals("NYC", p.get("city"));
        assertEquals("", p.get("country"), "unset key should load as empty string");
    }

    @Test
    public void overwriteReplacesNotAppends() {
        Session s = freshSession();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        s.saveProfile(map("firstName", "Jane"));
        s.saveProfile(map("firstName", "Ann"));   // second save of same key

        assertEquals("Ann", s.loadProfile("firstName").get("firstName"),
                "repeated save must replace, not append (stale value)");
    }

    @Test
    public void saveRejectedWhenSignedOut() {
        Session s = freshSession();   // never logged in
        assertEquals("Not Logged in", s.saveProfile(map("firstName", "Jane")),
                "saving a profile with no signed-in subject must be refused");
    }

    @Test
    public void survivesLogoutLogin() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        s.saveProfile(map("firstName", "Jane"));
        s.logout();

        assertEquals("", s.loadProfile("firstName").get("firstName"),
                "logged out → nothing to load");

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        assertEquals("Jane", s.loadProfile("firstName").get("firstName"),
                "profile must persist across logout/login in the same store");
    }
}
