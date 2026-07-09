package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.mock.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the address list stored as an {@code NVGenericMapList("addresses")} inside the
 * subject's property bag — each address its own {@link NVGenericMap}. Exercises add → list,
 * multiple addresses, edit-in-place ({@link Session#saveAddresses()}), remove-by-reference,
 * persistence across a logout/login cycle, and the signed-out guards.
 *
 * <p>Failure is signalled by a thrown {@link SecurityException}; success returns normally.</p>
 */
public class AddressRoundTripTest {

    private static Session freshSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        return s;
    }

    private static NVGenericMap address(String label, String street, String city) {
        NVGenericMap a = new NVGenericMap();
        a.build("label", label).build("street", street).build("city", city);
        return a;
    }

    @Test
    public void addThenListedWithFields() {
        Session s = freshSession();
        assertDoesNotThrow(() -> s.addAddress(address("Home", "1 Main St", "NYC")));

        List<NVGenericMap> all = s.getAddresses();
        assertEquals(1, all.size());
        NVGenericMap a = all.get(0);
        assertEquals("Home", a.getValue("label"));
        assertEquals("1 Main St", a.getValue("street"));
        assertEquals("NYC", a.getValue("city"));
    }

    @Test
    public void multipleAddressesListedInOrder() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));
        s.addAddress(address("Work", "500 Market", "SF"));

        List<NVGenericMap> all = s.getAddresses();
        assertEquals(2, all.size());
        assertEquals("Home", all.get(0).getValue("label"));
        assertEquals("Work", all.get(1).getValue("label"));
    }

    @Test
    public void editInPlacePersists() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));

        // mutate the stored map in place, then persist (the UI's edit path)
        NVGenericMap a = s.getAddresses().get(0);
        a.build("city", "Boston");
        a.build("label", "Home 2");
        assertDoesNotThrow(s::saveAddresses);

        // re-read from the list to confirm the edit stuck (replace, not append)
        List<NVGenericMap> all = s.getAddresses();
        assertEquals(1, all.size(), "editing must not add a second address");
        assertEquals("Boston", all.get(0).getValue("city"));
        assertEquals("Home 2", all.get(0).getValue("label"));
    }

    @Test
    public void removeByReference() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));
        s.addAddress(address("Work", "500 Market", "SF"));

        NVGenericMap home = s.getAddresses().get(0);
        assertDoesNotThrow(() -> s.removeAddress(home));

        List<NVGenericMap> all = s.getAddresses();
        assertEquals(1, all.size());
        assertEquals("Work", all.get(0).getValue("label"), "the surviving address must be the one not removed");
    }

    @Test
    public void survivesLogoutLogin() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        s.addAddress(address("Home", "1 Main St", "NYC"));
        s.logout();

        assertTrue(s.getAddresses().isEmpty(), "logged out → nothing to load");

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        List<NVGenericMap> all = s.getAddresses();
        assertEquals(1, all.size(), "the address must persist across logout/login in the same store");
        assertEquals("1 Main St", all.get(0).getValue("street"));
    }

    @Test
    public void signedOutGuards() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword("Password1!"));
        Session s = new Session(dsm);   // never logged in

        assertTrue(s.getAddresses().isEmpty(), "getAddresses returns empty when signed out");
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, () -> s.addAddress(address("H", "1 St", "NYC"))).getMessage());
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, s::saveAddresses).getMessage());
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, () -> s.removeAddress(address("H", "1 St", "NYC"))).getMessage());
    }
}