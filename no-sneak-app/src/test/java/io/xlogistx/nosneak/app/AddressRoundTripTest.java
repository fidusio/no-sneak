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
 * Covers the address list stored as an inline {@code NVGenericMapList("addresses")} inside the
 * subject's property bag — each address its own {@link NVGenericMap} of flat string fields.
 * Exercises add → list, multiple addresses, edit-in-place
 * ({@link Session#changeAddressDetails(NVGenericMap)}), remove-by-reference
 * ({@link Session#deleteAddress(NVGenericMap)}), persistence across a logout/login cycle, and the
 * signed-out guards.
 *
 * <p>Runs over the in-memory {@link MockAPIDataStore}. The inline {@code NVGenericMapList} model
 * is deliberate: it is the container the real Mongo store's property-bag serializer supports
 * (unlike an {@code NVEntityReferenceList}, which it silently drops), so what round-trips here
 * also round-trips against Mongo.</p>
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

        List<NVGenericMap> all = s.getAllAddresses();
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

        List<NVGenericMap> all = s.getAllAddresses();
        assertEquals(2, all.size());
        assertEquals("Home", all.get(0).getValue("label"));
        assertEquals("Work", all.get(1).getValue("label"));
    }

    @Test
    public void editInPlacePersists() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));

        // mutate the stored map in place, then persist (the UI's edit path)
        NVGenericMap a = s.getAllAddresses().get(0);
        a.build("city", "Boston");
        a.build("label", "Home 2");
        assertDoesNotThrow(() -> s.changeAddressDetails(a));

        // re-read from the store via a fresh login to confirm the edit survived persistence
        s.logout();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        List<NVGenericMap> all = s.getAllAddresses();
        assertEquals(1, all.size(), "editing must not add a second address");
        assertEquals("Boston", all.get(0).getValue("city"));
        assertEquals("Home 2", all.get(0).getValue("label"));
    }

    @Test
    public void removeByReference() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));
        s.addAddress(address("Work", "500 Market", "SF"));

        NVGenericMap home = s.getAllAddresses().get(0);
        assertDoesNotThrow(() -> s.deleteAddress(home));

        List<NVGenericMap> all = s.getAllAddresses();
        assertEquals(1, all.size());
        assertEquals("Work", all.get(0).getValue("label"), "the surviving address must be the one not removed");
    }

    @Test
    public void allFieldsSurvivePersistence() {
        Session s = freshSession();

        NVGenericMap in = new NVGenericMap();
        in.build("label", "Home")
                .build("street", "1 Main St")
                .build("city", "NYC")
                .build("state", "NY")
                .build("postal", "10001")
                .build("country", "United States");   // stored verbatim — no ISO3 canonicalization
        s.addAddress(in);

        // reload from the store via a fresh login so nothing is served from memory
        s.logout();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        List<NVGenericMap> all = s.getAllAddresses();
        assertEquals(1, all.size());
        NVGenericMap a = all.get(0);
        assertEquals("Home", a.getValue("label"), "label lost");
        assertEquals("1 Main St", a.getValue("street"), "street lost");
        assertEquals("NYC", a.getValue("city"), "city lost");
        assertEquals("NY", a.getValue("state"), "state/province lost");
        assertEquals("10001", a.getValue("postal"), "postal code lost");
        assertEquals("United States", a.getValue("country"), "country lost");
    }

    @Test
    public void editAllFieldsPersists() {
        Session s = freshSession();
        s.addAddress(address("Home", "1 Main St", "NYC"));

        // edit every field the UI can change, then persist the single address
        NVGenericMap a = s.getAllAddresses().get(0);
        a.build("label", "Work")
                .build("street", "500 Market")
                .build("city", "SF")
                .build("state", "CA")
                .build("postal", "94105")
                .build("country", "Canada");
        s.changeAddressDetails(a);

        // reload from the store and confirm every edited field survived
        s.logout();
        s.loginUsernamePassword("kailen", "Password1!".toCharArray());

        List<NVGenericMap> all = s.getAllAddresses();
        assertEquals(1, all.size(), "editing must not add a second address");
        NVGenericMap r = all.get(0);
        assertEquals("Work", r.getValue("label"));
        assertEquals("500 Market", r.getValue("street"));
        assertEquals("SF", r.getValue("city"));
        assertEquals("CA", r.getValue("state"));
        assertEquals("94105", r.getValue("postal"));
        assertEquals("Canada", r.getValue("country"));
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

        assertTrue(s.getAllAddresses().isEmpty(), "logged out → nothing to load");

        s.loginUsernamePassword("kailen", "Password1!".toCharArray());
        List<NVGenericMap> all = s.getAllAddresses();
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

        assertTrue(s.getAllAddresses().isEmpty(), "getAllAddresses returns empty when signed out");
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, () -> s.addAddress(address("H", "1 St", "NYC"))).getMessage());
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, () -> s.changeAddressDetails(address("H", "1 St", "NYC"))).getMessage());
        assertEquals("Not Logged in",
                assertThrows(SecurityException.class, () -> s.deleteAddress(address("H", "1 St", "NYC"))).getMessage());
    }
}
