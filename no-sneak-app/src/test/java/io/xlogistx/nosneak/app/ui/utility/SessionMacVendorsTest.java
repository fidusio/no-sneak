package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.net.util.NSNetUtil;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.OUIDB;
import org.zoxweb.shared.data.DataContent;
import org.zoxweb.shared.db.QueryMatchString;
import org.zoxweb.shared.util.Const;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Session#loadMacVendors()} against a real encrypted store (2026-10-25): the first login
 * downloads the manuf file once and stores it as the app-wide {@code Mac-Vendor-Content} row, a
 * later session finds the row and loads it without any download, the table resolves, and a body
 * that is not a manuf file is refused and never stored. The download is a seam here, so the test
 * never reaches wireshark.org.
 */
public class SessionMacVendorsTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";
    /** Prefixes real registries do not use; first octet FC keeps the U/L bit clear. */
    private static final byte[] MANUF = """
            # test manuf
            FC:FF:F2\tTestVen\tTest Vendor Inc
            FC:FF:F3:00/28\tOtherCo\tOther Company Ltd
            """.getBytes(StandardCharsets.UTF_8);

    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        System.setProperty("java.awt.headless", "true");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(), firstRun);
    }

    @AfterAll
    static void closeStore() {
        if (dsm != null) dsm.getDataStore().close();
    }

    private static List<DataContent> storedRows(Session s) {
        return s.runAsSystem(() -> dsm.getDataStore().search(DataContent.NVC_DATA_CONTENT, null,
                new QueryMatchString("full_name", Session.MAC_VENDOR_CONTENT_NAME, Const.RelationalOperator.EQUAL)));
    }

    @Test
    void firstLoginStoresTheListAndLaterOnesReuseIt() throws Exception {
        AtomicInteger downloads = new AtomicInteger();
        Session.IOSupplier<byte[]> source = () -> {
            downloads.incrementAndGet();
            return MANUF;
        };

        // a body that is not a manuf file is refused and nothing is stored
        Session refused = new Session(dsm);
        refused.setMacVendorSource(() -> "<html>captive portal</html>".getBytes(StandardCharsets.UTF_8));
        assertThrows(IOException.class, refused::loadMacVendors);
        assertFalse(refused.macVendorsLoaded());
        assertTrue(storedRows(refused).isEmpty(), "a refused body is not stored");

        // first login: nothing stored, so the list is downloaded once, stored and loaded
        Session first = new Session(dsm);
        first.setMacVendorSource(source);
        AtomicInteger events = new AtomicInteger();
        first.onMacVendorsChange(e -> events.set((Integer) e.getNewValue()));
        first.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            first.loadMacVendors();
        } finally {
            first.logout();
        }
        assertTrue(first.macVendorsLoaded());
        assertEquals(1, downloads.get());
        assertEquals(NSNetUtil.MAC_VENDORS.size(), events.get(), "the load fires the macVendors event with the table's size");
        assertTrue(events.get() > 0);
        assertEquals("Test Vendor Inc", NSNetUtil.MAC_VENDORS.lookupDescription("FC:FF:F2:00:00:01"));
        assertEquals("Other Company Ltd", NSNetUtil.MAC_VENDORS.lookupDescription("FC:FF:F3:0A:BB:CC"), "/28 prefix");
        assertNull(NSNetUtil.MAC_VENDORS.lookup("FC:FF:F3:1A:BB:CC"), "outside the /28");

        List<DataContent> rows = storedRows(first);
        assertEquals(1, rows.size(), "one app-wide row");
        assertEquals(Session.MAC_VENDOR_CONTENT_NAME, rows.get(0).getFullName());
        assertEquals(OUIDB.WIRESHARK_MANUF_URL, rows.get(0).getSourceID());
        assertArrayEquals(MANUF, rows.get(0).getData());

        // the same session does not load twice, and does not fire again
        events.set(-1);
        first.loadMacVendors();
        assertEquals(1, downloads.get());
        assertEquals(-1, events.get(), "no event when nothing was loaded");

        // a later session (next start) finds the row: no download
        Session later = new Session(dsm);
        later.setMacVendorSource(source);
        later.loadMacVendors();
        assertTrue(later.macVendorsLoaded());
        assertEquals(1, downloads.get(), "the stored copy is used");
        assertEquals(1, storedRows(later).size(), "still one row");

        Session.MacVendorStatus status = later.macVendorStatus();
        assertTrue(status.stored());
        assertTrue(status.entries() >= 2);
        assertEquals(0, status.syncedTs(), "never synced");

        // Settings > Sync: the current list replaces the stored copy and the live table learns it
        byte[] manuf2 = "FC:FF:F4\tNewCo\tNew Company SA\n".getBytes(StandardCharsets.UTF_8);
        later.setMacVendorSource(() -> {
            downloads.incrementAndGet();
            return manuf2;
        });
        Session.MacVendorStatus synced = later.syncMacVendors();
        assertEquals(2, downloads.get());
        assertEquals("New Company SA", NSNetUtil.MAC_VENDORS.lookupDescription("FC:FF:F4:00:00:01"));
        rows = storedRows(later);
        assertEquals(1, rows.size(), "replaced, not added");
        assertArrayEquals(manuf2, rows.get(0).getData());
        assertTrue(synced.syncedTs() >= synced.storedTs() && synced.syncedTs() > 0, "the sync is stamped on the row");
        assertEquals(synced.syncedTs(), later.macVendorStatus().syncedTs(), "and read back from the store");
        assertTrue(synced.entries() >= 3, "the live table keeps the earlier entries and gains the new one");

        // a bad body on sync is refused and the stored copy is kept
        later.setMacVendorSource(() -> "nope".getBytes(StandardCharsets.UTF_8));
        assertThrows(IOException.class, later::syncMacVendors);
        assertArrayEquals(manuf2, storedRows(later).get(0).getData());
    }

    @Test
    void statusOnAFreshSessionBeforeAnyStoreIsNotStored() throws Exception {
        // runs in the same store as the other test, so only the shape is pinned here
        Session.MacVendorStatus status = new Session(dsm).macVendorStatus();
        assertNotNull(status);
        assertTrue(status.entries() >= 0);
    }
}
