package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.net.util.NSNetUtil;
import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.net.OUIVendor;
import org.zoxweb.shared.util.NVGenericMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The host JSON names the MAC's vendor from {@link NSNetUtil#MAC_VENDORS} (2026-10-25): the full
 * vendor name (the manuf description, not the 8-char short name), only when the table knows the
 * prefix, and the synthetic "locally administered" entry for a randomized address. The table is
 * process-wide and never emptied, so the test seeds a prefix real registries do not use.
 */
public class ScanReportMacVendorTest {

    @BeforeAll
    static void seedTable() {
        // first octet FC: U/L bit clear, so the lookup consults the table rather than answering "Local"
        NSNetUtil.MAC_VENDORS.add(new OUIVendor("FCFFF0", 24, "TestVen", "Test Vendor Inc"));
    }

    private static NVGenericMap hostJson(String mac) {
        HostReport h = new HostReport("10.0.0.9");
        h.ip = "10.0.0.9";
        h.up = true;
        h.mac = mac;
        return h.toNVGenericMap(new NMapConfig().target("10.0.0.9"));
    }

    @Test
    void knownPrefixGetsTheFullVendorName() {
        NVGenericMap m = hostJson("FC:FF:F0:12:34:56");
        assertEquals("FC:FF:F0:12:34:56", m.getValue("mac"));
        assertEquals("Test Vendor Inc", m.getValue("macVendor"), "the description, not the short name");
    }

    @Test
    void unknownPrefixKeepsTheMacOnly() {
        NVGenericMap m = hostJson("FC:FF:F1:00:00:01");
        assertEquals("FC:FF:F1:00:00:01", m.getValue("mac"));
        assertNull(m.get("macVendor"));
    }

    @Test
    void locallyAdministeredAddressIsNamedAsSuch() {
        NVGenericMap m = hostJson("02:00:00:00:00:01");
        assertEquals(OUIVendor.LOCALLY_ADMINISTERED_DESCRIPTION, m.getValue("macVendor"));
    }

    @Test
    void noMacNoVendor() {
        NVGenericMap m = hostJson(null);
        assertNull(m.get("mac"));
        assertNull(m.get("macVendor"));
    }
}
