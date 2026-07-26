package io.xlogistx.nosneak.v2.nmap;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure tests for the scanner's target expansion and port-spec parsing — the two places where a
 * silent off-by-one scans the wrong hosts or quietly scans nothing at all.
 */
public class NMapScannerTest {

    @Test
    public void hostnamesAndSingleIpsPassThrough() {
        List<String> out = NMapScanner.expand(Arrays.asList("example.com", "10.0.0.5"));
        assertEquals(Arrays.asList("example.com", "10.0.0.5"), out);
    }

    @Test
    public void cidrExpandsToUsableHostsOnly() {
        // /30 => network .0, usable .1-.2, broadcast .3
        assertEquals(Arrays.asList("192.168.1.1", "192.168.1.2"),
                NMapScanner.expand(Collections.singletonList("192.168.1.0/30")));
    }

    @Test
    public void cidrOf31And32IncludeEveryAddress() {
        // A /31 (point-to-point) and /32 (single host) have no network/broadcast to skip.
        assertEquals(Arrays.asList("10.0.0.0", "10.0.0.1"),
                NMapScanner.expand(Collections.singletonList("10.0.0.0/31")));
        assertEquals(Collections.singletonList("10.0.0.7"),
                NMapScanner.expand(Collections.singletonList("10.0.0.7/32")));
    }

    @Test
    public void cidr24YieldsTheExpectedCount() {
        List<String> out = NMapScanner.expand(Collections.singletonList("172.16.5.0/24"));
        assertEquals(254, out.size());
        assertEquals("172.16.5.1", out.get(0));
        assertEquals("172.16.5.254", out.get(out.size() - 1));
    }

    @Test
    public void lastOctetRangeExpands() {
        assertEquals(Arrays.asList("10.0.0.5", "10.0.0.6", "10.0.0.7"),
                NMapScanner.expand(Collections.singletonList("10.0.0.5-7")));
    }

    @Test
    public void fullAddressRangeExpandsAcrossOctets() {
        List<String> out = NMapScanner.expand(Collections.singletonList("10.0.0.254-10.0.1.1"));
        assertEquals(Arrays.asList("10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"), out);
    }

    @Test
    public void reversedRangeIsNormalised() {
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.2", "10.0.0.3"),
                NMapScanner.expand(Collections.singletonList("10.0.0.3-1")));
    }

    @Test
    public void duplicatesAreCollapsedAndOrderPreserved() {
        List<String> out = NMapScanner.expand(Arrays.asList("10.0.0.1", "10.0.0.1-2", "10.0.0.1"));
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.2"), out);
    }

    @Test
    public void blanksAndNullsAreIgnored() {
        assertTrue(NMapScanner.expand(Arrays.asList("", "   ", null)).isEmpty());
        assertTrue(NMapScanner.expand(null).isEmpty());
    }

    /** A malformed CIDR must not silently expand to a huge sweep — it stays a literal token. */
    @Test
    public void malformedSpecsAreTreatedAsLiteralTargets() {
        assertEquals(Collections.singletonList("10.0.0.0/99"),
                NMapScanner.expand(Collections.singletonList("10.0.0.0/99")));
        assertEquals(Collections.singletonList("999.1.1.1/24"),
                NMapScanner.expand(Collections.singletonList("999.1.1.1/24")));
        assertEquals(Collections.singletonList("host-with-dash"),
                NMapScanner.expand(Collections.singletonList("host-with-dash")));
    }

    // ==================== Port specs ====================

    @Test
    public void portListAndRangeParse() {
        assertArrayEquals(new int[]{22, 80, 443}, NMap.parsePorts("22,80,443"));
        assertArrayEquals(new int[]{78, 79, 80}, NMap.parsePorts("78-80"));
        assertArrayEquals(new int[]{22, 80, 81, 443}, NMap.parsePorts("22,80-81,443"));
    }

    @Test
    public void emptyPortSpecFallsBackToDefaults() {
        assertArrayEquals(NMap.DEFAULT_PORTS, NMap.parsePorts(null));
        assertArrayEquals(NMap.DEFAULT_PORTS, NMap.parsePorts(""));
    }

    @Test
    public void outOfRangePortsAreDropped() {
        assertEquals(0, NMap.parsePorts("0").length);
        assertEquals(0, NMap.parsePorts("70000").length);
        assertArrayEquals(new int[]{65535}, NMap.parsePorts("65535"));
    }

    @Test
    public void reversedPortRangeIsNormalised() {
        assertArrayEquals(new int[]{80, 81, 82}, NMap.parsePorts("82-80"));
    }

    // ==================== Well-known port table ====================

    @Test
    public void wellKnownNamesResolvePerProtocol() {
        assertEquals("https", WellKnownPorts.name(443, "tcp"));
        assertEquals("domain", WellKnownPorts.name(53, "udp"));
        assertEquals("unknown", WellKnownPorts.name(64999, "tcp"));
    }

    @Test
    public void topPortsSliceIsBounded() {
        assertEquals(10, WellKnownPorts.topTcp(10).length);
        assertEquals(WellKnownPorts.TOP_100_TCP.length, WellKnownPorts.topTcp(1000).length,
                "asking for more than the table holds must clamp, not overflow");
        assertEquals(0, WellKnownPorts.topTcp(-1).length);
        assertEquals(WellKnownPorts.TOP_20_UDP.length, WellKnownPorts.topUdp(999).length);
    }

    // ==================== Port state semantics ====================

    @Test
    public void onlyOpenishStatesAreProbed() {
        assertTrue(PortState.OPEN.isPotentiallyOpen());
        assertTrue(PortState.OPEN_FILTERED.isPotentiallyOpen());
        assertTrue(PortState.UNFILTERED.isPotentiallyOpen());
        assertFalse(PortState.CLOSED.isPotentiallyOpen());
        assertFalse(PortState.FILTERED.isPotentiallyOpen());
        assertTrue(PortState.OPEN.isOpen());
        assertFalse(PortState.OPEN_FILTERED.isOpen());
    }

    @Test
    public void openPortsSelectionFeedsTheProbeStage() {
        ScanReport.HostReport h = new ScanReport.HostReport("host");
        h.ports.add(new ScanReport.PortReport(22, PortState.OPEN));
        h.ports.add(new ScanReport.PortReport(23, PortState.CLOSED));
        h.ports.add(new ScanReport.PortReport(53, PortState.OPEN_FILTERED));
        assertEquals(2, h.openPorts().size());
        assertEquals(1, h.countState(PortState.CLOSED));
    }

    /** With no probe identification the report falls back to the well-known service name. */
    @Test
    public void portReportFallsBackToTheWellKnownName() {
        assertEquals("https", new ScanReport.PortReport(443, PortState.OPEN).serviceName());
    }

    private static void assertArrayEquals(int[] expected, int[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual,
                "expected " + Arrays.toString(expected) + " but was " + Arrays.toString(actual));
    }
}
