package io.xlogistx.nosneak.nmap;

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

    // ==================== v1 grammar: per-octet ranges, comma tokens, the cap (item 11) ====================

    @Test
    public void perOctetRangesExpandInAddressOrder() {
        assertEquals(Arrays.asList("192.168.1.1", "192.168.1.2", "192.168.1.3",
                                   "192.168.2.1", "192.168.2.2", "192.168.2.3"),
                NMapScanner.expand(Collections.singletonList("192.168.1-2.1-3")));
        assertEquals(Arrays.asList("10.1.0.5", "10.2.0.5"),
                NMapScanner.expand(Collections.singletonList("10.1-2.0.5")), "any octet may be a range");
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.2"),
                NMapScanner.expand(Collections.singletonList("10.0.0.2-1")), "a reversed octet bound is normalised");
        assertEquals(Collections.singletonList("10.0.0.300-1"),
                NMapScanner.expand(Collections.singletonList("10.0.0.300-1")), "an octet past 255 is not an address");
        assertEquals(Collections.singletonList("10.0.1-2"),
                NMapScanner.expand(Collections.singletonList("10.0.1-2")), "three parts is not the grammar");
    }

    @Test
    public void commaSeparatedTargetsInsideOneToken() {
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.5", "example.com"),
                NMapScanner.expand(Collections.singletonList("10.0.0.1,10.0.0.5,example.com")));
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.2", "10.0.0.9"),
                NMapScanner.expand(Collections.singletonList("10.0.0.1-2, 10.0.0.9,,")), "blanks between commas are skipped");
        assertEquals(Arrays.asList("10.0.0.1", "10.0.0.2"),
                NMapScanner.expand(Arrays.asList("10.0.0.1,10.0.0.2", "10.0.0.2,10.0.0.1")), "still de-duplicated");
    }

    @Test
    public void expansionIsCappedWithAWarningInsteadOfSilently() {
        List<String> warnings = new java.util.ArrayList<>();
        List<String> cidr = NMapScanner.expand(Collections.singletonList("10.0.0.0/15"), warnings);
        assertEquals(NMapScanner.MAX_EXPANSION, cidr.size());
        assertEquals("10.0.0.1", cidr.get(0));
        assertEquals(Collections.singletonList("target expansion capped at 65536 addresses for '10.0.0.0/15'"), warnings);

        warnings.clear();
        List<String> octets = NMapScanner.expand(Collections.singletonList("10.0-1.0-255.0-255"), warnings);
        assertEquals(NMapScanner.MAX_EXPANSION, octets.size());
        assertEquals("10.0.0.0", octets.get(0));
        assertEquals("10.0.255.255", octets.get(octets.size() - 1), "cut short, in address order");
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).endsWith("for '10.0-1.0-255.0-255'"), warnings.get(0));

        warnings.clear();
        assertEquals(65534, NMapScanner.expand(Collections.singletonList("10.0.0.0/16"), warnings).size());
        assertTrue(warnings.isEmpty(), "a /16 fits; no warning");
        assertEquals(NMapScanner.MAX_EXPANSION,
                NMapScanner.expand(Collections.singletonList("10.0.0.0/8")).size(), "no sink: still capped, silently");
    }

    @Test
    public void ipLiteralsAreRecognisedWithoutAnyLookup() {
        assertTrue(NMapScanner.isIpLiteral("10.0.0.1"));
        assertTrue(NMapScanner.isIpLiteral(" 192.168.1.254 "));
        assertTrue(NMapScanner.isIpLiteral("::1"));
        assertTrue(NMapScanner.isIpLiteral("fe80::1%eth0"));
        assertTrue(NMapScanner.isIpLiteral("[2001:db8::1]"));
        assertFalse(NMapScanner.isIpLiteral("example.com"));
        assertFalse(NMapScanner.isIpLiteral("10.0.0"));
        assertFalse(NMapScanner.isIpLiteral("10.0.0.1-5"));
        assertFalse(NMapScanner.isIpLiteral("host:80"));
        assertFalse(NMapScanner.isIpLiteral(null));
        assertEquals("10.0.0.1", NMapScanner.literalAddress("10.0.0.1").getHostAddress());
        assertEquals(null, NMapScanner.literalAddress("example.com"), "a name is never resolved here");
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
        // merged from the v1 ServiceMatch table (item 17): the two entries v2 lacked
        assertEquals("oracle", WellKnownPorts.name(1521, "tcp"));
        assertEquals("route", WellKnownPorts.name(520, "udp"));
        assertEquals("unknown", WellKnownPorts.name(520, "tcp"), "transport-aware: route is UDP only");
        // the null-returning form the probe engine's fallback label uses
        assertEquals(null, WellKnownPorts.lookup(64999, "tcp"));
        assertEquals("domain", WellKnownPorts.lookup(53, "udp"));
        assertEquals("http", WellKnownPorts.lookup(80, null), "no protocol reads as TCP");
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

    /**
     * The probe stage visits every potentially-open TCP port but only a UDP port that answered:
     * an open|filtered UDP port is one nobody spoke to, and probing it costs a timeout per probe
     * for no evidence.
     */
    @Test
    public void udpPortsAreProbedOnlyWhenTheyAnswered() {
        ScanReport.PortReport tcpOpen = new ScanReport.PortReport(22, PortState.OPEN);
        ScanReport.PortReport tcpOpenFiltered = new ScanReport.PortReport(23, PortState.OPEN_FILTERED);
        ScanReport.PortReport tcpClosed = new ScanReport.PortReport(24, PortState.CLOSED);
        ScanReport.PortReport udpOpen = new ScanReport.PortReport(53, PortState.OPEN);
        udpOpen.protocol = "udp";
        ScanReport.PortReport udpSilent = new ScanReport.PortReport(123, PortState.OPEN_FILTERED);
        udpSilent.protocol = "udp";
        ScanReport.PortReport udpClosed = new ScanReport.PortReport(161, PortState.CLOSED);
        udpClosed.protocol = "udp";

        assertTrue(NMapScanner.probeable(tcpOpen));
        assertTrue(NMapScanner.probeable(tcpOpenFiltered));
        assertFalse(NMapScanner.probeable(tcpClosed));
        assertTrue(NMapScanner.probeable(udpOpen));
        assertFalse(NMapScanner.probeable(udpSilent));
        assertFalse(NMapScanner.probeable(udpClosed));
        assertEquals("domain", udpOpen.serviceName(), "the well-known name is looked up per protocol");
    }

    private static void assertArrayEquals(int[] expected, int[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual,
                "expected " + Arrays.toString(expected) + " but was " + Arrays.toString(actual));
    }
}
