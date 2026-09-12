package io.xlogistx.nosneak.v2.nmap;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.xlogistx.nosneak.v2.nmap.output.OutputFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NMapParseCommandTest {

    @Test
    public void bareTargetIsTheOnlyTarget() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.0/24");
        assertEquals(List.of("10.0.0.0/24"), cfg.targets);
        assertFalse(cfg.probeScan);
    }

    @Test
    public void flagsAreParsedNotTreatedAsTargets() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -p 22,80,443 -sV -t 9");
        assertEquals(List.of("10.0.0.1"), cfg.targets);
        assertArrayEquals(new int[]{22, 80, 443}, cfg.ports);
        assertTrue(cfg.probeScan);
        assertEquals(9, cfg.timeoutSec);
    }

    @Test
    public void severalTargetsAccumulate() {
        NMapConfig cfg = NMap.parseCommand("example.com 10.0.0.5   10.0.0.6");
        assertEquals(Arrays.asList("example.com", "10.0.0.5", "10.0.0.6"), cfg.targets);
    }

    @Test
    public void discoveryOnlyClearsPorts() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.0/24 -sn");
        assertEquals(0, cfg.ports.length);
    }

    @Test
    public void discoveryFlagsToggleIndividually() {
        NMapConfig arpOnly = NMap.parseCommand("10.0.0.0/24 -PR");
        assertTrue(arpOnly.discoveryArp);
        assertFalse(arpOnly.discoveryIcmp);
        assertFalse(arpOnly.discoveryTcp);
    }

    @Test
    public void blankCommandIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand(""));
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("   "));
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand(null));
    }

    @Test
    public void flagsWithoutATargetAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("-sV -p 443"));
    }

    @Test
    public void unknownOptionIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -zz"));
    }

    @Test
    public void missingFlagValueIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -p"));
    }

    @Test
    public void nonNumericPortIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -p http"));
    }

    @Test
    public void outputFileOptionsAreRejectedForACommandString() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -oJ out.json"));
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -oA base"));
    }

    @Test
    public void outputFileOptionsAreCollectedForTheCli() {
        Map<OutputFormat, String> outputs = new LinkedHashMap<>();
        NMapConfig cfg = NMap.parseArgs(outputs, "10.0.0.1", "-oJ", "out.json");
        assertEquals(List.of("10.0.0.1"), cfg.targets);
        assertEquals("out.json", outputs.get(OutputFormat.JSON));
    }

    @Test
    public void maxWaitGrowsWithTheTargetCount() {
        long one = NMap.maxWaitMs(NMap.parseCommand("10.0.0.1"));
        long many = NMap.maxWaitMs(NMap.parseCommand("10.0.0.0/24"));
        assertTrue(many > one, "a /24 must get a longer budget than a single host");
    }

    // ==================== Bounded defaults (matrix row 13) ====================

    @Test
    public void defaultsAreBoundedNotUnlimited() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        assertEquals(256, cfg.maxInFlight, "must match SweepOptions.defaults()");
        assertEquals(2000, cfg.maxPerSec, "must match SweepOptions.defaults()");
        assertEquals(5, cfg.timeoutSec);
        assertEquals(NMapConfig.DEFAULT_MAX_IN_FLIGHT, new NMapConfig().maxInFlight);
        assertEquals(NMapConfig.DEFAULT_MAX_PER_SEC, new NMapConfig().maxPerSec);
    }

    @Test
    public void explicitZeroStillMeansUnlimited() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 --max-inflight 0 --max-rate 0");
        assertEquals(0, cfg.maxInFlight);
        assertEquals(0, cfg.maxPerSec);
    }

    // ==================== Port-spec parity (matrix row 17) ====================

    @Test
    public void topPortsWiresTheWellKnownTable() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 --top-ports 10");
        assertArrayEquals(WellKnownPorts.topTcp(10), cfg.ports);
        assertEquals(80, cfg.ports[0], "nmap's most common TCP port comes first");
    }

    @Test
    public void topPortsClampsToTheTableAndRejectsNonPositive() {
        assertEquals(WellKnownPorts.TOP_100_TCP.length,
                NMap.parseCommand("10.0.0.1 --top-ports 1000").ports.length);
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 --top-ports 0"));
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 --top-ports x"));
    }

    @Test
    public void protocolPrefixesSplitTcpAndUdp() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -p T:80,443,U:53,161");
        assertArrayEquals(new int[]{80, 443}, cfg.ports);
        assertArrayEquals(new int[]{53, 161}, cfg.udpPorts);

        NMap.PortSpec spec = NMap.parsePortSpec("U:53,T:22-23,u:123");
        assertArrayEquals(new int[]{22, 23}, spec.tcp());
        assertArrayEquals(new int[]{53, 123}, spec.udp(), "a prefix applies until the next one; case-insensitive");
    }

    @Test
    public void prefixlessTokensAreTcpAndUdpStaysNullWhenUnused() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -p 22,80");
        assertArrayEquals(new int[]{22, 80}, cfg.ports);
        assertEquals(null, cfg.udpPorts);
        assertArrayEquals(new int[]{22, 80}, NMap.parsePorts("T:22,80"), "the legacy accessor returns the TCP half");
    }

    @Test
    public void unknownProtocolPrefixIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NMap.parsePortSpec("X:80"));
    }

    @Test
    public void openFlagIsRecorded() {
        assertTrue(NMap.parseCommand("10.0.0.1 --open").openOnly);
        assertFalse(NMap.parseCommand("10.0.0.1").openOnly);
    }

    @Test
    public void timingTemplatesMapOntoTheThreeKnobs() {
        int[][] expected = {
                {1, 1, 15}, {4, 10, 15}, {16, 50, 10}, {256, 2000, 5}, {512, 5000, 3}, {1024, 10000, 2}};
        for (int t = 0; t <= 5; t++) {
            NMapConfig cfg = NMap.parseCommand("10.0.0.1 -T" + t);
            assertEquals(expected[t][0], cfg.maxInFlight, "-T" + t + " in-flight");
            assertEquals(expected[t][1], cfg.maxPerSec, "-T" + t + " per-second");
            assertEquals(expected[t][2], cfg.timeoutSec, "-T" + t + " timeout");
        }
        assertEquals(NMap.parseCommand("10.0.0.1").maxInFlight,
                NMap.parseCommand("10.0.0.1 -T3").maxInFlight, "T3 is the default");
    }

    @Test
    public void anExplicitKnobAfterATemplateWins() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -T5 --max-inflight 8 -t 7");
        assertEquals(8, cfg.maxInFlight);
        assertEquals(10000, cfg.maxPerSec, "untouched knob keeps the template value");
        assertEquals(7, cfg.timeoutSec);
    }

    @Test
    public void lowerCaseTimeoutFlagIsStillTheTimeout() {
        assertEquals(9, NMap.parseCommand("10.0.0.1 -t 9").timeoutSec);
        assertThrows(IllegalArgumentException.class, () -> NMap.parseCommand("10.0.0.1 -T9"));
    }

    // ==================== Raw and evasive scans are refused by name ====================

    @Test
    public void rawAndEvasiveScanFlagsAreRejectedWithAMessageThatNamesThem() {
        for (String flag : NMap.REJECTED_SCAN_FLAGS) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> NMap.parseCommand("10.0.0.1 " + flag), flag);
            assertTrue(e.getMessage().contains(flag), "message must name the flag: " + e.getMessage());
            assertTrue(e.getMessage().contains("assessment-only"), "message must say why: " + e.getMessage());
            assertFalse(e.getMessage().contains("unknown option"), "must not read like a typo");
        }
        assertTrue(NMap.REJECTED_SCAN_FLAGS.containsAll(
                List.of("-sS", "-sF", "-sX", "-sN", "-sA", "-sW", "-sM", "-O", "--stealth")));
    }

    @Test
    public void rejectionHoldsOnTheCliPathToo() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> NMap.parseArgs(new LinkedHashMap<>(), "xlogistx.io", "-sS"));
        assertTrue(e.getMessage().contains("-sS"));
    }

    @Test
    public void usageTextDocumentsTheNewFlagsAndTheRefusals() {
        String u = NMap.usageText();
        for (String s : List.of("--top-ports", "--open", "-T0..-T5", "T:/U:", "-sU", "-sS", "assessment-only")) {
            assertTrue(u.contains(s), "usage must mention " + s);
        }
    }

    // ---- UDP scan (-sU, U: ports) ----

    @Test
    public void udpScanAloneIsUdpOnlyOverTheCommonUdpPorts() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -sU");
        assertTrue(cfg.udpScan);
        assertArrayEquals(WellKnownPorts.TOP_20_UDP, cfg.udpPorts);
        assertArrayEquals(new int[0], cfg.ports, "-sU without T: ports scans no TCP port, as nmap does");
    }

    @Test
    public void udpScanWithUdpPortsUsesThoseAndStaysUdpOnly() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -sU -p U:53,123");
        assertArrayEquals(new int[]{53, 123}, cfg.udpPorts);
        assertArrayEquals(new int[0], cfg.ports);
    }

    @Test
    public void udpAndTcpTogetherWhenBothHalvesAreNamed() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -sU -p T:80,U:53");
        assertArrayEquals(new int[]{80}, cfg.ports);
        assertArrayEquals(new int[]{53}, cfg.udpPorts);

        NMapConfig top = NMap.parseCommand("10.0.0.1 -sU --top-ports 5");
        assertEquals(5, top.ports.length, "--top-ports names TCP ports, so both stacks are scanned");
        assertArrayEquals(WellKnownPorts.TOP_20_UDP, top.udpPorts);
    }

    @Test
    public void udpPortsAreScannedEvenWithoutTheFlag() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -p T:80,U:53");
        assertFalse(cfg.udpScan);
        assertArrayEquals(new int[]{53}, cfg.udpPorts, "a U: port is a request to probe it");
        assertArrayEquals(new int[]{80}, cfg.ports);
    }

    @Test
    public void discoveryOnlyClearsUdpPortsToo() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -sn -sU");
        assertArrayEquals(new int[0], cfg.ports);
        assertArrayEquals(new int[0], cfg.udpPorts);
    }

    @Test
    public void maxWaitGrowsWithUdpPorts() {
        NMapConfig tcpOnly = NMap.parseCommand("10.0.0.1 -p 80");
        NMapConfig withUdp = NMap.parseCommand("10.0.0.1 -p 80,U:53,123,161,162,500,514,520,631,1900,4500");
        assertTrue(NMap.maxWaitMs(withUdp) >= NMap.maxWaitMs(tcpOnly),
                "a silent UDP port costs a full timeout, so the budget must account for it");
    }
}