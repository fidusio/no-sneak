package io.xlogistx.nosneak.nmap;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@link NMap#formatCommand} is the inverse of {@link NMap#parseCommand} for everything the
 * scanner's form can express: parsing what it prints gives the same configuration back, and a
 * canonical command prints in a fixed, readable order.
 */
public class NMapFormatCommandTest {

    private static final List<String> COMMANDS = List.of(
            "10.0.0.0/24",
            "10.0.0.1 -p 22,80,443 -sV -T4",
            "10.0.0.0/24 -p 1-1024 -sV -T5 --min-rtt-timeout 200 --max-inflight 4096 --up-only --open",
            "192.168.50.0/24 -sn -PR --up-only",
            "mail.example.com -p 25,465,587,993,995 -sV --probes TLS-handshake,smtp",
            "example.com 10.0.0.5 -p 1-100,443,8000-8010 -Pn -n",
            "10.0.0.1 -sU",
            "10.0.0.1 -p 22,U:53,161 -sU -R --dns-servers 1.1.1.1 -v",
            "10.0.0.1 --no-icmp --icmp-probes 4 -t 9 --max-rate 500",
            "10.0.0.1 -PE --open"
    );

    @Test
    public void parsingWhatItPrintsGivesTheSameConfig() {
        for (String command : COMMANDS) {
            NMapConfig first = NMap.parseCommand(command);
            String printed = NMap.formatCommand(first);
            NMapConfig second = NMap.parseCommand(printed);
            assertSameConfig(command + "  →  " + printed, first, second);
            // and printing is stable: a second round gives the same text
            assertEquals(printed, NMap.formatCommand(second), command);
        }
    }

    @Test
    public void canonicalOrderAndDefaultsOmitted() {
        assertEquals("10.0.0.1 -p 22,80,443 -sV -T4", NMap.formatCommand(NMap.parseCommand("10.0.0.1 -T4 -sV -p 22,80,443")));
        assertEquals("10.0.0.0/24", NMap.formatCommand(NMap.parseCommand("10.0.0.0/24 -T3")), "T3 is the default and is not printed");
        assertEquals("10.0.0.0/24 -sn", NMap.formatCommand(NMap.parseCommand("10.0.0.0/24 -sn")));
        assertEquals("10.0.0.1 -p 1-1024,8080", NMap.formatCommand(NMap.parseCommand("10.0.0.1 -p 1-1024,8080")), "ranges are compressed back");
        assertEquals("10.0.0.1 -p 1-5", NMap.formatCommand(NMap.parseCommand("10.0.0.1 -p 1,2,3,4,5")));
        assertEquals("10.0.0.1 -p 22,U:53,161 -sU", NMap.formatCommand(NMap.parseCommand("10.0.0.1 -p T:22,U:53,161 -sU")));
        assertEquals("10.0.0.1 -sU", NMap.formatCommand(NMap.parseCommand("10.0.0.1 -sU")), "the default UDP list is not printed");
        assertEquals("10.0.0.1 -T5 --max-inflight 4096",
                NMap.formatCommand(NMap.parseCommand("10.0.0.1 -T5 --max-inflight 4096")),
                "a timing template overridden on one knob prints as the template plus that knob");
        assertEquals("10.0.0.1 --max-rate 500 -t 9",
                NMap.formatCommand(NMap.parseCommand("10.0.0.1 --max-rate 500 -t 9")),
                "knobs off the defaults print without a template");
    }

    @Test
    public void probeNamesThatCannotRoundTripAreLeftOut() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1 -sV");
        cfg.probe("Redis TLS handshake"); // the panel applies such names to the config, never to the string
        cfg.probe("tls-handshake");
        assertEquals("10.0.0.1 -sV --probes tls-handshake", NMap.formatCommand(cfg));
    }

    @Test
    public void portSpecHelper() {
        assertEquals("", NMap.portSpec(new int[0], new int[0]));
        assertEquals("22", NMap.portSpec(new int[]{22}, null));
        assertEquals("1-3,7,9-10", NMap.portSpec(new int[]{1, 2, 3, 7, 9, 10}, null));
        assertEquals("U:53", NMap.portSpec(null, new int[]{53}));
        assertEquals("80,U:53,161-162", NMap.portSpec(new int[]{80}, new int[]{53, 161, 162}));
        assertNull(NMapConfig.Timing.matching(NMap.parseCommand("10.0.0.1 -T5 --max-inflight 4096")));
        assertEquals(NMapConfig.Timing.T5, NMapConfig.Timing.closest(NMap.parseCommand("10.0.0.1 -T5 --max-inflight 4096")));
        assertEquals(NMapConfig.Timing.T5, NMapConfig.Timing.matching(NMap.parseCommand("10.0.0.1 -T5")));
        assertEquals(NMapConfig.Timing.T3, NMapConfig.Timing.matching(new NMapConfig()));
        assertEquals(NMapConfig.Timing.T3, NMapConfig.Timing.closest(NMap.parseCommand("10.0.0.1 --max-rate 500 -t 9")));
    }

    static void assertSameConfig(String label, NMapConfig a, NMapConfig b) {
        assertEquals(a.targets, b.targets, label + " targets");
        assertArrayEquals(a.ports, b.ports, label + " ports");
        assertArrayEquals(a.udpPorts, b.udpPorts, label + " udpPorts " + Arrays.toString(a.udpPorts) + " vs " + Arrays.toString(b.udpPorts));
        assertEquals(a.udpScan, b.udpScan, label + " udpScan");
        assertEquals(a.openOnly, b.openOnly, label + " openOnly");
        assertEquals(a.upOnly, b.upOnly, label + " upOnly");
        assertEquals(a.discovery, b.discovery, label + " discovery");
        assertEquals(a.discoveryTcp, b.discoveryTcp, label + " discoveryTcp");
        assertEquals(a.discoveryIcmp, b.discoveryIcmp, label + " discoveryIcmp");
        assertEquals(a.discoveryArp, b.discoveryArp, label + " discoveryArp");
        assertEquals(a.icmpProbes, b.icmpProbes, label + " icmpProbes");
        assertEquals(a.probeScan, b.probeScan, label + " probeScan");
        assertEquals(a.probeNames, b.probeNames, label + " probeNames");
        assertEquals(a.maxInFlight, b.maxInFlight, label + " maxInFlight");
        assertEquals(a.maxPerSec, b.maxPerSec, label + " maxPerSec");
        assertEquals(a.timeoutSec, b.timeoutSec, label + " timeoutSec");
        assertEquals(a.minRttTimeoutMs, b.minRttTimeoutMs, label + " minRttTimeoutMs");
        assertEquals(a.verbose, b.verbose, label + " verbose");
        assertEquals(a.reverseDns, b.reverseDns, label + " reverseDns");
        assertEquals(a.dnsServer, b.dnsServer, label + " dnsServer");
    }
}
