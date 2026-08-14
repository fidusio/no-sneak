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
}