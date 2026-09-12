package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.nmap.NMap;
import io.xlogistx.nosneak.nmap.NMapConfig;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the scanner card's pure rules ({@link ScanPanel.ProbeSelection}): ticks become
 * {@code NMapConfig} state and never touch the command string, ticks are keyed by identity,
 * a re-saved probe replaces its row, and a timeout reads as a timeout. No Swing, no store.
 */
class ScanPanelTest {

    /** A minimal valid definition — connect, then done — under the given name. */
    private static String json(String name) {
        return "{\"name\":\"" + name + "\",\"service\":\"redis\",\"ports\":[6379],"
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeContent stored(String guid, String name) {
        ProbeContent p = new ProbeContent();
        if (guid != null) p.setGUID(guid);
        p.setName(name);
        p.setContent(json(name));
        return p;
    }

    private static List<ProbeDefinition> bundled(String... names) {
        return java.util.Arrays.stream(names).map(n -> ProbeDefinitionLoader.parse(json(n), n)).toList();
    }

    @Test
    void aProbeNameWithSpacesNeverBecomesAScanTarget() {
        String typed = "10.0.0.0/24 -p 6379";
        NMapConfig cfg = NMap.parseCommand(typed);
        ProbeContent redis = stored("g1", "Redis TLS handshake");
        Set<String> ticks = Set.of(ScanPanel.ProbeSelection.storedKey(redis));

        ScanPanel.ProbeSelection.Selection sel =
                ScanPanel.ProbeSelection.select(bundled("ssh"), List.of(redis), ticks);
        ScanPanel.ProbeSelection.applyTo(cfg, sel);

        assertEquals(List.of("10.0.0.0/24"), cfg.targets, "the words of the name are not targets");
        assertTrue(cfg.probeScan, "ticking implies -sV");
        assertEquals(List.of("Redis TLS handshake"), cfg.probeNames);
        assertEquals(1, cfg.extraProbes.size());
        assertEquals("Redis TLS handshake", cfg.extraProbes.get(0).getName());
        assertEquals("Redis TLS handshake", ScanPanel.ProbeSelection.describe(sel));
    }

    @Test
    void noTicksLeaveTheConfigUntouched() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        ScanPanel.ProbeSelection.Selection sel =
                ScanPanel.ProbeSelection.select(bundled("ssh"), List.of(stored("g1", "x")), Set.of());
        ScanPanel.ProbeSelection.applyTo(cfg, sel);

        assertFalse(cfg.probeScan);
        assertTrue(cfg.probeNames.isEmpty());
        assertTrue(cfg.extraProbes.isEmpty());
        assertEquals("", ScanPanel.ProbeSelection.describe(sel));
    }

    @Test
    void aStoredProbeSharingABundledNameHasItsOwnTick() {
        List<ProbeDefinition> bundled = bundled("ssh", "http");
        ProbeContent mine = stored("g7", "ssh");

        // Ticking the stored one selects only the stored one...
        Set<String> ticks = new HashSet<>(Set.of(ScanPanel.ProbeSelection.storedKey(mine)));
        ScanPanel.ProbeSelection.Selection sel = ScanPanel.ProbeSelection.select(bundled, List.of(mine), ticks);
        assertTrue(sel.bundledNames().isEmpty());
        assertEquals(1, sel.stored().size());

        // ...and ticking every bundled box does not pull the stored one in.
        ticks.clear();
        for (ProbeDefinition d : bundled) ticks.add(ScanPanel.ProbeSelection.bundledKey(d.getName()));
        sel = ScanPanel.ProbeSelection.select(bundled, List.of(mine), ticks);
        assertEquals(List.of("ssh", "http"), sel.bundledNames());
        assertTrue(sel.stored().isEmpty());
    }

    @Test
    void anInvalidStoredProbeIsNamedInTheError() {
        ProbeContent broken = stored("g2", "broken");
        broken.setContent("{\"name\":\"broken\",\"start\":\"nowhere\",\"states\":{}}");
        Set<String> ticks = Set.of(ScanPanel.ProbeSelection.storedKey(broken));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ScanPanel.ProbeSelection.select(List.of(), List.of(broken), ticks));
        assertTrue(e.getMessage().contains("broken"), e.getMessage());
    }

    @Test
    void reSavingADefinitionFindsTheRowItReplaces() {
        ProbeContent a = stored("g1", "alpha");
        ProbeContent b = stored("g2", "beta");
        assertSame(b, ScanPanel.ProbeSelection.existingByName(List.of(a, b), "beta"));
        assertNull(ScanPanel.ProbeSelection.existingByName(List.of(a, b), "gamma"));
        assertNull(ScanPanel.ProbeSelection.existingByName(List.of(a, b), null));
        assertNull(ScanPanel.ProbeSelection.existingByName(List.of(stored(null, "unsaved")), "unsaved"),
                "a row that was never saved cannot be updated in place");
    }

    @Test
    void theTimeoutMessageSaysTimedOutAndNamesTheTargets() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.0/24 10.0.1.5 -sV");
        String msg = ScanPanel.ProbeSelection.timeoutMessage(cfg, 61_500);
        assertTrue(msg.startsWith("Scan timed out after 62 s: 10.0.0.0/24 10.0.1.5"), msg);
        assertFalse(msg.contains("Unexpected"), msg);
        assertNotNull(msg);
    }

    @Test
    void keysAreDistinctPerKind() {
        ProbeContent mine = stored("g1", "ssh");
        assertEquals("b:ssh", ScanPanel.ProbeSelection.bundledKey("ssh"));
        assertEquals("s:g1", ScanPanel.ProbeSelection.storedKey(mine));
        assertEquals("s:name:draft", ScanPanel.ProbeSelection.storedKey(stored(null, "draft")));
    }
}
