package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.scan.ProbeSelection;
import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.data.ProbeGroup;
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
 * Pins the scanner card's pure rules ({@link ProbeSelection}): ticks become
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

    private static List<ProbeDefinition> bundledNamed(String... names) {
        List<String> wanted = List.of(names);
        return ProbeDefinitionLoader.loadBundled().stream().filter(d -> wanted.contains(d.getName())).toList();
    }

    /**
     * 2026-10-31, maintainer: with no ports typed the scan covers the ticked probes' declared
     * ports; the Ports field's placeholder names them in the field's own grammar.
     */
    @Test
    void thePortsPlaceholderNamesTheTickedProbesPorts() {
        assertEquals("22,443,2222,8443 (ticked probes)",
                ProbeSelection.portsPlaceholder(bundledNamed("ssh", "https-pqc")));
        assertEquals("U:53 (ticked probes)",
                ProbeSelection.portsPlaceholder(bundledNamed("dns")), "a UDP probe's ports in the U: half");
        assertEquals("22,2222,U:53 (ticked probes)",
                ProbeSelection.portsPlaceholder(bundledNamed("ssh", "dns")));
        assertEquals(io.xlogistx.nosneak.app.ui.scan.ScanFormPanel.PORTS_DEFAULT_HINT,
                ProbeSelection.portsPlaceholder(List.of()), "no chip: the engine's default list");
        assertEquals(io.xlogistx.nosneak.app.ui.scan.ScanFormPanel.PORTS_DEFAULT_HINT,
                ProbeSelection.portsPlaceholder(bundledNamed("tls-scan")), "tls-scan declares no port");
        assertEquals("6379 (ticked probes)",
                ProbeSelection.portsPlaceholder(bundled("my-redis")), "a stored probe counts the same");
    }

    @Test
    void aProbeNameWithSpacesNeverBecomesAScanTarget() {
        String typed = "10.0.0.0/24 -p 6379";
        NMapConfig cfg = NMap.parseCommand(typed);
        ProbeContent redis = stored("g1", "Redis TLS handshake");
        Set<String> ticks = Set.of(ProbeSelection.storedKey(redis));

        ProbeSelection.Selection sel =
                ProbeSelection.select(bundled("ssh"), List.of(redis), ticks);
        ProbeSelection.applyTo(cfg, sel);

        assertEquals(List.of("10.0.0.0/24"), cfg.targets, "the words of the name are not targets");
        assertTrue(cfg.probeScan, "ticking implies -sV");
        assertEquals(List.of("Redis TLS handshake"), cfg.probeNames);
        assertEquals(1, cfg.extraProbes.size());
        assertEquals("Redis TLS handshake", cfg.extraProbes.get(0).getName());
        assertEquals("Redis TLS handshake", ProbeSelection.describe(sel));
    }

    /**
     * 2026-10-26, maintainer: no ticked probe means no probing at all, even when the command
     * carries {@code -sV} or {@code --probes} — a bare {@code -sV} would otherwise run the whole
     * catalog. The user picks a set, or all.
     */
    @Test
    void noTicksMeanNoProbingWhateverTheCommandSays() {
        for (String typed : new String[]{"10.0.0.1", "10.0.0.1 -sV", "10.0.0.1 -sV --probes ssh"}) {
            NMapConfig cfg = NMap.parseCommand(typed);
            ProbeSelection.Selection sel =
                    ProbeSelection.select(bundled("ssh"), List.of(stored("g1", "x")), Set.of());
            ProbeSelection.applyTo(cfg, sel);

            assertFalse(cfg.probeScan, typed);
            assertTrue(cfg.probeNames.isEmpty(), typed);
            assertTrue(cfg.extraProbes.isEmpty(), typed);
            assertEquals("", ProbeSelection.describe(sel));
        }
    }

    @Test
    void allTickedNamesEveryProbe() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        ProbeContent mine = stored("g1", "mine");
        Set<String> all = Set.of(ProbeSelection.bundledKey("ssh"), ProbeSelection.bundledKey("http"),
                ProbeSelection.storedKey(mine));
        ProbeSelection.Selection sel =
                ProbeSelection.select(bundled("ssh", "http"), List.of(mine), all);
        ProbeSelection.applyTo(cfg, sel);

        assertTrue(cfg.probeScan);
        assertEquals(Set.of("ssh", "http", "mine"), Set.copyOf(cfg.probeNames));
        assertEquals(1, cfg.extraProbes.size());
    }

    @Test
    void aStoredProbeSharingABundledNameHasItsOwnTick() {
        List<ProbeDefinition> bundled = bundled("ssh", "http");
        ProbeContent mine = stored("g7", "ssh");

        // Ticking the stored one selects only the stored one...
        Set<String> ticks = new HashSet<>(Set.of(ProbeSelection.storedKey(mine)));
        ProbeSelection.Selection sel = ProbeSelection.select(bundled, List.of(mine), ticks);
        assertTrue(sel.bundledNames().isEmpty());
        assertEquals(1, sel.stored().size());

        // ...and ticking every bundled box does not pull the stored one in.
        ticks.clear();
        for (ProbeDefinition d : bundled) ticks.add(ProbeSelection.bundledKey(d.getName()));
        sel = ProbeSelection.select(bundled, List.of(mine), ticks);
        assertEquals(List.of("ssh", "http"), sel.bundledNames());
        assertTrue(sel.stored().isEmpty());
    }

    @Test
    void anInvalidStoredProbeIsNamedInTheError() {
        ProbeContent broken = stored("g2", "broken");
        broken.setContent("{\"name\":\"broken\",\"start\":\"nowhere\",\"states\":{}}");
        Set<String> ticks = Set.of(ProbeSelection.storedKey(broken));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProbeSelection.select(List.of(), List.of(broken), ticks));
        assertTrue(e.getMessage().contains("broken"), e.getMessage());
    }

    @Test
    void reSavingADefinitionFindsTheRowItReplaces() {
        ProbeContent a = stored("g1", "alpha");
        ProbeContent b = stored("g2", "beta");
        assertSame(b, ProbeSelection.existingByName(List.of(a, b), "beta"));
        assertNull(ProbeSelection.existingByName(List.of(a, b), "gamma"));
        assertNull(ProbeSelection.existingByName(List.of(a, b), null));
        assertNull(ProbeSelection.existingByName(List.of(stored(null, "unsaved")), "unsaved"),
                "a row that was never saved cannot be updated in place");
    }

    @Test
    void theTimeoutMessageSaysTimedOutAndNamesTheTargets() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.0/24 10.0.1.5 -sV");
        String msg = ProbeSelection.timeoutMessage(cfg, 61_500);
        assertTrue(msg.startsWith("Scan timed out after 62 s: 10.0.0.0/24 10.0.1.5"), msg);
        assertFalse(msg.contains("Unexpected"), msg);
        assertNotNull(msg);
    }

    /** Scan again (2026-10-25): a report's saved probe names become ticks against what exists now. */
    @Test
    void aStoredReportsProbeNamesBecomeTicksAgain() {
        ProbeContent mine = stored("g1", "Redis TLS handshake");
        Set<String> keys = ProbeSelection.keysForNames("ssh, Redis TLS handshake, deleted-since",
                bundled("ssh"), List.of(mine));
        assertEquals(Set.of("b:ssh", "s:g1"), keys, "bundled by name, stored by name, unknown dropped");
        assertTrue(ProbeSelection.keysForNames(null, bundled("ssh"), List.of()).isEmpty());
        assertTrue(ProbeSelection.keysForNames("  ", bundled("ssh"), List.of()).isEmpty());
    }

    /**
     * Probe groups (2026-11-01): a group is a convenience over the ticks. Ticking one adds
     * exactly its members' keys, the run then names exactly those probes (the group itself
     * never reaches the config), and unticking it leaves the other ticks alone.
     */
    @Test
    void aGroupTicksItsProbesAndNothingElseReachesTheEngine() {
        ProbeContent mine = stored("g1", "Redis TLS handshake");
        List<ProbeDefinition> bundled = bundled("ssh", "http");
        ProbeGroup web = new ProbeGroup();
        web.setName("web");
        web.setProbes("http, Redis TLS handshake, deleted-since");
        Set<String> members = io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel.memberKeys(web, bundled, List.of(mine));
        assertEquals(Set.of("b:http", "s:g1"), members, "the missing member resolves to nothing");

        Set<String> ticks = new HashSet<>(Set.of("b:ssh"));
        io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel.applyTick(ticks, members, true);
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        ProbeSelection.Selection sel = ProbeSelection.select(bundled, List.of(mine), ticks);
        ProbeSelection.applyTo(cfg, sel);
        assertTrue(cfg.probeScan);
        assertEquals(Set.of("ssh", "http", "Redis TLS handshake"), Set.copyOf(cfg.probeNames), "the probes, never the group");
        assertEquals("ssh, http, Redis TLS handshake", ProbeSelection.describe(sel), "what the report records");

        io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel.applyTick(ticks, members, false);
        assertEquals(Set.of("b:ssh"), ticks, "unticking the group leaves the earlier tick");
        // and Save ticked as group would store exactly the live names, in catalog order
        assertEquals("ssh", io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel.csvFromTicks(ticks, bundled, List.of(mine)));
    }

    @Test
    void keysAreDistinctPerKind() {
        ProbeContent mine = stored("g1", "ssh");
        assertEquals("b:ssh", ProbeSelection.bundledKey("ssh"));
        assertEquals("s:g1", ProbeSelection.storedKey(mine));
        assertEquals("s:name:draft", ProbeSelection.storedKey(stored(null, "draft")));
    }
}
