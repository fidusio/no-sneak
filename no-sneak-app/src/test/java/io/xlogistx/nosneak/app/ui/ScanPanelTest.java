package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel;
import io.xlogistx.nosneak.app.ui.scan.ProbeSelection;
import io.xlogistx.nosneak.data.ProbeType;
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
 * {@code NMapConfig} state and never touch the command string, ticks are keyed by the stored
 * row's identity, the engine's bundled catalog is switched off (one source of probes since
 * 2026-11-02), a re-saved probe replaces its row, a name is unique among the subject's rows,
 * and a timeout reads as a timeout. No Swing, no store.
 */
class ScanPanelTest {

    /** A minimal valid definition — connect, then done — under the given name. */
    private static String json(String name) {
        return "{\"name\":\"" + name + "\",\"service\":\"redis\",\"ports\":[6379],"
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeType stored(String guid, String name) {
        ProbeType p = new ProbeType();
        if (guid != null) p.setGUID(guid);
        p.setName(name);
        p.setDefinition(json(name));
        return p;
    }

    private static List<ProbeDefinition> defs(String... names) {
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
                ProbeSelection.portsPlaceholder(defs("my-redis")), "a probe written here counts the same");
    }

    @Test
    void aProbeNameWithSpacesNeverBecomesAScanTarget() {
        String typed = "10.0.0.0/24 -p 6379";
        NMapConfig cfg = NMap.parseCommand(typed);
        ProbeType redis = stored("g1", "Redis TLS handshake");
        Set<String> ticks = Set.of(ProbeSelection.storedKey(redis));

        ProbeSelection.Selection sel = ProbeSelection.select(List.of(stored("g0", "ssh"), redis), ticks);
        ProbeSelection.applyTo(cfg, sel);

        assertEquals(List.of("10.0.0.0/24"), cfg.targets, "the words of the name are not targets");
        assertTrue(cfg.probeScan, "ticking implies -sV");
        assertEquals(List.of("Redis TLS handshake"), cfg.probeNames);
        assertEquals(1, cfg.extraProbes.size());
        assertEquals("Redis TLS handshake", cfg.extraProbes.get(0).getName());
        assertEquals("Redis TLS handshake", ProbeSelection.describe(sel));
        assertFalse(cfg.bundledCatalog, "the engine runs the ticked definitions only, never its own bundle");
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
            ProbeSelection.Selection sel = ProbeSelection.select(List.of(stored("g0", "ssh"), stored("g1", "x")), Set.of());
            ProbeSelection.applyTo(cfg, sel);

            assertFalse(cfg.probeScan, typed);
            assertTrue(cfg.probeNames.isEmpty(), typed);
            assertTrue(cfg.extraProbes.isEmpty(), typed);
            assertFalse(cfg.bundledCatalog, typed);
            assertEquals("", ProbeSelection.describe(sel));
        }
    }

    @Test
    void allTickedNamesEveryProbe() {
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        List<ProbeType> stored = List.of(stored("g0", "ssh"), stored("g1", "http"), stored("g2", "mine"));
        Set<String> all = new HashSet<>();
        for (ProbeType p : stored) all.add(ProbeSelection.storedKey(p));
        ProbeSelection.Selection sel = ProbeSelection.select(stored, all);
        ProbeSelection.applyTo(cfg, sel);

        assertTrue(cfg.probeScan);
        assertEquals(Set.of("ssh", "http", "mine"), Set.copyOf(cfg.probeNames));
        assertEquals(3, cfg.extraProbes.size(), "every ticked definition is handed over; the engine has no bundle to add");
    }

    /** 2026-11-02: a name is unique among the subject's own rows; the row being saved may keep its own. */
    @Test
    void aNameIsTakenWhenAnotherStoredRowCarriesIt() {
        List<ProbeType> stored = List.of(stored("g1", "ssh"), stored("g2", "http"), stored(null, "draft"));
        assertTrue(ProbeSelection.nameTaken(stored, "ssh", null), "a new row cannot take ssh");
        assertTrue(ProbeSelection.nameTaken(stored, "ssh", "g2"), "http renamed to ssh is refused");
        assertFalse(ProbeSelection.nameTaken(stored, "ssh", "g1"), "ssh keeps its own name");
        assertFalse(ProbeSelection.nameTaken(stored, "draft", null), "an unsaved row holds no name");
        assertFalse(ProbeSelection.nameTaken(stored, "smtp", null));
        assertFalse(ProbeSelection.nameTaken(stored, null, null));
        assertTrue(ProbeSelection.nameTaken(stored, " SSH", null), "matched in the row's form");
        assertSame(stored.get(0), ProbeSelection.existingByName(stored, "SSH "), "a report's old spelling still finds the row");
    }

    /**
     * 2026-11-02, maintainer: {@code ProbeType.setName} lower-cases and trims. The app mirrors
     * the rule and refuses a JSON name that is not already in that form, so the row's name and
     * the JSON's never disagree (the engine, the groups and the reports read the JSON's).
     */
    @Test
    void aProbeNameMustAlreadyBeWhatTheRowWouldStore() {
        assertEquals("ssh", ProbeSelection.canonicalName("  SSH "));
        assertNull(ProbeSelection.canonicalName("   "));
        assertNull(ProbeSelection.canonicalName(null));
        assertNull(ProbeSelection.nameForm("my-redis"), "already what the row stores");
        assertEquals("myredis", ProbeSelection.nameForm("MyRedis"));
        assertEquals("ssh", ProbeSelection.nameForm("ssh "));
        assertEquals("", ProbeSelection.nameForm(" "));
        ProbeType row = new ProbeType();
        row.setName(" SSH ");
        assertEquals("ssh", row.getName(), "the entity's own rule, which the app mirrors");
    }

    @Test
    void anInvalidStoredProbeIsNamedInTheError() {
        ProbeType broken = stored("g2", "broken");
        broken.setDefinition("{\"name\":\"broken\",\"start\":\"nowhere\",\"states\":{}}");
        Set<String> ticks = Set.of(ProbeSelection.storedKey(broken));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProbeSelection.select(List.of(broken), ticks));
        assertTrue(e.getMessage().contains("broken"), e.getMessage());
    }

    @Test
    void reSavingADefinitionFindsTheRowItReplaces() {
        ProbeType a = stored("g1", "alpha");
        ProbeType b = stored("g2", "beta");
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
        ProbeType ssh = stored("g0", "ssh");
        ProbeType mine = stored("g1", "Redis TLS handshake");
        Set<String> keys = ProbeSelection.keysForNames("ssh, Redis TLS handshake, deleted-since", List.of(ssh, mine));
        assertEquals(Set.of("s:g0", "s:g1"), keys, "by name among the subject's rows, unknown dropped");
        assertTrue(ProbeSelection.keysForNames(null, List.of(ssh)).isEmpty());
        assertTrue(ProbeSelection.keysForNames("  ", List.of(ssh)).isEmpty());
    }

    /**
     * Probe groups (2026-11-01): a group is a convenience over the ticks. Ticking one adds
     * exactly its members' keys, the run then names exactly those probes (the group itself
     * never reaches the config), and unticking it leaves the other ticks alone.
     */
    @Test
    void aGroupTicksItsProbesAndNothingElseReachesTheEngine() {
        ProbeType ssh = stored("g0", "ssh");
        ProbeType http = stored("g2", "http");
        ProbeType mine = stored("g1", "Redis TLS handshake");
        List<ProbeType> stored = List.of(ssh, http, mine);
        ProbeGroup web = new ProbeGroup();
        web.setName("web");
        web.setProbes("http, Redis TLS handshake, deleted-since");
        Set<String> members = ProbeGroupModel.memberKeys(web, stored);
        assertEquals(Set.of("s:g2", "s:g1"), members, "the missing member resolves to nothing");

        Set<String> ticks = new HashSet<>(Set.of("s:g0"));
        ProbeGroupModel.applyTick(ticks, members, true);
        NMapConfig cfg = NMap.parseCommand("10.0.0.1");
        ProbeSelection.Selection sel = ProbeSelection.select(stored, ticks);
        ProbeSelection.applyTo(cfg, sel);
        assertTrue(cfg.probeScan);
        assertEquals(Set.of("ssh", "http", "Redis TLS handshake"), Set.copyOf(cfg.probeNames), "the probes, never the group");
        assertEquals("ssh, http, Redis TLS handshake", ProbeSelection.describe(sel), "what the report records");

        ProbeGroupModel.applyTick(ticks, members, false);
        assertEquals(Set.of("s:g0"), ticks, "unticking the group leaves the earlier tick");
        // and Save ticked as group would store exactly the live names
        assertEquals(Set.of("ssh"), ProbeGroupModel.namesFromTicks(ticks, stored));
    }

    @Test
    void aTickIsTheStoredRowsIdentity() {
        ProbeType mine = stored("g1", "ssh");
        assertEquals("s:g1", ProbeSelection.storedKey(mine));
        assertEquals("s:name:draft", ProbeSelection.storedKey(stored(null, "draft")));
    }

    /** The origin property (2026-11-02): set by the seed on a copy of a bundled probe, absent on a probe written here. */
    @Test
    void theOriginMarksACopyOfABundledProbe() {
        ProbeType copy = stored("g1", "ssh");
        assertEquals("", ProbeSelection.originOf(copy));
        assertFalse(ProbeSelection.isBundledCopy(copy));
        ProbeSelection.markBundledCopy(copy);
        assertEquals("bundled", ProbeSelection.originOf(copy));
        assertTrue(ProbeSelection.isBundledCopy(copy));
        assertEquals("", ProbeSelection.originOf(null));
    }
}
