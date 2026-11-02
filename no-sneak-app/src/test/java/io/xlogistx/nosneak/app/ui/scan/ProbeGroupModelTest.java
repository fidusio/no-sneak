package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.data.ProbeGroup;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the probe groups' rules (2026-11-01): a group stores names and resolves to tick keys
 * when used — bundled first, mine by name, unknown dropped; the csv a tick set produces reads
 * back to the same ticks; a tick adds and an untick removes exactly the members; validation,
 * dedupe by name, the search. No Swing, no store.
 */
class ProbeGroupModelTest {

    private static String json(String name, int priority) {
        return "{\"name\":\"" + name + "\",\"service\":\"redis\",\"ports\":[6379],\"priority\":" + priority + ","
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeContent stored(String guid, String name) {
        ProbeContent p = new ProbeContent();
        if (guid != null) p.setGUID(guid);
        p.setName(name);
        p.setContent(json(name, 10));
        return p;
    }

    /** ssh at priority 50, http at 80: catalog order is http, ssh. */
    private static List<ProbeDefinition> bundled() {
        return List.of(ProbeDefinitionLoader.parse(json("ssh", 50), "ssh"), ProbeDefinitionLoader.parse(json("http", 80), "http"));
    }

    private static ProbeGroup group(String guid, String name, String csv) {
        ProbeGroup g = new ProbeGroup();
        if (guid != null) g.setGUID(guid);
        g.setName(name);
        g.setProbes(csv);
        return g;
    }

    @Test
    void theEntityParsesItsCsv() {
        assertEquals(List.of("ssh", "https-pqc"), group(null, "g", " ssh ,https-pqc,, ").probeNames());
        assertTrue(group(null, "g", null).probeNames().isEmpty());
        assertTrue(ProbeGroup.parseNames("  ").isEmpty());
    }

    @Test
    void memberKeysResolveBundledFirstThenMineAndDropUnknown() {
        ProbeContent mine = stored("g1", "Redis TLS handshake");
        ProbeContent shadow = stored("g2", "ssh");
        ProbeGroup g = group("gg", "web", "ssh, Redis TLS handshake, deleted-since");
        assertEquals(Set.of("b:ssh", "s:g1"), ProbeGroupModel.memberKeys(g, bundled(), List.of(mine, shadow)),
                "a bundled name wins over a stored one of the same name, as Scan again resolves it");
        assertEquals(List.of("deleted-since"), ProbeGroupModel.missing(g, bundled(), List.of(mine, shadow)));
        assertTrue(ProbeGroupModel.missing(group(null, "x", "ssh"), bundled(), List.of()).isEmpty());
    }

    @Test
    void csvFromTicksIsTheInverseInCatalogOrder() {
        ProbeContent mine = stored("g1", "zz-mine");
        ProbeContent other = stored("g2", "aa-mine");
        Set<String> ticks = new HashSet<>(Set.of("b:ssh", "b:http", "s:g1", "s:g2", "b:gone", "s:g9"));
        String csv = ProbeGroupModel.csvFromTicks(ticks, bundled(), List.of(mine, other));
        assertEquals("http, ssh, aa-mine, zz-mine", csv, "bundled by priority then name, then mine by name; dead ticks dropped");
        ProbeGroup g = group(null, "all", csv);
        assertEquals(Set.of("b:ssh", "b:http", "s:g1", "s:g2"), ProbeGroupModel.memberKeys(g, bundled(), List.of(mine, other)));
        assertEquals("", ProbeGroupModel.csvFromTicks(Set.of(), bundled(), List.of(mine)));
    }

    @Test
    void aTickAddsExactlyTheMembersAndAnUntickRemovesExactlyThem() {
        Set<String> members = Set.of("b:ssh", "s:g1");
        Set<String> ticks = new HashSet<>(Set.of("b:http"));
        ProbeGroupModel.applyTick(ticks, members, true);
        assertEquals(Set.of("b:http", "b:ssh", "s:g1"), ticks);
        assertTrue(ProbeGroupModel.isTicked(ticks, members));
        ProbeGroupModel.applyTick(ticks, members, false);
        assertEquals(Set.of("b:http"), ticks, "the other tick survives");
        assertFalse(ProbeGroupModel.isTicked(ticks, members));
        assertFalse(ProbeGroupModel.isTicked(ticks, Set.of()), "a group with no live member never reads as ticked");
    }

    @Test
    void aGroupWhoseMembersAreAllGoneTicksNothingAndSaysSo() {
        ProbeGroup g = group("gg", "old", "deleted-a, deleted-b");
        Set<String> keys = ProbeGroupModel.memberKeys(g, bundled(), List.of());
        assertTrue(keys.isEmpty());
        Set<String> ticks = new HashSet<>(Set.of("b:ssh"));
        ProbeGroupModel.applyTick(ticks, keys, true);
        assertEquals(Set.of("b:ssh"), ticks);
        List<String> missing = ProbeGroupModel.missing(g, bundled(), List.of());
        assertEquals("Group \"old\": 2 probes no longer exist (deleted-a, deleted-b)", ProbeGroupModel.missingNote(g, missing));
        assertEquals("Group \"old\": 1 probe no longer exists (deleted-a)", ProbeGroupModel.missingNote(g, List.of("deleted-a")));
        assertNull(ProbeGroupModel.missingNote(g, List.of()));
    }

    @Test
    void rowsAreSortedByNameWithCountAndMissing() {
        ProbeContent mine = stored("g1", "mine");
        List<ProbeGroup> groups = List.of(
                group("a", "zeta", "ssh, mine"),
                group("b", "Alpha", "http, gone"));
        List<ProbeGroupModel.Row> rows = ProbeGroupModel.rows(groups, List.of(), bundled(), List.of(mine));
        assertEquals(2, rows.size());
        assertEquals("Alpha", rows.get(0).name());
        assertEquals("1 (1 missing)", rows.get(0).count());
        assertEquals("zeta", rows.get(1).name());
        assertEquals("2", rows.get(1).count());
        assertFalse(rows.get(0).preset());
        ProbeGroupModel model = new ProbeGroupModel();
        model.setRows(rows);
        assertEquals(3, model.getColumnCount());
        assertEquals("Alpha", model.getValueAt(0, ProbeGroupModel.COL_NAME));
        assertEquals("1 (1 missing)", model.getValueAt(0, ProbeGroupModel.COL_PROBES));
        assertEquals("", model.getValueAt(0, ProbeGroupModel.COL_DESCRIPTION));
        assertSame(rows.get(1), model.at(1));
        List<ProbeGroupModel.Row> withPreset = ProbeGroupModel.rows(groups, List.of(group(null, "builtin", "ssh")), bundled(), List.of());
        assertEquals(3, withPreset.size());
        assertTrue(withPreset.stream().anyMatch(ProbeGroupModel.Row::preset), "the seam for bundled groups");
    }

    @Test
    void existingByNameIsCaseInsensitiveAndWantsAStoredRow() {
        ProbeGroup a = group("g1", "Web tier", "ssh");
        ProbeGroup b = group("g2", "mail", "smtp");
        ProbeGroup unsaved = group(null, "draft", "ssh");
        assertSame(a, ProbeGroupModel.existingByName(List.of(a, b, unsaved), "web TIER "));
        assertSame(b, ProbeGroupModel.existingByName(List.of(a, b), "mail"));
        assertNull(ProbeGroupModel.existingByName(List.of(a, b, unsaved), "draft"), "never saved: nothing to update");
        assertNull(ProbeGroupModel.existingByName(List.of(a, b), "other"));
        assertNull(ProbeGroupModel.existingByName(List.of(a, b), null));
    }

    @Test
    void validateWantsANameAndAProbe() {
        assertNull(ProbeGroupModel.validate("web", "ssh"));
        assertEquals("Give the group a name.", ProbeGroupModel.validate("  ", "ssh"));
        assertEquals("Give the group a name.", ProbeGroupModel.validate(null, "ssh"));
        assertEquals("Tick at least one probe.", ProbeGroupModel.validate("web", " , "));
        assertEquals("Tick at least one probe.", ProbeGroupModel.validate("web", null));
    }

    @Test
    void theSearchMatchesNameDescriptionOrAnyMember() {
        ProbeGroup g = group("g1", "Web tier", "ssh, https-pqc");
        g.setDescription("Front doors");
        assertTrue(ProbeGroupModel.matches(g, ""));
        assertTrue(ProbeGroupModel.matches(g, null));
        assertTrue(ProbeGroupModel.matches(g, "web"));
        assertTrue(ProbeGroupModel.matches(g, "DOORS"));
        assertTrue(ProbeGroupModel.matches(g, "pqc"));
        assertFalse(ProbeGroupModel.matches(g, "smtp"));
    }
}
