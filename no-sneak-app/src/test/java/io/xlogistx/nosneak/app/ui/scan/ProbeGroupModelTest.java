package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.data.ProbeType;
import io.xlogistx.nosneak.data.ProbeGroup;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the probe groups' rules (2026-11-01): a group stores a set of names and resolves to tick
 * keys when used — by name among the subject's own rows (the one source of probes since
 * 2026-11-02), unknown dropped; the names a tick set produces read back to the same ticks; a
 * tick adds and an untick removes exactly the members; validation, dedupe by name, the search,
 * and a probe rename that follows into the groups. No Swing, no store.
 */
class ProbeGroupModelTest {

    private static String json(String name, int priority) {
        return "{\"name\":\"" + name + "\",\"service\":\"redis\",\"ports\":[6379],\"priority\":" + priority + ","
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeType stored(String guid, String name, int priority) {
        ProbeType p = new ProbeType();
        if (guid != null) p.setGUID(guid);
        p.setName(name);
        p.setDefinition(json(name, priority));
        return p;
    }

    private static ProbeType stored(String guid, String name) {
        return stored(guid, name, 10);
    }

    /** ssh at priority 50, http at 80: catalog order is http, ssh. */
    private static List<ProbeType> catalog() {
        return List.of(stored("g-ssh", "ssh", 50), stored("g-http", "http", 80));
    }

    private static List<ProbeType> with(ProbeType... more) {
        List<ProbeType> out = new ArrayList<>(catalog());
        out.addAll(List.of(more));
        return out;
    }

    private static ProbeGroup group(String guid, String name, String csv) {
        ProbeGroup g = new ProbeGroup();
        if (guid != null) g.setGUID(guid);
        g.setName(name);
        g.setProbes(csv);
        return g;
    }

    @Test
    void theEntityKeepsAnOrderedSetOfNames() {
        assertEquals(List.of("ssh", "https-pqc"), List.copyOf(group(null, "g", " ssh ,https-pqc,, ssh ").getProbes()),
                "trimmed, blanks dropped, a repeat kept once, stored order");
        assertTrue(group(null, "g", null).getProbes().isEmpty());
        assertTrue(ProbeGroup.parseNames("  ").isEmpty());
        ProbeGroup g = group(null, "g", "ssh");
        g.setProbes(Set.of("http"));
        assertEquals(Set.of("http"), g.getProbes(), "the set setter replaces the members");
        assertTrue(ProbeGroupModel.members(new ProbeGroup()).isEmpty(), "a fresh group has no members, never null");
    }

    @Test
    void memberKeysResolveByNameAmongTheSubjectsRowsAndDropUnknown() {
        ProbeType mine = stored("g1", "Redis TLS handshake");
        ProbeGroup g = group("gg", "web", "ssh, Redis TLS handshake, deleted-since");
        assertEquals(Set.of("s:g-ssh", "s:g1"), ProbeGroupModel.memberKeys(g, with(mine)));
        assertEquals(List.of("deleted-since"), ProbeGroupModel.missing(g, with(mine)));
        assertTrue(ProbeGroupModel.missing(group(null, "x", "ssh"), catalog()).isEmpty());
        // two rows of one name (possible only in a store from before the unique-name rule): the
        // first saved row is the one, as the engine keeps the first definition of a name
        ProbeType twin = stored("g9", "ssh");
        assertEquals(Set.of("s:g-ssh"), ProbeGroupModel.memberKeys(group(null, "d", "ssh"), with(twin)));
    }

    @Test
    void namesFromTicksIsTheInverseInCatalogOrder() {
        ProbeType mine = stored("g1", "zz-mine");
        ProbeType other = stored("g2", "aa-mine");
        List<ProbeType> all = with(mine, other);
        Set<String> ticks = new HashSet<>(Set.of("s:g-ssh", "s:g-http", "s:g1", "s:g2", "s:gone"));
        Set<String> names = ProbeGroupModel.namesFromTicks(ticks, all);
        assertEquals(List.of("http", "ssh", "aa-mine", "zz-mine"), List.copyOf(names), "by priority then name, as the library lists them; dead ticks dropped");
        assertEquals("http, ssh, aa-mine, zz-mine", ProbeGroupModel.describe(names));
        ProbeGroup g = new ProbeGroup();
        g.setName("all");
        g.setProbes(names);
        assertEquals(Set.of("s:g-ssh", "s:g-http", "s:g1", "s:g2"), ProbeGroupModel.memberKeys(g, all));
        assertTrue(ProbeGroupModel.namesFromTicks(Set.of(), all).isEmpty());
        assertEquals("", ProbeGroupModel.describe(Set.of()));
        ProbeType broken = stored("g3", "broken");
        broken.setDefinition("{ not json");
        assertEquals(List.of("http", "ssh", "broken"), List.copyOf(ProbeGroupModel.namesFromTicks(
                Set.of("s:g-ssh", "s:g-http", "s:g3"), with(broken))), "a probe that does not parse sorts last, by name");
    }

    @Test
    void aTickAddsExactlyTheMembersAndAnUntickRemovesExactlyThem() {
        Set<String> members = Set.of("s:g-ssh", "s:g1");
        Set<String> ticks = new HashSet<>(Set.of("s:g-http"));
        ProbeGroupModel.applyTick(ticks, members, true);
        assertEquals(Set.of("s:g-http", "s:g-ssh", "s:g1"), ticks);
        assertTrue(ProbeGroupModel.isTicked(ticks, members));
        ProbeGroupModel.applyTick(ticks, members, false);
        assertEquals(Set.of("s:g-http"), ticks, "the other tick survives");
        assertFalse(ProbeGroupModel.isTicked(ticks, members));
        assertFalse(ProbeGroupModel.isTicked(ticks, Set.of()), "a group with no live member never reads as ticked");
    }

    @Test
    void aGroupWhoseMembersAreAllGoneTicksNothingAndSaysSo() {
        ProbeGroup g = group("gg", "old", "deleted-a, deleted-b");
        Set<String> keys = ProbeGroupModel.memberKeys(g, catalog());
        assertTrue(keys.isEmpty());
        Set<String> ticks = new HashSet<>(Set.of("s:g-ssh"));
        ProbeGroupModel.applyTick(ticks, keys, true);
        assertEquals(Set.of("s:g-ssh"), ticks);
        List<String> missing = ProbeGroupModel.missing(g, catalog());
        assertEquals("Group \"old\": 2 probes no longer exist (deleted-a, deleted-b)", ProbeGroupModel.missingNote(g, missing));
        assertEquals("Group \"old\": 1 probe no longer exists (deleted-a)", ProbeGroupModel.missingNote(g, List.of("deleted-a")));
        assertNull(ProbeGroupModel.missingNote(g, List.of()));
    }

    @Test
    void rowsAreSortedByNameWithCountAndMissing() {
        ProbeType mine = stored("g1", "mine");
        List<ProbeGroup> groups = List.of(
                group("a", "zeta", "ssh, mine"),
                group("b", "Alpha", "http, gone"));
        List<ProbeGroupModel.Row> rows = ProbeGroupModel.rows(groups, List.of(), with(mine));
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
        List<ProbeGroupModel.Row> withPreset = ProbeGroupModel.rows(groups, List.of(group(null, "builtin", "ssh")), catalog());
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
        assertNull(ProbeGroupModel.validate("web", Set.of("ssh")));
        assertEquals("Give the group a name.", ProbeGroupModel.validate("  ", Set.of("ssh")));
        assertEquals("Give the group a name.", ProbeGroupModel.validate(null, Set.of("ssh")));
        assertEquals("Tick at least one probe.", ProbeGroupModel.validate("web", Set.of(" ")));
        assertEquals("Tick at least one probe.", ProbeGroupModel.validate("web", Set.of()));
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

    /** 2026-11-02: a probe renamed in the editor keeps its place in every group that named it. */
    @Test
    void aRenameFollowsIntoTheGroupsThatNameTheProbe() {
        ProbeGroup a = group("g1", "web", "ssh, http");
        ProbeGroup b = group("g2", "mail", "smtp");
        ProbeGroup c = group("g3", "all", "http");
        List<ProbeGroup> changed = ProbeGroupModel.renamed(List.of(a, b, c), "http", "http-banner");
        assertEquals(List.of(a, c), changed, "only the groups that named it, for the caller to save");
        assertEquals(List.of("ssh", "http-banner"), List.copyOf(a.getProbes()), "renamed in place, order kept");
        assertEquals(Set.of("http-banner"), c.getProbes());
        assertEquals(Set.of("smtp"), b.getProbes(), "untouched");
        assertTrue(ProbeGroupModel.renamed(List.of(a, b, c), "nope", "x").isEmpty());
        assertTrue(ProbeGroupModel.renamed(List.of(a, b, c), "ssh", "ssh").isEmpty(), "the same name is no rename");
        assertTrue(ProbeGroupModel.renamed(List.of(a), null, "x").isEmpty());
    }
}
