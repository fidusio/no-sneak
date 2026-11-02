package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.data.ProbeType;
import io.xlogistx.nosneak.data.ProbeGroup;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The Probe groups table (2026-11-01) and the pure rules behind a group: a named set of probe
 * <b>names</b> (the entity's {@code probes}, an {@code NVStringSet}) that resolves to tick keys
 * the moment it is used. Swing-free apart from the
 * table-model contract, so {@code ProbeGroupModelTest} pins every rule without a display.
 * <p>
 * The one rule that matters: a group is a convenience over the ticks. Ticking it adds its
 * members' keys to {@code tickedProbes} ({@link #applyTick}); the chips stay individual probes;
 * the report records the probes, never the group. Names resolve through
 * {@link ProbeSelection#keysForMembers} — by name among the subject's own rows, the one source
 * of probes since 2026-11-02, a name that matches nothing dropped — exactly as a stored report's
 * {@code probes} do for <i>Scan again</i>, so a group outlives the deletion of a member and
 * simply says what is missing; a probe renamed in the editor is followed ({@link #renamed}).
 */
public final class ProbeGroupModel extends AbstractTableModel {

    /** One group and what its names resolve to now. {@code preset} marks a bundled, read-only group (none ship yet). */
    public record Row(ProbeGroup group, boolean preset, Set<String> keys, List<String> missing) {
        public String name() {
            return group.getName() == null ? "" : group.getName();
        }

        public String description() {
            return group.getDescription() == null ? "" : group.getDescription();
        }

        /** {@code 4}, or {@code 4 (1 missing)}: the resolved count, and what did not resolve. */
        public String count() {
            return missing.isEmpty() ? String.valueOf(keys.size()) : keys.size() + " (" + missing.size() + " missing)";
        }
    }

    /** The columns are {@link NSAppUtil.ProbeGroupColumn}, in its order; the header is the constant's display name. */
    public static final int COL_NAME = NSAppUtil.ProbeGroupColumn.NAME.ordinal(),
            COL_PROBES = NSAppUtil.ProbeGroupColumn.PROBES.ordinal(),
            COL_DESCRIPTION = NSAppUtil.ProbeGroupColumn.DESCRIPTION.ordinal();

    private List<Row> rows = List.of();

    /**
     * The rows: the subject's groups, then any preset ones (the seam for bundled groups), each
     * resolved against the probes known now, sorted by name.
     */
    public static List<Row> rows(List<ProbeGroup> mine, List<ProbeGroup> presets, List<ProbeType> stored) {
        List<Row> out = new ArrayList<>();
        for (ProbeGroup g : mine) out.add(new Row(g, false, memberKeys(g, stored), missing(g, stored)));
        for (ProbeGroup g : presets) out.add(new Row(g, true, memberKeys(g, stored), missing(g, stored)));
        out.sort(Comparator.comparing(Row::name, String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    /** The group's member names in stored order; empty, never null, for a group with none. */
    public static Set<String> members(ProbeGroup g) {
        Set<String> probes = g.getProbes();
        return probes == null ? Set.of() : probes;
    }

    /** The tick keys the group's names resolve to now (by name among the subject's rows; unknown dropped). */
    public static Set<String> memberKeys(ProbeGroup g, List<ProbeType> stored) {
        return ProbeSelection.keysForMembers(members(g), stored);
    }

    /** The member names that resolve to nothing — a probe deleted since the group was saved. */
    public static List<String> missing(ProbeGroup g, List<ProbeType> stored) {
        List<String> out = new ArrayList<>();
        for (String name : members(g)) {
            if (ProbeSelection.keysForNames(name, stored).isEmpty()) out.add(name);
        }
        return out;
    }

    /**
     * The inverse of {@link #memberKeys}: the ticked probes' names in catalog order — by
     * priority then name, as the library lists them and the engine runs them; a probe whose
     * JSON does not parse sorts last — so a group saved from the chips reads the same way every
     * time (the set keeps insertion order, so it goes into {@code ProbeGroup.setProbes(Set)} as
     * is). A tick for a probe that no longer exists contributes nothing.
     */
    public static Set<String> namesFromTicks(Set<String> ticks, List<ProbeType> stored) {
        List<ProbeType> s = new ArrayList<>();
        for (ProbeType p : stored) if (p.getName() != null && !p.getName().isBlank()) s.add(p);
        s.sort(Comparator.comparingInt(ProbeGroupModel::priorityOf).reversed()
                .thenComparing(ProbeType::getName, String.CASE_INSENSITIVE_ORDER));
        Set<String> names = new LinkedHashSet<>();
        for (ProbeType p : s) {
            if (ticks.contains(ProbeSelection.storedKey(p))) names.add(p.getName());
        }
        return names;
    }

    /** The declared priority of a stored probe; the lowest possible for one that does not parse. */
    private static int priorityOf(ProbeType p) {
        try {
            return ProbeDefinitionLoader.parse(p.getDefinition(), p.getName()).getPriority();
        } catch (RuntimeException e) {
            return Integer.MIN_VALUE;
        }
    }

    /**
     * A probe rename follows into the groups (2026-11-02): every group whose members hold
     * {@code oldName} gets {@code newName} in its place, order kept, and is returned for the
     * caller to save. Nothing for a null or unchanged name.
     */
    public static List<ProbeGroup> renamed(List<ProbeGroup> groups, String oldName, String newName) {
        List<ProbeGroup> out = new ArrayList<>();
        if (oldName == null || newName == null || oldName.equals(newName)) return out;
        for (ProbeGroup g : groups) {
            Set<String> before = members(g);
            if (!before.contains(oldName)) continue;
            Set<String> after = new LinkedHashSet<>();
            for (String n : before) after.add(oldName.equals(n) ? newName : n);
            g.setProbes(after);
            out.add(g);
        }
        return out;
    }

    /** The members as the dialogs show them: {@code ssh, https-pqc}. */
    public static String describe(Set<String> names) {
        return names == null ? "" : String.join(", ", names);
    }

    /**
     * Ticks or unticks a group: on adds exactly its member keys, off removes exactly them, so
     * ticks that belong to other probes survive either way. Returns {@code ticks} for chaining.
     */
    public static Set<String> applyTick(Set<String> ticks, Set<String> members, boolean on) {
        if (on) ticks.addAll(members);
        else ticks.removeAll(members);
        return ticks;
    }

    /** A group reads as ticked when every member that still exists is ticked, and at least one exists. */
    public static boolean isTicked(Set<String> ticks, Set<String> members) {
        return !members.isEmpty() && ticks.containsAll(members);
    }

    /** The inline note for a group with members that no longer exist; null when nothing is missing. */
    public static String missingNote(ProbeGroup g, List<String> missing) {
        if (missing.isEmpty()) return null;
        return "Group \"" + g.getName() + "\": " + missing.size() + " probe" + (missing.size() == 1 ? "" : "s")
                + " no longer exist" + (missing.size() == 1 ? "s" : "") + " (" + String.join(", ", missing) + ")";
    }

    /** The stored group a name would replace (case-insensitive), or null when it is new. */
    public static ProbeGroup existingByName(List<ProbeGroup> groups, String name) {
        if (name == null) return null;
        String wanted = name.trim();
        for (ProbeGroup g : groups) {
            if (g.getName() != null && g.getName().trim().equalsIgnoreCase(wanted) && SUS.isNotEmpty(g.getGUID())) return g;
        }
        return null;
    }

    /** Null when a group can be saved, else the reason: a blank name, or no probes. */
    public static String validate(String name, Set<String> probes) {
        if (name == null || name.isBlank()) return "Give the group a name.";
        if (probes == null || probes.stream().noneMatch(p -> p != null && !p.isBlank())) return "Tick at least one probe.";
        return null;
    }

    /** The search box: a case-insensitive match on the name, the description or any member name. */
    public static boolean matches(ProbeGroup g, String query) {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        if (q.isEmpty()) return true;
        if (g.getName() != null && g.getName().toLowerCase(Locale.ROOT).contains(q)) return true;
        if (g.getDescription() != null && g.getDescription().toLowerCase(Locale.ROOT).contains(q)) return true;
        for (String name : members(g)) {
            if (name.toLowerCase(Locale.ROOT).contains(q)) return true;
        }
        return false;
    }

    public void setRows(List<Row> rows) {
        this.rows = rows == null ? List.of() : rows;
        fireTableDataChanged();
    }

    public Row at(int modelRow) {
        return rows.get(modelRow);
    }

    public List<Row> rows() {
        return rows;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return NSAppUtil.ProbeGroupColumn.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return NSAppUtil.ProbeGroupColumn.values()[column].getDisplayName();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (NSAppUtil.ProbeGroupColumn.values()[columnIndex]) {
            case NAME -> r.name();
            case PROBES -> r.count();
            case DESCRIPTION -> r.description();
        };
    }
}
