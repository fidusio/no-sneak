package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.scan.data.ProbeType;
import io.xlogistx.scan.model.ProbeDefinition;
import io.xlogistx.scan.model.ProbeDefinitionLoader;
import io.xlogistx.scan.nmap.NMap;
import io.xlogistx.scan.nmap.NMapConfig;
import io.xlogistx.scan.nmap.NMapScanner;
import io.xlogistx.scan.nmap.ScanReport;
import org.zoxweb.shared.data.PropertyImpl;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SUS;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The pure half of the scanner card: how ticks map onto an {@link NMapConfig}, how they are
 * described, what a timeout says, and which stored row a saved definition replaces. Static
 * and Swing-free so {@code ScanPanelTest} can pin every rule without a display. Moved out of
 * {@code ScanPanel} on 2026-11-01 so {@link ProbeGroupModel} shares one {@link #keysForNames}.
 * <p>
 * Since 2026-11-02 there is <b>one source of probes</b>: the subject's own {@link ProbeType}
 * rows, which the bundled definitions were copied into once at the subject's first login
 * ({@code Session.seedBundledProbes}). A tick key is a stored row's identity ({@link #storedKey});
 * the engine is handed exactly the ticked definitions with its bundled catalog switched off
 * ({@link NMapConfig#bundledCatalog}), so nothing is shadowed and nothing runs that the subject
 * did not tick. A copy made by the seed carries the property {@link #ORIGIN} = {@link #ORIGIN_BUNDLED}.
 */
public final class ProbeSelection {

    /** The property on a probe row that says where it came from, and its value for a copy of a bundled probe. */
    public static final String ORIGIN = "origin";
    public static final String ORIGIN_BUNDLED = "bundled";

    /** What the ticks resolved to: the stored probes as definitions. */
    public record Selection(List<ProbeDefinition> probes) {
        public boolean isEmpty() {
            return probes.isEmpty();
        }
    }

    private ProbeSelection() {}

    /** A stored row's identity; falls back to the name only for a row that was never saved. */
    public static String storedKey(ProbeType p) {
        String guid = p.getGUID();
        return SUS.isNotEmpty(guid) ? "s:" + guid : "s:name:" + p.getName();
    }

    /** The row's {@link #ORIGIN} property, {@code ""} when it has none (a probe written here). */
    public static String originOf(ProbeType p) {
        NVGenericMap props = p == null ? null : p.getProperties();
        Object v = props == null ? null : props.getValue(ORIGIN);
        return v == null ? "" : v.toString();
    }

    /** True for a row the seed copied from the bundled set. Nothing reads it for behaviour; the library shows it. */
    public static boolean isBundledCopy(ProbeType p) {
        return ORIGIN_BUNDLED.equals(originOf(p));
    }

    /** Marks {@code p} as a copy of a bundled probe (the seed and its test). */
    public static void markBundledCopy(ProbeType p) {
        NVGenericMap props = p.getProperties();
        if (props == null) {
            props = new NVGenericMap();
            p.setValue(PropertyImpl.Param.PROPERTIES, props);
        }
        props.build(ORIGIN, ORIGIN_BUNDLED);
    }

    /**
     * Resolves the ticked keys. A stored probe's JSON is parsed here so an invalid one is a
     * clear message naming the probe, not an engine failure later.
     *
     * @throws IllegalArgumentException when a ticked stored probe is not a valid definition
     */
    public static Selection select(List<ProbeType> stored, Set<String> ticks) {
        List<ProbeDefinition> defs = new ArrayList<>();
        for (ProbeType p : stored) {
            if (p.getName() == null || !ticks.contains(storedKey(p))) continue;
            try {
                defs.add(ProbeDefinitionLoader.parse(p.getDefinition(), p.getName()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "Probe '" + p.getName() + "' is not valid: " + e.getMessage(), e);
            }
        }
        return new Selection(defs);
    }

    /**
     * Applies the selection to the parsed config. The selection is the only source of
     * probing (maintainer, 2026-10-26): ticked probes imply {@code -sV} and name the set;
     * <b>no ticks mean no probing</b>, whatever {@code -sV} or {@code --probes} the command
     * carried (a bare {@code -sV} would otherwise run the engine's whole catalog). Names never
     * pass through the command string. The engine's bundled catalog is switched off either way
     * (2026-11-02): the subject owns a copy of every probe, so the catalog is exactly the ticks.
     */
    public static void applyTo(NMapConfig cfg, Selection sel) {
        cfg.bundledCatalog(false);
        if (sel.isEmpty()) {
            cfg.probeScan(false);
            cfg.probeNames.clear();
            cfg.extraProbes.clear();
            return;
        }
        cfg.probeScan(true);
        for (ProbeDefinition d : sel.probes()) {
            cfg.extraProbe(d);
            cfg.probe(d.getName());
        }
    }

    /**
     * What an empty Ports field scans, in the field's own grammar (2026-10-31, the maintainer:
     * "if the ports are not set and probes were selected we scan the probe default port per
     * probe"): the ticked definitions' declared ports through {@link NMap#probePorts}, the
     * engine's own rule — {@code 22,443,2222,8443 (ticked probes)}, {@code U:53}
     * for a UDP probe — or {@link ScanFormPanel#PORTS_DEFAULT_HINT} with no chip, or chips
     * that declare no port (the engine then scans 1-1024 and says so).
     */
    public static String portsPlaceholder(List<ProbeDefinition> ticked) {
        if (ticked == null || ticked.isEmpty()) return ScanFormPanel.PORTS_DEFAULT_HINT;
        NMap.PortSpec spec = NMap.probePorts(ticked);
        if (spec.tcp().length == 0 && spec.udp().length == 0) return ScanFormPanel.PORTS_DEFAULT_HINT;
        return NMap.portSpec(spec.tcp(), spec.udp()) + " (ticked probes)";
    }

    /**
     * The inverse of {@link #describe}: the ticks a report's saved {@code probes} property
     * stands for, against the probes known now (2026-10-25, for <i>Scan again</i>). A name is
     * matched to the subject's stored row of that name; a name that matches nothing (a probe
     * deleted since) is dropped. Null or blank gives no ticks.
     */
    public static Set<String> keysForNames(String csv, List<ProbeType> stored) {
        if (csv == null || csv.isBlank()) return new HashSet<>();
        return keysForMembers(List.of(csv.split(",")), stored);
    }

    /** The same for names already split (a {@code ProbeGroup}'s members): trimmed, blanks skipped. */
    public static Set<String> keysForMembers(Collection<String> names, List<ProbeType> stored) {
        Set<String> keys = new HashSet<>();
        if (names == null) return keys;
        for (String raw : names) {
            String name = raw == null ? "" : raw.trim();
            if (name.isEmpty()) continue;
            ProbeType mine = existingByName(stored, name);
            if (mine != null) keys.add(storedKey(mine));
        }
        return keys;
    }

    /** The ticked names as a comma-separated list, for display and for the report. */
    public static String describe(Selection sel) {
        List<String> names = new ArrayList<>();
        for (ProbeDefinition d : sel.probes()) names.add(d.getName());
        return String.join(", ", names);
    }

    /** What the subject reads when the wait budget runs out. The scan has been stopped. */
    public static String timeoutMessage(NMapConfig cfg, long budgetMs) {
        long seconds = Math.max(1, (budgetMs + 999) / 1000);
        return "Scan timed out after " + seconds + " s: " + String.join(" ", cfg.targets)
                + "\nThe scan was stopped; what completed is shown and nothing was saved."
                + " A narrower range, fewer ports, or -t with a longer per-connection timeout"
                + " gives it room.";
    }

    /** What the subject reads after pressing Stop. */
    public static String cancelledMessage(ScanReport report) {
        return NMapScanner.progress(report).cancelledLine()
                + "\nWhat completed is shown; nothing was saved.";
    }

    /**
     * A probe's name as {@link ProbeType#setName} stores it (the entity's rule since the
     * 2026-11-02 rename): lower-case and trimmed, null when nothing is left.
     */
    public static String canonicalName(String name) {
        return SUS.trimOrNull(DataEncoder.StringLower.encode(name));
    }

    /**
     * Null when {@code name} is already what the row would store, otherwise the form to use
     * ({@code ""} when nothing would be left). The JSON's {@code name} and the row's must be one
     * string — the engine, the groups and the reports read the JSON's, the library and the
     * dedupe rules ({@link #existingByName}, {@link #nameTaken}) the row's — so a definition
     * whose name the entity would re-case is refused rather than stored under another name.
     */
    public static String nameForm(String name) {
        String canonical = canonicalName(name);
        if (canonical == null) return "";
        return canonical.equals(name) ? null : canonical;
    }

    /**
     * The stored row a definition with this name would replace, or null when it is new. The
     * name is matched in the row's form ({@link #canonicalName}), so a report or a group that
     * kept the JSON's own spelling of a name from before the rule still finds the row.
     */
    public static ProbeType existingByName(List<ProbeType> stored, String name) {
        String wanted = canonicalName(name);
        if (wanted == null) return null;
        for (ProbeType p : stored) {
            if (wanted.equals(p.getName()) && SUS.isNotEmpty(p.getGUID())) return p;
        }
        return null;
    }

    /**
     * Whether another stored row of the subject already carries {@code name} (2026-11-02): the
     * engine's catalog, a group's members and a report's {@code probes} all identify a probe by
     * its name, so a second row of one name would be invisible to all three. {@code exceptGuid}
     * is the row being saved, which may of course keep its own name. Matched in the row's form
     * ({@link #canonicalName}), like {@link #existingByName}.
     */
    public static boolean nameTaken(List<ProbeType> stored, String name, String exceptGuid) {
        String wanted = canonicalName(name);
        if (wanted == null) return false;
        for (ProbeType p : stored) {
            if (!wanted.equals(p.getName()) || SUS.isEmpty(p.getGUID())) continue;
            if (!p.getGUID().equals(exceptGuid)) return true;
        }
        return false;
    }
}
