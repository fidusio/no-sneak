package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.nmap.NMap;
import io.xlogistx.nosneak.nmap.NMapConfig;
import io.xlogistx.nosneak.nmap.NMapScanner;
import io.xlogistx.nosneak.nmap.ScanReport;
import org.zoxweb.shared.util.SUS;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The pure half of the scanner card: how ticks map onto an {@link NMapConfig}, how they are
 * described, what a timeout says, and which stored row a saved definition replaces. Static
 * and Swing-free so {@code ScanPanelTest} can pin every rule without a display. Moved out of
 * {@code ScanPanel} on 2026-11-01 so {@link ProbeGroupModel} shares one {@link #keysForNames}.
 */
public final class ProbeSelection {

    /** What the ticks resolved to: bundled probes by name, stored probes as definitions. */
    public record Selection(List<String> bundledNames, List<ProbeDefinition> stored) {
        public boolean isEmpty() {
            return bundledNames.isEmpty() && stored.isEmpty();
        }
    }

    private ProbeSelection() {}

    public static String bundledKey(String name) {
        return "b:" + name;
    }

    /** A stored row's identity; falls back to the name only for a row that was never saved. */
    public static String storedKey(ProbeContent p) {
        String guid = p.getGUID();
        return SUS.isNotEmpty(guid) ? "s:" + guid : "s:name:" + p.getName();
    }

    /**
     * Resolves the ticked keys. A stored probe's JSON is parsed here so an invalid one is a
     * clear message naming the probe, not an engine failure later.
     *
     * @throws IllegalArgumentException when a ticked stored probe is not a valid definition
     */
    public static Selection select(List<ProbeDefinition> bundled, List<ProbeContent> stored,
                            Set<String> ticks) {
        List<String> names = new ArrayList<>();
        for (ProbeDefinition d : bundled) {
            if (ticks.contains(bundledKey(d.getName()))) names.add(d.getName());
        }
        List<ProbeDefinition> extras = new ArrayList<>();
        for (ProbeContent p : stored) {
            if (p.getName() == null || !ticks.contains(storedKey(p))) continue;
            try {
                extras.add(ProbeDefinitionLoader.parse(p.getContent(), p.getName()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "Probe '" + p.getName() + "' is not valid: " + e.getMessage(), e);
            }
        }
        return new Selection(names, extras);
    }

    /**
     * Applies the selection to the parsed config. The selection is the only source of
     * probing (maintainer, 2026-10-26): ticked probes imply {@code -sV} and name the set;
     * <b>no ticks mean no probing</b>, whatever {@code -sV} or {@code --probes} the command
     * carried (a bare {@code -sV} would otherwise run the engine's whole catalog). Names never
     * pass through the command string.
     */
    public static void applyTo(NMapConfig cfg, Selection sel) {
        if (sel.isEmpty()) {
            cfg.probeScan(false);
            cfg.probeNames.clear();
            cfg.extraProbes.clear();
            return;
        }
        cfg.probeScan(true);
        for (String name : sel.bundledNames()) cfg.probe(name);
        for (ProbeDefinition d : sel.stored()) {
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
     * matched to a bundled probe first, then to a stored one by name; a name that matches
     * nothing (a stored probe deleted since) is dropped. Null or blank gives no ticks.
     */
    public static Set<String> keysForNames(String csv, List<ProbeDefinition> bundled, List<ProbeContent> stored) {
        Set<String> keys = new HashSet<>();
        if (csv == null || csv.isBlank()) return keys;
        for (String raw : csv.split(",")) {
            String name = raw.trim();
            if (name.isEmpty()) continue;
            boolean found = false;
            for (ProbeDefinition d : bundled) {
                if (name.equals(d.getName())) {
                    keys.add(bundledKey(d.getName()));
                    found = true;
                    break;
                }
            }
            if (found) continue;
            ProbeContent mine = existingByName(stored, name);
            if (mine != null) keys.add(storedKey(mine));
        }
        return keys;
    }

    /** The ticked names as a comma-separated list, for display and for the report. */
    public static String describe(Selection sel) {
        List<String> names = new ArrayList<>(sel.bundledNames());
        for (ProbeDefinition d : sel.stored()) names.add(d.getName());
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

    /** The stored row a definition with this name would replace, or null when it is new. */
    public static ProbeContent existingByName(List<ProbeContent> stored, String name) {
        if (name == null) return null;
        for (ProbeContent p : stored) {
            if (name.equals(p.getName()) && SUS.isNotEmpty(p.getGUID())) return p;
        }
        return null;
    }
}
