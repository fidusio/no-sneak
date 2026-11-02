package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.data.ProbeType;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * The Probe library's table (2026-10-26): every probe a scan can run — the subject's own rows,
 * the one source of probes since 2026-11-02 (the bundled set was copied in at their first
 * login) — one row each, in the engine's order (priority first, then name). Pure and
 * Swing-free apart from the table-model contract, so {@code ProbeLibraryModelTest} pins the
 * rows, the filter and the editor's check message without a display.
 * <p>
 * A stored probe whose JSON no longer parses still gets a row — named after the stored row, with
 * {@link Row#error()} carrying the loader's reason — so the subject can find it and fix or delete
 * it rather than wonder where it went.
 */
public final class ProbeLibraryModel extends AbstractTableModel {

    /**
     * One probe. {@code def} is null only for a probe that fails to parse; then {@code error}
     * says why. {@code source} is the JSON text as the reader sees it (the stored content).
     */
    public record Row(ProbeDefinition def, String source, ProbeType content, String error) {
        /** {@code bundled} for a copy the seed made of a bundled probe, else {@code mine}; the Origin column. */
        public String origin() {
            return ProbeSelection.isBundledCopy(content) ? ProbeSelection.ORIGIN_BUNDLED : "mine";
        }

        public String name() {
            return def != null ? def.getName() : content != null ? String.valueOf(content.getName()) : "";
        }

        public String service() {
            return def != null && def.getService() != null ? def.getService() : "";
        }

        public String description() {
            return def != null ? def.getDescription() : null;
        }

        public int priority() {
            return def != null ? def.getPriority() : 0;
        }
    }

    /** The columns are {@link NSAppUtil.ProbeLibraryColumn}, in its order; the header is the constant's display name. */
    public static final int COL_NAME = NSAppUtil.ProbeLibraryColumn.NAME.ordinal(),
            COL_SERVICE = NSAppUtil.ProbeLibraryColumn.SERVICE.ordinal(),
            COL_PORTS = NSAppUtil.ProbeLibraryColumn.PORTS.ordinal(),
            COL_TRANSPORT = NSAppUtil.ProbeLibraryColumn.TRANSPORT.ordinal(),
            COL_PRIORITY = NSAppUtil.ProbeLibraryColumn.PRIORITY.ordinal(),
            COL_SOURCE = NSAppUtil.ProbeLibraryColumn.SOURCE.ordinal();

    private List<Row> rows = List.of();

    /**
     * The rows for a library: the subject's stored probes (parsed here; an unparsable one keeps
     * its row with the reason), sorted by priority descending then name, as the engine orders
     * its catalog.
     */
    public static List<Row> rows(List<ProbeType> stored) {
        List<Row> out = new ArrayList<>();
        for (ProbeType p : stored) {
            String json = p.getDefinition() == null ? "" : p.getDefinition();
            try {
                out.add(new Row(ProbeDefinitionLoader.parse(json, String.valueOf(p.getName())), json, p, null));
            } catch (IllegalArgumentException e) {
                out.add(new Row(null, json, p, e.getMessage()));
            }
        }
        out.sort(Comparator.comparingInt(Row::priority).reversed()
                .thenComparing(Row::name, String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    /** "22, 2222"; "any" for a probe with no declared port (the fallback tier). */
    public static String ports(ProbeDefinition def) {
        if (def == null || def.getPorts() == null || def.getPorts().length == 0) return "any";
        StringBuilder sb = new StringBuilder();
        for (int p : def.getPorts()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p);
        }
        return sb.toString();
    }

    /**
     * The row filter: a free-text query matched case-insensitively against the name, the
     * service, the description and every declared port (so "22" finds ssh).
     */
    public static boolean matches(Row row, String query) {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        if (q.isEmpty()) return true;
        if (row.name().toLowerCase(Locale.ROOT).contains(q)) return true;
        if (row.service().toLowerCase(Locale.ROOT).contains(q)) return true;
        String desc = row.description();
        if (desc != null && desc.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (row.def() != null && row.def().getPorts() != null) {
            for (int p : row.def().getPorts()) {
                if (String.valueOf(p).equals(q)) return true;
            }
        }
        return false;
    }

    /**
     * What the editor's Check button says about a draft: the parsed probe in one line, or the
     * loader's reason as an {@link IllegalArgumentException}. A markdown fence around the JSON
     * is tolerated, as the save path tolerates it.
     */
    public static String checkMessage(String draft) {
        ProbeDefinition def = ProbeDefinitionLoader.parse(unfence(draft), "draft");
        String form = ProbeSelection.nameForm(def.getName());
        if (form != null) {
            throw new IllegalArgumentException(NSAppUtil.ProbeEditor.NAME_FORM.getDisplayName() + " \"" + form + "\".");
        }
        int states = def.getStates() == null ? 0 : def.getStates().size();
        return "Valid: " + def.getName() + " · " + def.getTransport() + " " + ports(def)
                + " · " + states + " state" + (states == 1 ? "" : "s") + " from " + def.getStart();
    }

    /**
     * The request the Probe library types into the assistant's composer, alongside the probe
     * definition it attaches; §13 of that document is the output contract the request cites.
     */
    public static String assistantPrompt(String service, String port) {
        String what = service == null || service.isBlank() ? "the service" : service.trim();
        String where = port == null || port.isBlank() ? "" : " on port " + port.trim();
        return "Write a no-sneak probe for " + what + where + ".\n"
                + "Return only one JSON object in a ```json fence, as section 13 of the attached probe definition says,"
                + " with a one-line \"description\".";
    }

    static String unfence(String text) {
        if (text == null) return "";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("```[a-zA-Z]*\\s*\\n(.*?)```", java.util.regex.Pattern.DOTALL).matcher(text);
        return m.find() ? m.group(1) : text.trim();
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
        return NSAppUtil.ProbeLibraryColumn.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return NSAppUtil.ProbeLibraryColumn.values()[column].getDisplayName();
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == COL_PRIORITY ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (NSAppUtil.ProbeLibraryColumn.values()[columnIndex]) {
            case NAME -> r.name();
            case SERVICE -> r.def() != null ? r.service() : "?";
            case PORTS -> r.def() != null ? ports(r.def()) : "";
            case TRANSPORT -> r.def() != null ? r.def().getTransport() : "";
            case PRIORITY -> r.priority();
            case SOURCE -> r.origin();
        };
    }
}
