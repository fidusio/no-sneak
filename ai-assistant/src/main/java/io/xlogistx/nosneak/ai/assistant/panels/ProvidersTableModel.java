package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.AIModelCatalog;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AIAPIProvider;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The Providers table (2026-10-26, the page's move to the house table look): one row per
 * configured provider — label, type, endpoint, default model, how many models discovery found,
 * when it last synced. The rows are {@link Row}s computed once per refresh ({@link #rowOf}), so
 * nothing walks a catalog from a renderer; the model itself is pure.
 */
public class ProvidersTableModel extends AbstractTableModel {

    /** One provider's facts, read once; {@code models} and {@code lastSynced} are discovery's. */
    public record Row(AIProvider provider, String name, String type, String endpoint, String defaultModel,
                      int models, Long lastSynced) {
    }

    public static final String[] COLS = {"Provider", "Type", "Endpoint", "Default model", "Models", "Last sync"};
    public static final int COL_NAME = 0, COL_TYPE = 1, COL_ENDPOINT = 2, COL_MODEL = 3, COL_MODELS = 4, COL_SYNCED = 5;

    public static final String UNNAMED = "Unnamed provider";

    private List<Row> rows = List.of();

    /** The row for a registered provider: its config's facts, and its catalog's count and stamp. */
    public static Row rowOf(AIProvider provider) {
        String name = SUS.trimOrNull(provider.getName()) != null ? provider.getName().trim() : UNNAMED;
        if (!(provider instanceof AIAPIProvider p))
            return new Row(provider, name, "", "", "", 0, null);
        AIModelCatalog catalog = p.getModelCatalog();
        String[] models = catalog != null ? catalog.models() : null;
        Instant synced = catalog != null ? catalog.lastSynced() : null;
        return new Row(provider, name,
                blank(p.getConfig().getProviderType()),
                blank(p.getBaseURL()),
                blank(p.getConfig().getDefaultModel()),
                models != null ? models.length : 0,
                synced != null ? synced.toEpochMilli() : null);
    }

    private static String blank(String s) {
        return SUS.trimOrNull(s) != null ? s.trim() : "";
    }

    public void setRows(List<Row> providers) {
        rows = providers == null ? List.of() : new ArrayList<>(providers);
        fireTableDataChanged();
    }

    public Row rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    /** The model row of the provider with that ID, or -1. */
    public int indexOf(String providerID) {
        if (providerID == null) return -1;
        for (int i = 0; i < rows.size(); i++)
            if (rows.get(i).provider() != null && providerID.equals(rows.get(i).provider().getID())) return i;
        return -1;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (column) {
            case COL_MODELS -> Integer.class;
            case COL_SYNCED -> Long.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_NAME -> r.name();
            case COL_TYPE -> r.type();
            case COL_ENDPOINT -> r.endpoint();
            case COL_MODEL -> r.defaultModel();
            case COL_MODELS -> r.models();
            case COL_SYNCED -> r.lastSynced();
            default -> "";
        };
    }
}
