package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * The key picker's table on the Providers page (2026-10-26): one row per credential the source
 * offers — name, the provider type it was stored with (or {@link #CHOOSE} when it has none the
 * assistant knows), endpoint, and how many live providers already borrow it. Unfiltered on
 * purpose: one key can back several providers. Rows are {@link Row}s computed by the panel.
 */
public class ProviderKeysTableModel extends AbstractTableModel {

    /** One credential's facts; {@code usedBy} is a registrar count taken when the rows were built. */
    public record Row(APIKey<String> key, String name, String provider, String endpoint, int usedBy) {
    }

    /** The columns are {@link AIAssistantUtil.ProviderKeysColumn}, in its order; the header is the constant's display name. */
    public static final int COL_NAME = AIAssistantUtil.ProviderKeysColumn.NAME.ordinal(),
            COL_PROVIDER = AIAssistantUtil.ProviderKeysColumn.PROVIDER.ordinal(),
            COL_ENDPOINT = AIAssistantUtil.ProviderKeysColumn.ENDPOINT.ordinal(),
            COL_USED = AIAssistantUtil.ProviderKeysColumn.USED.ordinal();
    /** The headers, in column order, read from the enum. */
    public static final String[] COLS = java.util.Arrays.stream(AIAssistantUtil.ProviderKeysColumn.values())
            .map(AIAssistantUtil.ProviderKeysColumn::getDisplayName).toArray(String[]::new);

    public static final String UNNAMED = "Unnamed key";
    public static final String CHOOSE = "choose provider";

    private List<Row> rows = List.of();

    /** A row from a key's facts: a blank name reads {@link #UNNAMED}, an unknown provider {@link #CHOOSE}. */
    public static Row row(APIKey<String> key, String name, String knownProvider, String endpoint, int usedBy) {
        return new Row(key,
                SUS.trimOrNull(name) != null ? name.trim() : UNNAMED,
                SUS.trimOrNull(knownProvider) != null ? knownProvider.trim() : CHOOSE,
                SUS.trimOrNull(endpoint) != null ? endpoint.trim() : "",
                usedBy);
    }

    public void setRows(List<Row> keys) {
        rows = keys == null ? List.of() : new ArrayList<>(keys);
        fireTableDataChanged();
    }

    public Row rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return AIAssistantUtil.ProviderKeysColumn.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return AIAssistantUtil.ProviderKeysColumn.values()[column].getDisplayName();
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return AIAssistantUtil.ProviderKeysColumn.values()[column] == AIAssistantUtil.ProviderKeysColumn.USED ? Integer.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (AIAssistantUtil.ProviderKeysColumn.values()[columnIndex]) {
            case NAME -> r.name();
            case PROVIDER -> r.provider();
            case ENDPOINT -> r.endpoint();
            case USED -> r.usedBy();
        };
    }
}
