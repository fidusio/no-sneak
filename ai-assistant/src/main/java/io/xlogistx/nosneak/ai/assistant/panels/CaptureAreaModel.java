package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.CaptureArea;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * The Capture areas table of the Capture page (2026-10-26): one row per session capture area —
 * name (editable in place: a blank keeps the old name), the display it was drawn on and the
 * region. Pure: it holds the areas it is given; the set itself stays in the context.
 */
public class CaptureAreaModel extends AbstractTableModel {

    public static final String[] COLS = {"Area", "Display", "Region"};
    public static final int COL_NAME = 0, COL_DISPLAY = 1, COL_REGION = 2;

    public static final String UNTITLED = "Untitled area";

    private List<CaptureArea> rows = List.of();

    public void setRows(CaptureArea[] areas) {
        rows = areas == null ? List.of() : new ArrayList<>(List.of(areas));
        fireTableDataChanged();
    }

    public CaptureArea rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    /** The model row of that area (by identity), or -1. */
    public int indexOf(CaptureArea area) {
        for (int i = 0; i < rows.size(); i++)
            if (rows.get(i) == area) return i;
        return -1;
    }

    /** The row's name: the area's, or {@link #UNTITLED} when blank. */
    public static String title(CaptureArea area) {
        String t = SUS.trimOrNull(area.getName());
        return t != null ? t : UNTITLED;
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
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == COL_NAME;
    }

    /** The Area column's editor commits here: a trimmed non-blank value renames, anything else is ignored. */
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != COL_NAME) return;
        String name = aValue == null ? null : SUS.trimOrNull(aValue.toString());
        if (name == null) return;
        rows.get(rowIndex).setName(name);
        fireTableRowsUpdated(rowIndex, rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CaptureArea a = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_NAME -> title(a);
            case COL_DISPLAY -> SUS.trimOrNull(a.getDescription()) != null ? a.getDescription().trim() : "";
            case COL_REGION -> CaptureSupport.region(a.getCaptureArea());
            default -> "";
        };
    }
}
