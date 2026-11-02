package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import io.xlogistx.nosneak.ai.model.AICapture;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Captures table of the Capture page (2026-10-26, the page's move to the house table look):
 * one row per stored capture — thumbnail, name, the area it came from, size, bytes, when it was
 * taken. Pure: it holds the projected rows and the thumbnails it is given (keyed by GUID).
 */
public class CaptureTableModel extends AbstractTableModel {

    /** The columns are {@link AIAssistantUtil.CaptureColumn}, in its order; the header is the constant's display name. {@code COLS} is that list of headers, kept for callers that read it. */
    public static final String[] COLS = java.util.Arrays.stream(AIAssistantUtil.CaptureColumn.values())
            .map(AIAssistantUtil.CaptureColumn::getDisplayName).toArray(String[]::new);
    public static final int COL_THUMB = AIAssistantUtil.CaptureColumn.THUMB.ordinal(),
            COL_NAME = AIAssistantUtil.CaptureColumn.NAME.ordinal(),
            COL_AREA = AIAssistantUtil.CaptureColumn.AREA.ordinal(),
            COL_SIZE = AIAssistantUtil.CaptureColumn.SIZE.ordinal(),
            COL_BYTES = AIAssistantUtil.CaptureColumn.BYTES.ordinal(),
            COL_TAKEN = AIAssistantUtil.CaptureColumn.TAKEN.ordinal();

    public static final String UNTITLED = "Untitled capture";

    private List<AICapture> rows = List.of();
    private Map<String, ImageIcon> icons = Map.of();

    public void setRows(List<AICapture> captures, Map<String, ImageIcon> thumbnails) {
        rows = captures == null ? List.of() : new ArrayList<>(captures);
        icons = thumbnails == null ? Map.of() : new HashMap<>(thumbnails);
        fireTableDataChanged();
    }

    public AICapture rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    /** A copy of the rows, in model order. */
    public List<AICapture> rows() {
        return new ArrayList<>(rows);
    }

    /** The model row of the capture with that GUID, or -1. */
    public int indexOf(String guid) {
        if (guid == null) return -1;
        for (int i = 0; i < rows.size(); i++)
            if (guid.equals(rows.get(i).getGUID())) return i;
        return -1;
    }

    /** The row's name: the capture's, or {@link #UNTITLED} when blank. */
    public static String title(AICapture capture) {
        String t = SUS.trimOrNull(capture.getName());
        return t != null ? t : UNTITLED;
    }

    /** {@code WxH} in pixels. */
    public static String size(AICapture capture) {
        return capture.getWidth() + "x" + capture.getHeight();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return AIAssistantUtil.CaptureColumn.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return AIAssistantUtil.CaptureColumn.values()[column].getDisplayName();
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (AIAssistantUtil.CaptureColumn.values()[column]) {
            case THUMB -> Icon.class;
            case BYTES -> Integer.class;
            case TAKEN -> Long.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AICapture c = rows.get(rowIndex);
        return switch (AIAssistantUtil.CaptureColumn.values()[columnIndex]) {
            case THUMB -> c.getGUID() != null ? icons.get(c.getGUID()) : null;
            case NAME -> title(c);
            case AREA -> SUS.trimOrNull(c.getFromArea()) != null ? c.getFromArea().trim() : "";
            case SIZE -> size(c);
            case BYTES -> c.getNumBytes();
            case TAKEN -> c.getCreationTime();
        };
    }
}
