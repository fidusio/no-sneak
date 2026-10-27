package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.CaptureArea;
import io.xlogistx.nosneak.ai.assistant.panels.CaptureAreaModel;
import io.xlogistx.nosneak.ai.assistant.panels.CaptureTableModel;
import io.xlogistx.nosneak.ai.model.AICapture;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The Capture page's two tables (2026-10-26): capture rows with thumbnails, and areas renamed in place. */
class CaptureModelsTest {

    private static AICapture capture(String name, String area, int w, int h, int bytes) {
        AICapture c = new AICapture();
        c.setName(name);
        c.setFromArea(area);
        c.setWidth(w);
        c.setHeight(h);
        c.setNumBytes(bytes);
        return c;
    }

    @Test
    void captureRows() {
        AICapture a = capture("Dashboard", "Area 1", 640, 360, 42_000);
        a.setGUID("g-1");
        AICapture b = capture("  ", null, 10, 10, 1);
        ImageIcon thumb = new ImageIcon(new BufferedImage(8, 6, BufferedImage.TYPE_INT_RGB));
        CaptureTableModel m = new CaptureTableModel();
        m.setRows(List.of(a, b), Map.of("g-1", thumb));

        assertEquals(CaptureTableModel.COLS.length, m.getColumnCount());
        assertSame(thumb, m.getValueAt(0, CaptureTableModel.COL_THUMB), "the thumbnail is looked up by GUID");
        assertEquals("Dashboard", m.getValueAt(0, CaptureTableModel.COL_NAME));
        assertEquals("Area 1", m.getValueAt(0, CaptureTableModel.COL_AREA));
        assertEquals("640x360", m.getValueAt(0, CaptureTableModel.COL_SIZE));
        assertEquals(42_000, m.getValueAt(0, CaptureTableModel.COL_BYTES));
        assertEquals(Long.class, m.getColumnClass(CaptureTableModel.COL_TAKEN), "taken sorts as a number");
        assertEquals(Icon.class, m.getColumnClass(CaptureTableModel.COL_THUMB));

        assertNull(m.getValueAt(1, CaptureTableModel.COL_THUMB), "no GUID, no thumbnail");
        assertEquals(CaptureTableModel.UNTITLED, m.getValueAt(1, CaptureTableModel.COL_NAME));
        assertEquals("", m.getValueAt(1, CaptureTableModel.COL_AREA));
        assertEquals(0, m.indexOf("g-1"));
        assertEquals(-1, m.indexOf("nope"));
        assertFalse(m.isCellEditable(0, CaptureTableModel.COL_NAME));
        assertEquals(2, m.rows().size());
        m.setRows(null, null);
        assertEquals(0, m.getRowCount());
    }

    @Test
    void areaRowsRenameInPlace() {
        CaptureArea one = new CaptureArea("Area 1", "Display 1", new Rectangle(120, 180, 640, 360));
        CaptureArea two = new CaptureArea("", null, null);
        CaptureAreaModel m = new CaptureAreaModel();
        m.setRows(new CaptureArea[]{one, two});

        assertEquals("Area 1", m.getValueAt(0, CaptureAreaModel.COL_NAME));
        assertEquals("Display 1", m.getValueAt(0, CaptureAreaModel.COL_DISPLAY));
        assertEquals("640x360 at 120,180", m.getValueAt(0, CaptureAreaModel.COL_REGION));
        assertEquals(CaptureAreaModel.UNTITLED, m.getValueAt(1, CaptureAreaModel.COL_NAME));
        assertEquals("", m.getValueAt(1, CaptureAreaModel.COL_DISPLAY));
        assertEquals("no area", m.getValueAt(1, CaptureAreaModel.COL_REGION));
        assertTrue(m.isCellEditable(0, CaptureAreaModel.COL_NAME));
        assertFalse(m.isCellEditable(0, CaptureAreaModel.COL_REGION));
        assertEquals(1, m.indexOf(two));

        m.setValueAt("  Office  ", 0, CaptureAreaModel.COL_NAME);
        assertEquals("Office", one.getName(), "the edit lands on the area, trimmed");
        m.setValueAt("   ", 0, CaptureAreaModel.COL_NAME);
        assertEquals("Office", one.getName(), "a blank keeps the old name");
        m.setValueAt("x", 0, CaptureAreaModel.COL_REGION);
        assertEquals("Office", one.getName(), "only the name column edits");
    }
}
