package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.SkillsTableModel;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The Skills table's rows (2026-10-26): titles, the type's own name, trimmed descriptions, stamps. */
class SkillsTableModelTest {

    @Test
    void columnsAndValues() {
        AISkill recon = new AISkill("network-recon", "  What to look at first on a new segment  ", "# Recon\n");
        recon.setSkillType(AISkill.SkillType.MD_SKILL);
        recon.setGUID("g-1");
        AISkill blank = new AISkill("  ", null, "");
        SkillsTableModel m = new SkillsTableModel();
        m.setRows(List.of(recon, blank));

        assertEquals(SkillsTableModel.COLS.length, m.getColumnCount());
        assertEquals("network-recon", m.getValueAt(0, SkillsTableModel.COL_NAME));
        assertEquals("md skill", m.getValueAt(0, SkillsTableModel.COL_TYPE), "the type reads as the enum names itself");
        assertEquals("What to look at first on a new segment", m.getValueAt(0, SkillsTableModel.COL_DESCRIPTION));
        assertEquals(Long.class, m.getColumnClass(SkillsTableModel.COL_UPDATED), "updated sorts as a number");

        assertEquals(SkillsTableModel.UNTITLED, m.getValueAt(1, SkillsTableModel.COL_NAME));
        assertEquals("", m.getValueAt(1, SkillsTableModel.COL_TYPE), "an untyped skill shows no type");
        assertEquals("", m.getValueAt(1, SkillsTableModel.COL_DESCRIPTION));
        assertEquals(0, m.indexOf("g-1"));
        assertEquals(-1, m.indexOf(null));
        assertFalse(m.isCellEditable(0, 0));
        m.setRows(null);
        assertEquals(0, m.getRowCount());
    }
}
