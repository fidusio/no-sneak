package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The Skills table (2026-10-26, the page's move to the house table look): one row per stored
 * skill — name, type (the {@code SkillType}'s own name: md skill / prompt skill), description,
 * last update. Pure: it holds the skills it is given.
 */
public class SkillsTableModel extends AbstractTableModel {

    /** The columns are {@link AIAssistantUtil.SkillsColumn}, in its order; the headers are the constants' display names. */
    public static final String[] COLS = Arrays.stream(AIAssistantUtil.SkillsColumn.values())
            .map(AIAssistantUtil.SkillsColumn::getDisplayName).toArray(String[]::new);
    public static final int COL_NAME = AIAssistantUtil.SkillsColumn.NAME.ordinal(),
            COL_TYPE = AIAssistantUtil.SkillsColumn.TYPE.ordinal(),
            COL_DESCRIPTION = AIAssistantUtil.SkillsColumn.DESCRIPTION.ordinal(),
            COL_UPDATED = AIAssistantUtil.SkillsColumn.UPDATED.ordinal();

    public static final String UNTITLED = "Untitled skill";

    private List<AISkill> rows = List.of();

    public void setRows(List<AISkill> skills) {
        rows = skills == null ? List.of() : new ArrayList<>(skills);
        fireTableDataChanged();
    }

    public AISkill rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    /** The model row of the skill with that GUID, or -1. */
    public int indexOf(String guid) {
        if (guid == null) return -1;
        for (int i = 0; i < rows.size(); i++)
            if (guid.equals(rows.get(i).getGUID())) return i;
        return -1;
    }

    /** The row's name: the skill's, or {@link #UNTITLED} when blank. */
    public static String title(AISkill skill) {
        String t = SUS.trimOrNull(skill.getName());
        return t != null ? t : UNTITLED;
    }

    /** The Type column: the skill type's name, or an empty string for an untyped skill. */
    public static String type(AISkill skill) {
        AISkill.SkillType type = skill.getSkillType();
        return type != null ? type.getName() : "";
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return AIAssistantUtil.SkillsColumn.values().length;
    }

    @Override
    public String getColumnName(int column) {
        return AIAssistantUtil.SkillsColumn.values()[column].getDisplayName();
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return AIAssistantUtil.SkillsColumn.values()[column] == AIAssistantUtil.SkillsColumn.UPDATED ? Long.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AISkill s = rows.get(rowIndex);
        return switch (AIAssistantUtil.SkillsColumn.values()[columnIndex]) {
            case NAME -> title(s);
            case TYPE -> type(s);
            case DESCRIPTION -> SUS.trimOrNull(s.getDescription()) != null ? s.getDescription().trim() : "";
            case UPDATED -> s.getLastTimeUpdated();
        };
    }
}
