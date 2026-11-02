package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import io.xlogistx.gui.*;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.AISkill;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.util.GetName;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.blankTo;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

/**
 * The Skills page (re-laid out 2026-10-26 in the house list look, after Chat History and
 * Capture): a {@link PagePanel} head with the one primary action (New skill), a toolbar (search,
 * count, Edit / Delete on the selected row) and a styled table on {@link SkillsTableModel}, by
 * name; double-click edits. The one markdown editor is framed in a page of its own (New skill /
 * Edit skill) that replaces the list while it is open.
 */
public class SkillsPanel extends JPanel {
    private final AssistantContext ctx;

    private Consumer<AISkill> onSkillRemoved;

    /**
     * Extra destinations offered by the editor's type combo alongside the skill types, keyed by
     * the label shown there. The handler takes (name, content) rather than an {@code MDDocument}
     * so a host can register one without depending on this module's editor types.
     */
    private final Map<String, BiConsumer<String, String>> saveTargets = new LinkedHashMap<>();

    /**
     * Offers another destination in the editor's "Save as" combo, alongside the skill types.
     * Choosing it routes the editor's content to {@code handler} — as {@code (name, content)} —
     * instead of saving a skill.
     * <p>
     * The handler takes plain strings rather than an {@code MDDocument} so a host can register one
     * without depending on this module's editor types, and so this module never has to know what
     * the destination is. The app registers {@code "probe"} here.
     * <p>
     * Register before the editor is <i>opened</i>, not before it is built — the combo is rebuilt
     * on every open precisely so late registrations appear.
     */
    public void addSaveTarget(String label, BiConsumer<String, String> handler) {
        if (label != null && handler != null) saveTargets.put(label, handler);
    }

    public SkillsPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setName(AIAssistantUtil.SkillsPage.PAGE.getName());
        setLayout(new BorderLayout());
        add(buildSkillCards());
    }

    public void setOnSkillRemoved(Consumer<AISkill> onSkillRemoved) {
        this.onSkillRemoved = onSkillRemoved;
    }

    private final CardStack skillsCards = new CardStack();
    private final JPanel editorHost = new JPanel(new BorderLayout());
    private final SkillsTableModel skillsModel = new SkillsTableModel();
    private final JTable skillsTable = new JTable(skillsModel);
    private final TableRowSorter<SkillsTableModel> skillsSorter = new TableRowSorter<>(skillsModel);
    private final JLabel skillsCount = new JLabel();
    private MDEditorPanel skillEditor;
    private AISkill selectedSkill;

    /**
     * Two cards: {@code "list"} (the page with the table) and {@code "editor"} (the one
     * {@link MDEditorPanel}, re-framed in a titled page on every open by {@link #showEditorPage}).
     */
    public JComponent buildSkillCards() {
        skillsCards.add(buildSkillPanel(), "list");
        skillEditor = buildSkillEditor();
        skillsCards.add(editorHost, "editor");
        skillsCards.show("list");
        return skillsCards.view();
    }

    public JPanel buildSkillPanel() {
        PagePanel page = new PagePanel(AIAssistantUtil.Page.SKILLS.getDisplayName(), AIAssistantUtil.SkillsPage.SUBTITLE.getDisplayName());
        JButton newSkill = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), AIAssistantUtil.SkillsPage.NEW_SKILL));
        newSkill.addActionListener(_ -> onAddSkill());
        page.action(newSkill);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][]"));
        bar.setOpaque(false);
        JTextField search = GUIUtil.applyProp(new JTextField(), AIAssistantUtil.SkillsPage.SEARCH);
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        GUIUtil.applyProp(skillsCount, AIAssistantUtil.SkillsPage.COUNT);
        skillsCount.setForeground(UITokens.muted());
        skillsCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(skillsCount);
        JButton edit = GUIUtil.applyProp(new JButton(new IconUtil.EditIcon(16)), AIAssistantUtil.SkillsPage.EDIT);
        JButton delete = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), AIAssistantUtil.SkillsPage.DELETE);
        delete.setForeground(UITokens.danger());
        for (JButton b : new JButton[]{edit, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            b.setEnabled(false);
            bar.add(b);
        }
        page.row(bar);

        GUIUtil.applyProp(skillsTable, AIAssistantUtil.SkillsPage.TABLE);
        Tables.style(skillsTable);
        Tables.width(skillsTable, SkillsTableModel.COL_NAME, 220);
        Tables.width(skillsTable, SkillsTableModel.COL_TYPE, 110);
        Tables.width(skillsTable, SkillsTableModel.COL_DESCRIPTION, 460);
        Tables.width(skillsTable, SkillsTableModel.COL_UPDATED, 140);
        skillsTable.getColumnModel().getColumn(SkillsTableModel.COL_TYPE).setCellRenderer(new MutedRenderer(false));
        skillsTable.getColumnModel().getColumn(SkillsTableModel.COL_UPDATED).setCellRenderer(new MutedRenderer(true));
        skillsTable.setRowSorter(skillsSorter);
        skillsSorter.setSortKeys(List.of(new RowSorter.SortKey(SkillsTableModel.COL_NAME, SortOrder.ASCENDING)));
        skillsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        skillsTable.getSelectionModel().addListSelectionListener(_ -> {
            boolean one = skillsTable.getSelectedRowCount() == 1;
            edit.setEnabled(one);
            delete.setEnabled(one);
        });
        skillsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) onEditSkill(selectedRow());
            }
        });
        edit.addActionListener(_ -> onEditSkill(selectedRow()));
        delete.addActionListener(_ -> onRemoveSkill(selectedRow()));
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            public void changedUpdate(DocumentEvent e) {
                filter();
            }

            private void filter() {
                String q = search.getText().trim();
                skillsSorter.setRowFilter(q.isEmpty() ? null : RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
                updateCount();
            }
        });
        JScrollPane scroll = new JScrollPane(skillsTable);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(UITokens.surface());
        page.card(scroll);
        updateCount();
        return page;
    }

    /** The selected skill, or null when no row is selected. */
    private AISkill selectedRow() {
        int row = skillsTable.getSelectedRow();
        return row < 0 ? null : skillsModel.rowAt(skillsTable.convertRowIndexToModel(row));
    }

    private void updateCount() {
        int shown = skillsTable.getRowCount();
        int all = skillsModel.getRowCount();
        skillsCount.setText(all == 0 ? AIAssistantUtil.SkillsPage.COUNT_EMPTY.getDisplayName() : shown == all ? all + (all == 1 ? " skill" : " skills") : shown + " of " + all + " skills");
    }

    /** The type column plain, or a {@code yyyy-MM-dd HH:mm} stamp; both muted like the scan history's. */
    private static final class MutedRenderer extends DefaultTableCellRenderer {
        private final boolean stamp;

        MutedRenderer(boolean stamp) {
            this.stamp = stamp;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (stamp) setText(value instanceof Long l ? timestamp(l) : "");
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
    }

    public MDEditorPanel buildSkillEditor() {
        MDEditorPanel editor = GUIUtil.applyProp(new MDEditorPanel(), AIAssistantUtil.SkillEditor.EDITOR);
        editor.setTitle(AIAssistantUtil.SkillEditor.TITLE.getDisplayName());
        editor.withName(AIAssistantUtil.SkillEditor.NAME.getDisplayName(), "");
        editor.withDescription(AIAssistantUtil.SkillEditor.DESCRIPTION.getDisplayName(), "");
        UITokens.primary(editor.getSaveButton()).setIcon(new IconUtil.SaveIcon(16, Color.WHITE)); // the page's primary, like Create / Save on the chat forms
        editor.setValidator(this::validateSkill);
        editor.setOnCommit(this::onSaveSkill);
        editor.setOnCancel(() -> {
            selectedSkill = null;
            skillsCards.show("list");
        });
        return editor;
    }

    /** Frames the one editor in a titled page and shows it; the editor keeps its own Save / Cancel. */
    private void showEditorPage(AIAssistantUtil.SkillEditor framing) {
        PagePanel page = new PagePanel(framing.getDisplayName(), framing.getDescription());
        page.setName(framing.getName());
        page.card(skillEditor);
        editorHost.removeAll();
        editorHost.add(page, BorderLayout.CENTER);
        editorHost.revalidate();
        editorHost.repaint();
        skillsCards.show("editor");
    }

    /**
     * A skill needs a name. A registered save target does not: it validates its own content
     * (a probe takes its name from the JSON, for instance) and reports its own failure, so a
     * skill-worded refusal there would be both wrong and misleading.
     */
    private boolean validateSkill(MDEditorPanel.MDDocument document) {
        if (!(document.getType() instanceof AISkill.SkillType)) {
            return true;
        }
        String name = document.getName() != null ? document.getName().trim() : "";
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Give the skill a name before saving.",
                    AIAssistantUtil.SkillsPage.NAME_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    private void onSaveSkill(MDEditorPanel.MDDocument document) {
        Object type = document.getType();
        if (!(type instanceof AISkill.SkillType)) {
            String label = targetLabel(type);
            BiConsumer<String, String> target = saveTargets.get(label);
            if (target != null) {
                // Editing an existing skill and sending its text elsewhere leaves the skill
                // unchanged. Say so before the edits go somewhere the subject did not expect.
                if (selectedSkill != null) {
                    int ok = JOptionPane.showConfirmDialog(this,
                            "Save this text as a " + label + " instead of updating skill \""
                                    + blankTo(selectedSkill.getName(), SkillsTableModel.UNTITLED)
                                    + "\"?\nThe skill itself will not be changed.",
                            AIAssistantUtil.SkillsPage.SAVE_AS_DIALOG.getDisplayName() + " " + label, JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
                    if (ok != JOptionPane.OK_OPTION) {
                        skillEditor.markDirty();
                        return;
                    }
                }
                try {
                    target.accept(document.getName() != null ? document.getName().trim() : "",
                                  document.getMarkdown());
                } catch (RuntimeException refused) {
                    // The target did not accept the content: the editor stays open, dirty,
                    // with the text intact, and the reason is the target's own message.
                    skillEditor.markDirty();
                    JOptionPane.showMessageDialog(this, refused.getMessage(),
                            AIAssistantUtil.SkillsPage.NOT_VALID_DIALOG.getDisplayName() + " " + label, JOptionPane.ERROR_MESSAGE);
                }
                return;
            }
        }
        AISkill skill = selectedSkill != null ? selectedSkill : new AISkill();
        String oldName = skill.getName();
        String oldDescription = skill.getDescription();
        AISkill.SkillType oldType = skill.getSkillType();
        String oldContent = skill.getContent();
        skill.setName(document.getName().trim());
        skill.setDescription(document.getDescription());
        skill.setSkillType(document.typeAs());
        skill.setContent(document.getMarkdown());

        BackgroundTask.runCatching(this, skillEditor.getSaveButton(), () -> {
            try {
                ctx.saveSkill(skill);
            } catch (Exception e) {
                skill.setName(oldName);
                skill.setDescription(oldDescription);
                skill.setSkillType(oldType);
                skill.setContent(oldContent);
                SwingUtilities.invokeLater(() -> {
                    skillEditor.markDirty();
                    refreshSkills();
                });
                throw e;
            }
        }, () -> {
            selectedSkill = null;
            refreshSkills();
            skillsCards.show("list");
        });
    }

    private void onAddSkill() {
        selectedSkill = null;
        showSkillEditor(null, AIAssistantUtil.SkillEditor.CREATE.getDisplayName());
    }

    private void onEditSkill(AISkill skill) {
        if (skill == null) return;
        selectedSkill = skill;
        showSkillEditor(skill, AIAssistantUtil.SkillEditor.SAVE.getDisplayName());
    }

    private void showSkillEditor(AISkill skill, String saveText) {
        showSkillEditorFields(skill, saveText);
        showEditorPage(skill == null ? AIAssistantUtil.SkillEditor.PAGE_NEW : AIAssistantUtil.SkillEditor.PAGE_EDIT);
    }

    public boolean startSkillFromResponse(String markdown) {
        if (skillEditor != null && skillEditor.isDirty()) {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Discard the unsaved skill edits and start a new skill from this response?",
                    AIAssistantUtil.SkillsPage.UNSAVED_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) return false;
        }
        selectedSkill = null;
        showSkillEditorFields(null, AIAssistantUtil.SkillEditor.CREATE.getDisplayName());
        skillEditor.setMarkdown(markdown);
        showEditorPage(AIAssistantUtil.SkillEditor.PAGE_FROM_RESPONSE);
        return true;
    }

    private void showSkillEditorFields(AISkill skill, String saveText) {
        skillEditor.setSaveText(saveText);
        // Rebuilt per open, not once at construction: a host registers its save targets after
        // this panel is built, so a combo populated in buildSkillEditor would never show them.
        List<Object> targets = new ArrayList<>(List.of(AISkill.SkillType.values()));
        targets.addAll(saveTargets.keySet());
        skillEditor.withTypes(AIAssistantUtil.SkillEditor.TYPE.getDisplayName(), targets,
                skill != null && skill.getSkillType() != null ? skill.getSkillType() : AISkill.SkillType.MD_SKILL,
                SkillsPanel::targetLabel);
        skillEditor.setDocumentName(skill != null ? skill.getName() : "");
        skillEditor.setDescription(skill != null ? skill.getDescription() : "");
        skillEditor.setSelectedType(skill != null && skill.getSkillType() != null
                ? skill.getSkillType() : AISkill.SkillType.MD_SKILL);
        skillEditor.setMarkdown(skill != null ? skill.getContent() : "");
    }

    private static String targetLabel(Object value) {
        return value instanceof GetName named ? named.getName() : String.valueOf(value);
    }

    private void onRemoveSkill(AISkill skill) {
        if (skill == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(SkillsTableModel.title(skill), "skill"),
                AIAssistantUtil.SkillsPage.DELETE_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> ctx.deleteSkill(skill), () -> {
            if (selectedSkill == skill) selectedSkill = null;
            if (onSkillRemoved != null) onSkillRemoved.accept(skill);
            refreshSkills();
        });
    }

    /** Re-reads the skills (EDT-safe) and keeps the selected row by GUID. */
    public void refreshSkills() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshSkills);
            return;
        }
        AISkill keep = selectedRow();
        skillsModel.setRows(ctx.getAllSkills());
        int model = keep == null ? -1 : skillsModel.indexOf(keep.getGUID());
        if (model >= 0) {
            int view = skillsTable.convertRowIndexToView(model);
            skillsTable.setRowSelectionInterval(view, view);
        }
        updateCount();
    }

    public void reset() {
        skillsCards.show("list");
        selectedSkill = null;
        if (skillEditor != null) showSkillEditorFields(null, AIAssistantUtil.SkillEditor.CREATE.getDisplayName());
    }
}
