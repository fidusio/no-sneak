package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.ListSection;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.MDFileViewer;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.util.SUS;

import org.zoxweb.shared.util.GetName;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.blankTo;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;

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
        setLayout(new BorderLayout());
        add(buildSkillCards());
    }

    public void setOnSkillRemoved(Consumer<AISkill> onSkillRemoved) {
        this.onSkillRemoved = onSkillRemoved;
    }

    private final CardStack skillsCards = new CardStack();
    private ListSection<AISkill> skillsList;
    private MDFileViewer skillEditor;
    private AISkill selectedSkill;

    public JComponent buildSkillCards() {
        skillsCards.add(buildSkillPanel(), "list");
        skillsCards.add(buildSkillEditor(), "editor");

        skillsCards.show("list");
        return skillsCards.view();
    }

    public JPanel buildSkillPanel() {
        skillsList = ListSection.of(ctx::getAllSkills)
                .title("Skills")
                .addButton("+ New Skill", this::onAddSkill)
                .label(SkillsPanel::skillLabel)
                .sublabel(skill -> SUS.trimOrNull(skill.getDescription()))
                .onEdit(c -> () -> onEditSkill(c))
                .onRemove(c -> () -> onRemoveSkill(c))
                .emptyText("No Skills yet")
                .scrollable()
                .search("search")
                .build();

        return skillsList;
    }

    public JPanel buildSkillEditor() {
        skillEditor = new MDFileViewer();
        skillEditor.setTitle("Skill instructions");
        skillEditor.withName("Name", "");
        skillEditor.withDescription("Description", "");
        skillEditor.setValidator(this::validateSkill);
        skillEditor.setOnCommit(this::onSaveSkill);
        skillEditor.setOnCancel(() -> {
            selectedSkill = null;
            skillsCards.show("list");
        });
        return skillEditor;
    }

    /**
     * Name and type share the first line: the type decides whether the composer attaches the
     * skill or pastes it, so it belongs with the identity rather than down in the description.
     */
    private static String skillLabel(AISkill skill) {
        String name = blankTo(skill.getName(), "Untitled skill");
        AISkill.SkillType type = skill.getSkillType();
        return (type == null) ? name : name + "  ·  " + type.getName();
    }

    private boolean validateSkill(MDFileViewer.MDDocument document) {
        String name = document.getName() != null ? document.getName().trim() : "";
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Give the skill a name before saving.",
                    "Skill", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    private void onSaveSkill(MDFileViewer.MDDocument document) {
        Object type = document.getType();
        if (!(type instanceof AISkill.SkillType)) {
            BiConsumer<String, String> target = saveTargets.get(targetLabel(type));
            if (target != null) {
                target.accept(document.getName().trim(), document.getMarkdown());
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
        showSkillEditor(null, "Create");
    }

    private void onEditSkill(AISkill skill) {
        if (skill == null) return;
        selectedSkill = skill;
        showSkillEditor(skill, "Save");
    }

    private void showSkillEditor(AISkill skill, String saveText) {
        showSkillEditorFields(skill, saveText);
        skillsCards.show("editor");
    }

    public boolean startSkillFromResponse(String markdown) {
        if (skillEditor != null && skillEditor.isDirty()) {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Discard the unsaved skill edits and start a new skill from this response?",
                    "Unsaved skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) return false;
        }
        selectedSkill = null;
        showSkillEditorFields(null, "Create");
        skillEditor.setMarkdown(markdown);
        skillsCards.show("editor");
        return true;
    }

    private void showSkillEditorFields(AISkill skill, String saveText) {
        skillEditor.setSaveText(saveText);
        // Rebuilt per open, not once at construction: a host registers its save targets after
        // this panel is built, so a combo populated in buildSkillEditor would never show them.
        List<Object> targets = new ArrayList<>(List.of(AISkill.SkillType.values()));
        targets.addAll(saveTargets.keySet());
        skillEditor.withTypes("Save as", targets,
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
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(skill.getName(), "skill"),
                "Delete skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> ctx.deleteSkill(skill), () -> {
            if (selectedSkill == skill) selectedSkill = null;
            if (onSkillRemoved != null) onSkillRemoved.accept(skill);
            refreshSkills();
        });
    }

    public void refreshSkills() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshSkills);
            return;
        }
        if (skillsList != null) skillsList.refresh();
    }

    public void reset() {
        skillsCards.show("list");
        selectedSkill = null;
        if (skillEditor != null) showSkillEditorFields(null, "Create");
    }
}
