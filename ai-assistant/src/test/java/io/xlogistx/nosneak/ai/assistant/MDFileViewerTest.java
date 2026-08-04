package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.model.AISkill;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards {@link MDFileViewer}'s commit/revert state machine — the guarantee the skills page
 * relies on: nothing reaches the caller until Save, a rejected save leaves the committed
 * baseline intact (so Cancel still restores the pre-edit values), and the metadata fields
 * (name / description / type) participate in dirty tracking and revert alongside the
 * markdown buffer.
 */
public class MDFileViewerTest {

    private static MDFileViewer editorWithMeta() {
        MDFileViewer v = new MDFileViewer();
        v.withName("Name", "orig-name");
        v.withDescription("Description", "orig-desc");
        v.withTypes("Type", List.of(AISkill.SkillType.values()),
                AISkill.SkillType.MD_SKILL, AISkill.SkillType::getName);
        v.setMarkdown("original text");
        return v;
    }

    @Test
    public void rejectedSaveLeavesBaselineIntact() {
        MDFileViewer v = editorWithMeta();
        AtomicInteger commits = new AtomicInteger();
        v.setOnCommit(d -> commits.incrementAndGet());
        v.setValidator(d -> false);

        v.getNameField().setText("");
        v.getEditor().setText("edited text");
        v.getSaveButton().doClick();

        assertEquals(0, commits.get(), "a rejected save must not deliver a document");
        assertTrue(v.isDirty(), "a rejected save must not commit the edits");

        v.getCancelButton().doClick();
        assertEquals("orig-name", v.getDocumentName(), "cancel must restore the pre-edit name");
        assertEquals("original text", v.getMarkdown(), "cancel must restore the pre-edit text");
    }

    @Test
    public void acceptedSaveCommitsAndDeliversDocument() {
        MDFileViewer v = editorWithMeta();
        AtomicReference<MDFileViewer.MDDocument> delivered = new AtomicReference<>();
        v.setOnCommit(delivered::set);
        v.setValidator(d -> d.getName() != null && !d.getName().isBlank());

        v.getNameField().setText("new-name");
        v.getEditor().setText("new text");
        v.getSaveButton().doClick();

        MDFileViewer.MDDocument doc = delivered.get();
        assertNotNull(doc, "an accepted save must deliver the document");
        assertEquals("new-name", doc.getName());
        assertEquals("orig-desc", doc.getDescription());
        assertEquals("new text", doc.getMarkdown());
        assertEquals(AISkill.SkillType.MD_SKILL, doc.<AISkill.SkillType>typeAs());
        assertFalse(v.isDirty(), "save commits — the editor is clean afterwards");

        v.getCancelButton().doClick();
        assertEquals("new-name", v.getDocumentName(), "cancel after save reverts to the saved state");
    }

    @Test
    public void cancelRevertsMetadataAndRunsHandler() {
        MDFileViewer v = editorWithMeta();
        AtomicInteger cancels = new AtomicInteger();
        v.setOnCancel(cancels::incrementAndGet);

        v.getNameField().setText("abandoned");
        v.getDescriptionField().setText("abandoned");
        v.getTypeCombo().setSelectedItem(AISkill.SkillType.PROMPT_SKILL);
        v.getEditor().setText("abandoned");
        v.getCancelButton().doClick();

        assertEquals(1, cancels.get());
        assertEquals("orig-name", v.getDocumentName());
        assertEquals("orig-desc", v.getDescription());
        assertEquals(AISkill.SkillType.MD_SKILL, v.<AISkill.SkillType>getSelectedType());
        assertEquals("original text", v.getMarkdown());
        assertFalse(v.isDirty());
    }

    @Test
    public void metadataEditsDriveDirtyTracking() {
        MDFileViewer v = editorWithMeta();
        assertFalse(v.isDirty(), "freshly populated editor starts clean");

        v.getNameField().setText("renamed");
        assertTrue(v.isDirty(), "a name edit alone must read as dirty");

        v.revert();
        assertFalse(v.isDirty());
        assertEquals("orig-name", v.getDocumentName());
    }

    @Test
    public void typeChangeAloneIsDirty() {
        MDFileViewer v = editorWithMeta();
        v.getTypeCombo().setSelectedItem(AISkill.SkillType.PROMPT_SKILL);
        assertTrue(v.isDirty(), "a type change alone must read as dirty");
    }

    @Test
    public void setMarkdownNullIsEmpty() {
        MDFileViewer v = new MDFileViewer();
        v.setMarkdown(null);
        assertEquals("", v.getMarkdown(), "a null skill content must load as an empty buffer");
    }

    @Test
    public void saveWithoutValidatorStillCommits() {
        MDFileViewer v = editorWithMeta();
        AtomicInteger commits = new AtomicInteger();
        v.setOnCommit(d -> commits.incrementAndGet());

        v.getEditor().setText("edited");
        v.getSaveButton().doClick();

        assertEquals(1, commits.get(), "the validator is optional — absent means always valid");
        assertFalse(v.isDirty());
    }
}
