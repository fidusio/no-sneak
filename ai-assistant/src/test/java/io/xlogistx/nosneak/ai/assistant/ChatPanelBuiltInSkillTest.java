package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.model.AIChat;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The composer's built-in skills (2026-10-30): a host registers a reference text, the {@code +}
 * popup lists it under <i>Built-in skills</i> as a tick box, ticking it attaches the text as an
 * md skill for the next message (a chip, the + tooltip), unticking drops it, and the supplier
 * is read once. Runs over a real {@link ChatPanel} on the in-memory repository.
 */
public class ChatPanelBuiltInSkillTest {

    private static <T extends Component> void collect(Component root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        if (root instanceof Container c)
            for (Component child : c.getComponents()) collect(child, type, out);
    }

    private static JCheckBox box(JPopupMenu popup, String name) {
        List<JCheckBox> boxes = new ArrayList<>();
        collect(popup, JCheckBox.class, boxes);
        return boxes.stream().filter(b -> name.equals(b.getName())).findFirst().orElse(null);
    }

    private static JButton plusButton(ChatPanel panel) {
        List<JButton> buttons = new ArrayList<>();
        collect(panel, JButton.class, buttons);
        return buttons.stream()
                .filter(b -> b.getToolTipText() != null && b.getToolTipText().startsWith("Attach"))
                .findFirst().orElse(null);
    }

    @Test
    public void builtInSkillIsOfferedTickedAndDropped() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContextTest.MemoryRepository repo = new AssistantContextTest.MemoryRepository();
            AssistantContext ctx = new AssistantContext(null, repo);
            ChatPanel panel = new ChatPanel(ctx);
            ctx.setCurrentChat(repo.saveChat(new AIChat("probes")));

            assertNull(box(panel.buildAttachPopup(), ChatPanel.BUILT_IN_SKILL + "Probe definition"),
                    "nothing registered, no Built-in skills row");

            AtomicInteger reads = new AtomicInteger();
            panel.addBuiltInSkill("Probe definition", "the contract a probe file follows", () -> {
                reads.incrementAndGet();
                return "# Probe definition\n\nA probe is one JSON file.";
            });
            assertEquals(0, reads.get(), "registering reads nothing");
            assertFalse(panel.isBuiltInSkillAttached("Probe definition"));

            JCheckBox row = box(panel.buildAttachPopup(), ChatPanel.BUILT_IN_SKILL + "Probe definition");
            assertNotNull(row, "the popup offers the built-in skill");
            assertFalse(row.isSelected(), "not attached yet");
            assertEquals("the contract a probe file follows", row.getToolTipText());

            row.doClick();
            assertTrue(panel.isBuiltInSkillAttached("Probe definition"), "ticking attaches it");
            assertEquals(1, reads.get(), "the text is read on first use");
            JButton plus = plusButton(panel);
            assertNotNull(plus, "the + button");
            assertTrue(plus.getToolTipText().contains("Probe definition"), "the + tooltip names it: " + plus.getToolTipText());

            JCheckBox again = box(panel.buildAttachPopup(), ChatPanel.BUILT_IN_SKILL + "Probe definition");
            assertTrue(again.isSelected(), "a reopened popup shows it ticked");
            again.doClick();
            assertFalse(panel.isBuiltInSkillAttached("Probe definition"), "unticking drops it");

            assertTrue(panel.attachBuiltInSkill("Probe definition", true));
            assertEquals(1, reads.get(), "attached again, the text is not read twice");
            assertFalse(panel.attachBuiltInSkill("No such skill", true), "an unknown name attaches nothing");
        });
    }
}
