package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.model.AIChat;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The composer's clear icon (2026-10-27, the X at the right end of the input box): hidden while the prompt is empty, shown as soon
 * as text arrives (typed or inserted by {@code setComposerText}), and a click empties the prompt
 * and hides itself again. Runs over a real {@link ChatPanel} on the in-memory repository.
 */
public class ChatPanelClearTest {

    private static <T extends Component> T find(Component root, Class<T> type, String name) {
        if (type.isInstance(root) && (name == null || name.equals(root.getName())))
            return type.cast(root);
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                T found = find(child, type, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    public void clearFollowsTheComposerAndEmptiesIt() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContextTest.MemoryRepository repo = new AssistantContextTest.MemoryRepository();
            AssistantContext ctx = new AssistantContext(null, repo);
            ChatPanel panel = new ChatPanel(ctx);
            // the conversation page is laid into its host when a chat becomes current
            ctx.setCurrentChat(repo.saveChat(new AIChat("posture")));
            JButton clear = find(panel, JButton.class, ChatPanel.CLEAR_PROMPT);
            JTextArea composer = find(panel, JTextArea.class, null);
            assertNotNull(clear, "the input box carries the clear icon");
            assertNotNull(clear.getIcon(), "an icon, no text");
            assertNotNull(composer);
            assertFalse(clear.isVisible(), "nothing to clear yet, no X");

            panel.setComposerText("grade 10.0.0.12");
            assertTrue(clear.isVisible(), "text in the composer shows the X");

            clear.doClick();
            assertEquals("", composer.getText(), "Clear empties the prompt");
            assertFalse(clear.isVisible(), "and it hides again");

            composer.setText("typed");
            assertTrue(clear.isVisible(), "typing shows it too");
        });
    }
}
