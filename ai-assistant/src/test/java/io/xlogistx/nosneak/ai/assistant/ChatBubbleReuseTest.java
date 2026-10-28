package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The user bubble's copy icon (2026-10-27): built with a reuse handler, the bubble carries one
 * icon button and clicking it runs the handler (the chat puts the prompt back in the composer).
 * Assistant bubbles never get it, and a user bubble built without a handler has none.
 */
public class ChatBubbleReuseTest {

    private static JButton findNamed(Component root, String name) {
        if (root instanceof JButton b && name.equals(b.getName())) return b;
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                JButton found = findNamed(child, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    public void userBubbleWithHandlerCarriesOneClickableIcon() {
        AtomicInteger runs = new AtomicInteger();
        JComponent bubble = AssistantUtil.chatBubble("send it again", null, true, null, null, null,
                null, null, runs::incrementAndGet);

        JButton icon = findNamed(bubble, AssistantUtil.REUSE_PROMPT);
        assertNotNull(icon, "a user bubble built with a reuse handler must carry the icon");
        assertNotNull(icon.getIcon(), "it is an icon button, no text");
        assertNull(icon.getText() == null || icon.getText().isEmpty() ? null : icon.getText());
        icon.doClick();
        assertEquals(1, runs.get(), "clicking the icon must run the handler once");
    }

    @Test
    public void assistantBubbleNeverCarriesTheIcon() {
        JComponent bubble = AssistantUtil.chatBubble("a reply", "p · m", false, 120, 1, 2,
                null, null, () -> fail("never offered on a reply"));
        assertNull(findNamed(bubble, AssistantUtil.REUSE_PROMPT));
    }

    @Test
    public void userBubbleWithoutHandlerHasNoIcon() {
        JComponent bubble = AssistantUtil.chatBubble("my prompt", true, null, null, null);
        assertNull(findNamed(bubble, AssistantUtil.REUSE_PROMPT));
    }
}
