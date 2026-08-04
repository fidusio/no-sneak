package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards the "Save as skill" bubble action: it exists only on assistant bubbles built with a
 * handler, and clicking it runs the handler. The user's own bubbles never get it — saving your
 * own prompt as a skill goes through the composer, not the transcript.
 */
public class ChatBubbleSaveAsSkillTest {

    private static JButton findSaveAsSkill(Component root) {
        if (root instanceof JButton b && "Save as skill".equals(b.getText())) return b;
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                JButton found = findSaveAsSkill(child);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    public void assistantBubbleWithHandlerCarriesClickableAction() {
        AtomicInteger runs = new AtomicInteger();
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, 120, 42, runs::incrementAndGet);

        JButton action = findSaveAsSkill(bubble);
        assertNotNull(action, "an assistant bubble built with a handler must carry the action");

        action.doClick();
        assertEquals(1, runs.get(), "clicking the action must run the handler");
    }

    @Test
    public void assistantBubbleWithoutHandlerHasNoAction() {
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, 120, 42);
        assertNull(findSaveAsSkill(bubble));
    }

    @Test
    public void userBubbleNeverCarriesTheAction() {
        JComponent bubble = AssistantUtil.chatBubble("my prompt", true, null, null, () -> {
        });
        assertNull(findSaveAsSkill(bubble), "user bubbles must not offer save-as-skill");
    }

    @Test
    public void actionAppearsEvenWithoutLatencyAndTokens() {
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, null, null, () -> {
        });
        assertNotNull(findSaveAsSkill(bubble),
                "a response with no latency/token detail still needs the action row");
    }
}
