package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards the "Save as skill" bubble action: it exists only on assistant bubbles built with a
 * handler, and clicking it runs the handler. The user's own bubbles never get it — saving your
 * own prompt as a skill goes through the composer, not the transcript.
 */
public class ChatBubbleSaveAsSkillTest {

    private static JButton findSaveAsSkill(Component root) {
        return findButton(root, "Save as skill");
    }

    private static JButton findButton(Component root, String text) {
        if (root instanceof JButton b && text.equals(b.getText())) return b;
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                JButton found = findButton(child, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    /** 2026-10-26: a host save target ("probe") is one more button on assistant bubbles only. */
    @Test
    public void assistantBubbleCarriesOneButtonPerSaveTarget() {
        AtomicInteger runs = new AtomicInteger();
        Map<String, Runnable> saveAs = new LinkedHashMap<>();
        saveAs.put("probe", runs::incrementAndGet);
        JComponent bubble = AssistantUtil.chatBubble("a reply", false, null, null, null, null, saveAs);

        JButton action = findButton(bubble, "Save as probe");
        assertNotNull(action, "an assistant bubble must offer every registered save target");
        assertNull(findSaveAsSkill(bubble), "no skill handler, no skill button");
        action.doClick();
        assertEquals(1, runs.get(), "clicking the target must run its action");
    }

    @Test
    public void userBubbleNeverCarriesASaveTarget() {
        Map<String, Runnable> saveAs = new LinkedHashMap<>();
        saveAs.put("probe", () -> {
        });
        JComponent bubble = AssistantUtil.chatBubble("my prompt", true, null, null, null, null, saveAs);
        assertNull(findButton(bubble, "Save as probe"));
    }

    @Test
    public void assistantBubbleWithHandlerCarriesClickableAction() {
        AtomicInteger runs = new AtomicInteger();
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, 120, 10, 32, runs::incrementAndGet);

        JButton action = findSaveAsSkill(bubble);
        assertNotNull(action, "an assistant bubble built with a handler must carry the action");

        action.doClick();
        assertEquals(1, runs.get(), "clicking the action must run the handler");
    }

    @Test
    public void assistantBubbleWithoutHandlerHasNoAction() {
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, 120, 10, 32);
        assertNull(findSaveAsSkill(bubble));
    }

    @Test
    public void userBubbleNeverCarriesTheAction() {
        JComponent bubble = AssistantUtil.chatBubble("my prompt", true, null, null, null, () -> {
        });
        assertNull(findSaveAsSkill(bubble), "user bubbles must not offer save-as-skill");
    }

    @Test
    public void actionAppearsEvenWithoutLatencyAndTokens() {
        JComponent bubble = AssistantUtil.chatBubble("**answer**", false, null, null, null, () -> {
        });
        assertNotNull(findSaveAsSkill(bubble),
                "a response with no latency/token detail still needs the action row");
    }
}
