package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.CapturePanel;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The Capture page's <i>Hide window</i> box (2026-10-29): ticked by default, so Capture (N) hides
 * the application while the areas are shot as before; unticked, the window stays and the sweep
 * can shoot the application itself. The box drives {@link AssistantContext#isHideWindowOnCapture()},
 * which {@code CaptureSupport.shootAndSave} reads for both the page's Capture button and the chat's
 * send-time sweep. Runs over a real {@link CapturePanel} on the in-memory repository.
 */
public class CapturePanelHideWindowTest {

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
    public void hideWindowBoxDrivesTheContextFlag() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContextTest.MemoryRepository repo = new AssistantContextTest.MemoryRepository();
            AssistantContext ctx = new AssistantContext(null, repo);
            assertTrue(ctx.isHideWindowOnCapture(), "hiding the window is the default");

            CapturePanel panel = new CapturePanel(ctx);
            JCheckBox box = find(panel, JCheckBox.class, CapturePanel.HIDE_WINDOW);
            assertNotNull(box, "the Capture page carries the Hide window box");
            assertTrue(box.isSelected(), "ticked by default, as the context says");

            box.doClick();
            assertFalse(ctx.isHideWindowOnCapture(), "unticked: the window stays while the areas are shot");

            box.doClick();
            assertTrue(ctx.isHideWindowOnCapture(), "ticked again: hidden as before");
        });
    }

    @Test
    public void boxReadsTheContextOnBuild() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContext ctx = new AssistantContext(null, new AssistantContextTest.MemoryRepository());
            ctx.setHideWindowOnCapture(false);
            JCheckBox box = find(new CapturePanel(ctx), JCheckBox.class, CapturePanel.HIDE_WINDOW);
            assertNotNull(box);
            assertFalse(box.isSelected(), "a page built on a context with the flag off starts unticked");
        });
    }
}
