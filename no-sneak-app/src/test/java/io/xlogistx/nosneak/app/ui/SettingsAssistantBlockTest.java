package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The Settings page's Assistant block (2026-10-31): the reply timeout spinner starts on the stored
 * value, moves in tens within the bounds, and reports every change in seconds. Paints the block
 * to {@code render.dir/settings-assistant.png} when that system property is set, so it can be
 * looked at; the OS preferences are never written here.
 */
class SettingsAssistantBlockTest {

    @Test
    void spinnerStartsOnTheValueAndReportsChanges() throws Exception {
        List<Integer> seen = new ArrayList<>();
        JPanel block = SubjectPanel.assistantBlock(AppPrefs.AI_TIMEOUT_DEFAULT, seen::add);
        JSpinner spinner = find(block, SubjectPanel.REPLY_TIMEOUT);
        assertNotNull(spinner, "the spinner is named for the harness");
        assertEquals(40, spinner.getValue(), "the default is the http library's own 40 s");

        spinner.setValue(200);
        assertEquals(List.of(200), seen);

        SpinnerNumberModel model = (SpinnerNumberModel) spinner.getModel();
        assertEquals(AppPrefs.AI_TIMEOUT_MIN, model.getMinimum());
        assertEquals(AppPrefs.AI_TIMEOUT_MAX, model.getMaximum());
        assertEquals(10, model.getStepSize());
        spinner.setValue(AppPrefs.AI_TIMEOUT_MAX);
        assertNull(model.getNextValue(), "no step past the ceiling");

        render(block, "settings-assistant.png");
    }

    @Test
    void anOutOfRangeStoredValueIsClampedBeforeTheSpinnerSeesIt() {
        assertEquals(AppPrefs.AI_TIMEOUT_MIN, AppPrefs.clampAiTimeout(1));
        assertEquals(AppPrefs.AI_TIMEOUT_MAX, AppPrefs.clampAiTimeout(5000));
        assertEquals(AppPrefs.AI_TIMEOUT_DEFAULT, AppPrefs.clampAiTimeout(AppPrefs.AI_TIMEOUT_DEFAULT));
        JSpinner spinner = find(SubjectPanel.assistantBlock(5000, _ -> {}), SubjectPanel.REPLY_TIMEOUT);
        assertEquals(AppPrefs.AI_TIMEOUT_MAX, spinner.getValue());
    }

    private static JSpinner find(Container root, String name) {
        for (Component c : root.getComponents()) {
            if (c instanceof JSpinner s && name.equals(s.getName())) return s;
            if (c instanceof Container inner) {
                JSpinner found = find(inner, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static void render(JComponent c, String file) throws Exception {
        String dir = System.getProperty("render.dir");
        if (dir == null) return;
        SwingUtilities.invokeAndWait(() -> {
            c.setSize(560, c.getPreferredSize().height + 24);
            layoutAll(c);
            BufferedImage img = new BufferedImage(c.getWidth(), c.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, img.getWidth(), img.getHeight());
            c.paint(g);
            g.dispose();
            try {
                ImageIO.write(img, "png", new File(dir, file));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static void layoutAll(Component c) {
        c.doLayout();
        if (c instanceof Container p) for (Component k : p.getComponents()) layoutAll(k);
    }
}
