package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.FontSizeWidget;
import io.xlogistx.gui.UIFontSize;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The text size row on the unlock screen (2026-11-03): the control is there, named for the
 * harness, starts on the size in force, applies a turn at once to the whole application and
 * Reset takes it back to the look-and-feel base — the Settings page's contract, before sign-in.
 * With {@code -Drender.dir=…} the screen is painted to {@code unlock-text-size.png} there.
 */
public class UnlockPanelTextSizeTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void theRowAppliesAtOnceAndResetGoesBackToTheBase() throws Exception {
        try {
            UnlockPanel[] panel = new UnlockPanel[1];
            SwingUtilities.invokeAndWait(() -> {
                float base = UIFontSize.getBase();
                panel[0] = new UnlockPanel((location, password, firstRun) -> {
                    throw new IllegalStateException("not opened in this test");
                }, _ -> {});
                FontSizeWidget widget = find(panel[0], FontSizeWidget.class, UnlockPanel.TEXT_SIZE);
                JButton reset = find(panel[0], JButton.class, UnlockPanel.TEXT_SIZE_RESET);
                assertNotNull(widget, "the control is on the unlock screen, named for the harness");
                assertNotNull(reset, "with its Reset");
                assertNull(widget.getScope(), "it drives the whole application, like the Settings page's");
                assertEquals(Math.round(base), widget.getSpinner().getValue(), "starts on the size in force");

                widget.getSpinner().setValue(Math.round(base) + 3);
                assertEquals(Math.round(base) + 3f, UIFontSize.get(), "applied at once");
                assertEquals(Math.round(base) + 3f, UIManager.getFont("Label.font").getSize2D(), 0.01f, "the look and feel's fonts follow");

                reset.doClick();
                assertEquals(base, UIFontSize.get(), "Reset is the base");
                assertEquals(Math.round(base), widget.getSpinner().getValue(), "the control follows");
            });
            render(panel[0], "unlock-text-size.png");
        } finally {
            SwingUtilities.invokeAndWait(UIFontSize::reset);
        }
    }

    static <T> T find(Container root, Class<T> type, String name) {
        for (Component c : root.getComponents()) {
            if (type.isInstance(c) && name.equals(c.getName())) return type.cast(c);
            if (c instanceof Container inner) {
                T found = find(inner, type, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static void render(JComponent c, String file) throws Exception {
        String dir = System.getProperty("render.dir");
        if (dir == null) return;
        SwingUtilities.invokeAndWait(() -> {
            c.setSize(1100, 720);
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
