package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.FontSizeWidget;
import io.xlogistx.gui.UIFontSize;
import io.xlogistx.nosneak.app.NSAppUtil;
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
 * The Settings page's Appearance block (2026-11-02, {@code PLAN-appearance.md}): the theme combo
 * starts on the theme in force, lists the two themes by their display names and hands a choice
 * on; while a scan runs it snaps back, stores nothing and says so. The text-size control applies
 * at once through gui-audio's {@code UIFontSize} and Reset goes back to the base. Paints the block
 * to {@code render.dir/settings-appearance.png} when that system property is set. The OS
 * preferences are never written here.
 */
class SettingsAppearanceBlockTest {

    @Test
    void theThemeComboStartsOnTheThemeInForceAndReportsAChoice() throws Exception {
        List<NSAppUtil.Theme> seen = new ArrayList<>();
        boolean[] busy = {false};
        JPanel block = SubjectPanel.appearanceBlock(NSAppUtil.Theme.DARK, seen::add, () -> busy[0]);
        JComboBox<?> combo = find(block, JComboBox.class, SubjectPanel.THEME);
        JLabel status = find(block, JLabel.class, SubjectPanel.THEME_STATUS);
        assertNotNull(combo, "the combo is named for the harness");
        assertNotNull(status);
        assertEquals(2, combo.getItemCount());
        assertEquals(NSAppUtil.Theme.LIGHT, combo.getItemAt(0));
        assertEquals(NSAppUtil.Theme.DARK, combo.getItemAt(1));
        assertEquals(NSAppUtil.Theme.DARK, combo.getSelectedItem(), "preselected from the stored theme");
        assertEquals(NSAppUtil.SettingsPage.THEME_NOTE.getDisplayName(), status.getText());
        assertTrue(seen.isEmpty(), "building the block applies nothing");

        combo.setSelectedItem(NSAppUtil.Theme.LIGHT);
        assertEquals(List.of(NSAppUtil.Theme.LIGHT), seen);
        combo.setSelectedItem(NSAppUtil.Theme.LIGHT);
        assertEquals(List.of(NSAppUtil.Theme.LIGHT), seen, "the theme in force again is not a switch");

        busy[0] = true;
        combo.setSelectedItem(NSAppUtil.Theme.DARK);
        assertEquals(NSAppUtil.Theme.LIGHT, combo.getSelectedItem(), "snapped back while a scan runs");
        assertEquals(List.of(NSAppUtil.Theme.LIGHT), seen, "nothing handed on");
        assertEquals(NSAppUtil.SettingsPage.THEME_BUSY.getDisplayName(), status.getText());

        busy[0] = false;
        combo.setSelectedItem(NSAppUtil.Theme.DARK);
        assertEquals(List.of(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.DARK), seen);
        assertEquals(NSAppUtil.SettingsPage.THEME_NOTE.getDisplayName(), status.getText(), "the standing note is back");

        render(block, "settings-appearance.png");
    }

    @Test
    void theTextSizeAppliesAtOnceAndResetGoesBackToTheBase() throws Exception {
        try {
            SwingUtilities.invokeAndWait(() -> {
                float base = UIFontSize.getBase();
                JPanel block = SubjectPanel.appearanceBlock(NSAppUtil.Theme.LIGHT, _ -> {}, () -> false);
                FontSizeWidget widget = find(block, FontSizeWidget.class, SubjectPanel.TEXT_SIZE);
                JButton reset = find(block, JButton.class, SubjectPanel.TEXT_SIZE_RESET);
                assertNotNull(widget, "the control is named for the harness");
                assertNotNull(reset);
                assertEquals(Math.round(base), widget.getSpinner().getValue(), "starts on the size in force");

                widget.getSpinner().setValue(Math.round(base) + 2);
                assertEquals(Math.round(base) + 2f, UIFontSize.get(), "applied at once");
                assertEquals(Math.round(base) + 2f, UIManager.getFont("Label.font").getSize2D(), 0.01f, "the look and feel's fonts follow");

                reset.doClick();
                assertEquals(base, UIFontSize.get(), "Reset is the base");
                assertEquals(Math.round(base), widget.getSpinner().getValue(), "the control follows a size set elsewhere");
            });
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
