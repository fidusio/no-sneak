package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.NSAppUtil.SignInForm;
import io.xlogistx.nosneak.app.NSAppUtil.UnlockPage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The unlock screen's Sign in / Register button has one fixed size (2026-11-18; the maintainer:
 * "make the sign in and register button fixed size, it's still getting shrunk"): the same width
 * under both labels, wide enough for the wider one, and kept in a narrow window.
 */
public class UnlockPanelSignButtonTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void theButtonKeepsOneSizeUnderBothLabelsAndInANarrowWindow() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            UnlockPanel panel = new UnlockPanel((location, password, firstRun) -> {
                throw new IllegalStateException("not opened in this test");
            }, _ -> {});

            JButton sign = UnlockPanelTextSizeTest.find(panel, JButton.class, SignInForm.SIGN_IN.getName());
            JButton toggle = UnlockPanelTextSizeTest.find(panel, JButton.class, SignInForm.TO_REGISTER.getName());
            assertNotNull(sign, "the Sign in button");
            assertNotNull(toggle, "the link that switches to Register");

            FontMetrics fm = sign.getFontMetrics(sign.getFont());
            int widestText = Math.max(fm.stringWidth(SignInForm.SIGN_IN.getDisplayName()),
                    fm.stringWidth(SignInForm.REGISTER.getDisplayName()));

            int asSignIn = sign.getPreferredSize().width;
            assertTrue(asSignIn > widestText, "wide enough for the wider label");
            assertEquals(sign.getPreferredSize(), sign.getMinimumSize(), "it never asks for less");
            assertEquals(asSignIn, laidOutWidth(panel, sign, 1100), "its size in a wide window");
            assertEquals(asSignIn, laidOutWidth(panel, sign, 640), "and in a narrow one");

            toggle.setEnabled(true); // step 2 is disabled until a store is open; none is opened here
            toggle.doClick();
            assertEquals(SignInForm.REGISTER.getDisplayName(), sign.getText(), "the same button, now Register");
            assertEquals(asSignIn, sign.getPreferredSize().width, "the same size under the other label");
            assertEquals(asSignIn, laidOutWidth(panel, sign, 1100));
            assertEquals(asSignIn, laidOutWidth(panel, sign, 640));
        });
    }

    @Test
    void theOpenButtonKeepsOneSizeAsOpenAndAsCreate(@org.junit.jupiter.api.io.TempDir java.io.File dir) throws Exception {
        java.io.File withVault = new java.io.File(dir, "with-vault");
        java.io.File empty = new java.io.File(dir, "empty");
        assertTrue(withVault.mkdirs() && empty.mkdirs());
        // the screen only looks for the vault file to choose between Open and Create
        assertTrue(new java.io.File(withVault, "no-sneak.store").createNewFile());

        SwingUtilities.invokeAndWait(() -> {
            UnlockPanel panel = new UnlockPanel((location, password, firstRun) -> {
                throw new IllegalStateException("not opened in this test");
            }, _ -> {});

            panel.setLocation(withVault);
            JButton open = UnlockPanelTextSizeTest.find(panel, JButton.class, UnlockPage.OPEN.getName());
            assertNotNull(open, "the Open button, on a directory that has a vault");
            assertEquals(UnlockPage.OPEN.getDisplayName(), open.getText());

            FontMetrics fm = open.getFontMetrics(open.getFont());
            int widestText = Math.max(fm.stringWidth(UnlockPage.OPEN.getDisplayName()),
                    fm.stringWidth(UnlockPage.CREATE.getDisplayName()));

            int asOpen = open.getPreferredSize().width;
            assertTrue(asOpen > widestText, "wide enough for the wider label");
            assertEquals(open.getPreferredSize(), open.getMinimumSize(), "it never asks for less");
            assertEquals(asOpen, laidOutWidth(panel, open, 1100), "its size in a wide window");
            assertEquals(asOpen, laidOutWidth(panel, open, 640), "and in a narrow one");

            panel.setLocation(empty);
            assertEquals(UnlockPage.CREATE.getDisplayName(), open.getText(), "the same button, now Create");
            assertEquals(asOpen, open.getPreferredSize().width, "the same size under the other label");
            assertEquals(asOpen, laidOutWidth(panel, open, 1100));
            assertEquals(asOpen, laidOutWidth(panel, open, 640));
        });
    }

    private static int laidOutWidth(JComponent root, JButton button, int width) {
        root.setSize(width, 720);
        invalidateAll(root);
        layoutAll(root);
        return button.getWidth();
    }

    private static void invalidateAll(Component c) {
        c.invalidate();
        if (c instanceof Container p) for (Component k : p.getComponents()) invalidateAll(k);
    }

    private static void layoutAll(Component c) {
        c.doLayout();
        if (c instanceof Container p) for (Component k : p.getComponents()) layoutAll(k);
    }
}
