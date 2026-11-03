package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import io.xlogistx.gui.UIFontSize;
import io.xlogistx.gui.UITokens;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The start-up order of {@code PLAN-appearance.md} (2026-11-02): {@code installLookAndFeel}
 * installs the theme and the 13-point default font, the stored text size is applied after it and
 * stays in force across a theme switch, and each theme file supplies the {@code xlogistx.*} tokens
 * (the dark ones differ from the light ones, so chips and cards do not stay light on a dark page);
 * Dark is FlatLaf's macOS Dark palette, which extends FlatDarkLaf and so reads the dark file.
 * The look and feel the JVM had is put back afterwards.
 */
class StartupLookAndFeelTest {

    @Test
    void theSizeAppliedAfterTheThemeStaysInForceAcrossASwitchAndTheTokensFollowTheTheme() throws Exception {
        LookAndFeel before = UIManager.getLookAndFeel();
        try {
            SwingUtilities.invokeAndWait(() -> {
                FlatLaf.registerCustomDefaultsSource("themes");
                NoSneakMain.installLookAndFeel(NSAppUtil.Theme.LIGHT);
                assertInstanceOf(FlatLightLaf.class, UIManager.getLookAndFeel());
                assertEquals(NoSneakMain.DEFAULT_FONT_SIZE, ((Font) UIManager.get("defaultFont")).getSize());
                Color lightOk = UIManager.getColor("xlogistx.okSoft");
                Color lightGround = UIManager.getColor("xlogistx.ground");
                assertNotNull(lightOk, "the light theme file pins the tokens");
                assertEquals(0xF4F4F7, lightGround.getRGB() & 0xFFFFFF, "the design's light value");
                assertEquals(0xE2E2E8, UIManager.getColor("Component.borderColor").getRGB() & 0xFFFFFF, "the light border moved with the theme");

                UIFontSize.apply(15f);
                assertEquals(15f, UIFontSize.get());
                assertEquals(15f, UIManager.getFont("Label.font").getSize2D(), 0.01f, "every look-and-feel font is scaled");

                NoSneakMain.installLookAndFeel(NSAppUtil.Theme.DARK);
                assertInstanceOf(FlatMacDarkLaf.class, UIManager.getLookAndFeel(), "Dark is the macOS Dark palette");
                assertEquals(15f, UIManager.getFont("Label.font").getSize2D(), 0.01f, "the size in force survives the switch");
                Color darkOk = UIManager.getColor("xlogistx.okSoft");
                assertNotNull(darkOk, "the dark theme file was read (mix() parsed)");
                assertNotEquals(lightOk, darkOk, "a dark value, not the light fallback");
                assertNotEquals(lightGround, UITokens.ground(), "UITokens reads the theme's key first");
                assertTrue(luminance(UITokens.ground()) < 0.2 && luminance(UITokens.text()) > 0.5, "a near-black ground, light text");
                assertTrue(luminance(UITokens.okSoft()) < 0.5 && luminance(UITokens.dangerSoft()) < 0.5, "the soft tints are dark too");
                for (String key : new String[]{"accent", "accentSoft", "accentText", "text", "muted", "border", "surface", "surfaceAlt",
                        "ground", "ok", "okSoft", "warn", "warnSoft", "danger", "dangerSoft", "neutral", "neutralSoft"}) {
                    assertNotNull(UIManager.getColor("xlogistx." + key), "dark: xlogistx." + key);
                }
                assertTrue(luminance(UITokens.surface()) < 0.5, "a dark card");
            });
        } finally {
            SwingUtilities.invokeAndWait(() -> {
                UIFontSize.reset();
                try {
                    UIManager.setLookAndFeel(before);
                } catch (UnsupportedLookAndFeelException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    private static double luminance(Color c) {
        return (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255d;
    }
}
