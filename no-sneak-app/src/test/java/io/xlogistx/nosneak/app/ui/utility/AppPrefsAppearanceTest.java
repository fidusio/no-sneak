package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.gui.UIFontSize;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The Appearance preferences (2026-11-02, {@code PLAN-appearance.md}): the theme resolves by its
 * stored name with Light for anything unknown, and the text size is clamped to gui-audio's bounds
 * with the shipped 13 points as the default. The OS preferences are never written by a test, so
 * the rules are pinned on the pure halves ({@code Theme.of}, {@code clampUiFontSize}).
 */
class AppPrefsAppearanceTest {

    @Test
    void aStoredThemeNameResolvesAndAnythingElseIsLight() {
        assertEquals(NSAppUtil.Theme.DARK, NSAppUtil.Theme.of("dark"));
        assertEquals(NSAppUtil.Theme.DARK, NSAppUtil.Theme.of("Dark"), "case does not matter");
        assertEquals(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.of("darcula"), "themes of an earlier build, dropped");
        assertEquals(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.of("mac-dark"));
        assertEquals(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.of("light"));
        assertEquals(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.of(null), "nothing stored");
        assertEquals(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.of("solarized"), "a name from another version");
        for (NSAppUtil.Theme t : NSAppUtil.Theme.values()) {
            assertSame(t, NSAppUtil.Theme.of(t.getName()), "what is stored is what comes back");
        }
    }

    @Test
    void theTwoThemesInOrderWithTheirWords() {
        assertEquals(List.of(NSAppUtil.Theme.LIGHT, NSAppUtil.Theme.DARK), List.of(NSAppUtil.Theme.values()));
        assertEquals("Light", NSAppUtil.Theme.LIGHT.getDisplayName());
        assertEquals("Dark", NSAppUtil.Theme.DARK.getDisplayName());
        assertFalse(NSAppUtil.Theme.LIGHT.isDark());
        assertTrue(NSAppUtil.Theme.DARK.isDark());
        for (NSAppUtil.Theme t : NSAppUtil.Theme.values()) assertFalse(t.getDescription().isBlank(), t + " explains itself");
    }

    @Test
    void theTextSizeIsClampedToTheWidgetsBoundsAndDefaultsToThirteen() {
        assertEquals(13f, AppPrefs.UI_FONT_SIZE_DEFAULT);
        assertEquals(NoSneakMain.DEFAULT_FONT_SIZE, AppPrefs.UI_FONT_SIZE_DEFAULT, "the default font the app installs");
        assertEquals(UIFontSize.MIN, AppPrefs.clampUiFontSize(2f));
        assertEquals(UIFontSize.MAX, AppPrefs.clampUiFontSize(99f));
        assertEquals(15f, AppPrefs.clampUiFontSize(15f));
        assertEquals(13f, AppPrefs.clampUiFontSize(Float.NaN), "a corrupt value reads as the default");
    }
}
