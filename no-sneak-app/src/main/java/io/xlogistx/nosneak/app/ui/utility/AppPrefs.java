package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.gui.UIFontSize;
import io.xlogistx.nosneak.app.NSAppUtil;

import java.io.File;
import java.util.prefs.Preferences;

/**
 * The few settings that live <b>outside</b> the encrypted store, in {@link Preferences} of the
 * OS user (the registry on Windows, {@code ~/.java/.userPrefs} on Linux, the Java prefs plist on
 * macOS). They exist because the setup screen needs them before any vault is open; nothing
 * secret goes here — a vault password is never stored, only directories.
 *
 * <ul>
 *   <li>{@link #storeLocation()} — the installation directory the app last opened, offered on
 *       the setup screen so the subject only types the vault password.</li>
 *   <li>{@link #fileDirectory()} — where the backup / restore choosers last landed.</li>
 *   <li>{@link #aiTimeoutSeconds()} — the assistant's reply timeout (2026-10-31), set on the
 *       Settings page; per installation, like the rest, because a timeout is about this
 *       machine's connection rather than an account.</li>
 *   <li>{@link #theme()} — the look (2026-11-02, the Settings page's Appearance block): Light,
 *       or Dark, installed before the unlock screen and switched live.</li>
 *   <li>{@link #uiFontSize()} — the control text size in points (same day), applied before the
 *       unlock screen and whenever the Appearance block's control moves. Both are about this
 *       screen, not the account, and are needed before any login.</li>
 * </ul>
 *
 * Readers return null when nothing is saved or the saved directory no longer exists; writers
 * ignore null and blank values.
 */
public final class AppPrefs {

    private static final Preferences PREFS = Preferences.userNodeForPackage(AppPrefs.class);
    static final String STORE_LOCATION = "store.location";
    static final String FILE_DIRECTORY = "file.directory";
    static final String AI_TIMEOUT = "ai.timeout.seconds";
    static final String THEME = "ui.theme";
    static final String UI_FONT_SIZE = "ui.font.size";

    /** The reply timeout's default (the http library's own 40 s) and bounds, in seconds; the Settings spinner moves in tens. */
    public static final int AI_TIMEOUT_DEFAULT = 40, AI_TIMEOUT_MIN = 10, AI_TIMEOUT_MAX = 600;
    /** The control text size the app ships with, in points: the Roboto default font {@code NoSneakMain} installs. */
    public static final float UI_FONT_SIZE_DEFAULT = 13f;

    private AppPrefs() {}

    /** The installation directory of the last successful open or create, or null. */
    public static File storeLocation() {
        return existingDirectory(PREFS.get(STORE_LOCATION, null));
    }

    /** Records the installation directory; call only after the store opened. */
    public static void storeLocation(String location) {
        put(STORE_LOCATION, location);
    }

    /** The directory the file choosers last used, or null. */
    public static File fileDirectory() {
        return existingDirectory(PREFS.get(FILE_DIRECTORY, null));
    }

    /** Records the directory of a chosen file (the file's parent when given a file). */
    public static void fileDirectory(File chosen) {
        if (chosen == null) return;
        File dir = chosen.isDirectory() ? chosen : chosen.getAbsoluteFile().getParentFile();
        if (dir != null) put(FILE_DIRECTORY, dir.getAbsolutePath());
    }

    /** Seconds the assistant waits for a provider's reply; the default when nothing is stored, always within the bounds. */
    public static int aiTimeoutSeconds() {
        return clampAiTimeout(PREFS.getInt(AI_TIMEOUT, AI_TIMEOUT_DEFAULT));
    }

    /** Records the reply timeout, clamped to the bounds. */
    public static void aiTimeoutSeconds(int seconds) {
        PREFS.putInt(AI_TIMEOUT, clampAiTimeout(seconds));
    }

    public static int clampAiTimeout(int seconds) {
        return Math.max(AI_TIMEOUT_MIN, Math.min(AI_TIMEOUT_MAX, seconds));
    }

    /** The theme to install; {@link NSAppUtil.Theme#LIGHT} when nothing is stored or the stored name is unknown. */
    public static NSAppUtil.Theme theme() {
        return NSAppUtil.Theme.of(PREFS.get(THEME, null));
    }

    /** Records the theme by its name; null is ignored. */
    public static void theme(NSAppUtil.Theme theme) {
        if (theme != null) PREFS.put(THEME, theme.getName());
    }

    /** The control text size in points; the default when nothing is stored, always within {@code UIFontSize}'s bounds. */
    public static float uiFontSize() {
        return clampUiFontSize(PREFS.getFloat(UI_FONT_SIZE, UI_FONT_SIZE_DEFAULT));
    }

    /** Records the text size, clamped to the bounds. */
    public static void uiFontSize(float size) {
        PREFS.putFloat(UI_FONT_SIZE, clampUiFontSize(size));
    }

    /** {@code size} within {@link UIFontSize#MIN}..{@link UIFontSize#MAX}; the default for NaN. */
    public static float clampUiFontSize(float size) {
        return UIFontSize.clamp(Float.isNaN(size) ? UI_FONT_SIZE_DEFAULT : size);
    }

    private static File existingDirectory(String path) {
        if (path == null || path.isBlank()) return null;
        File dir = new File(path);
        return dir.isDirectory() ? dir : null;
    }

    private static void put(String key, String value) {
        if (value == null || value.isBlank()) return;
        PREFS.put(key, value.trim());
    }
}
