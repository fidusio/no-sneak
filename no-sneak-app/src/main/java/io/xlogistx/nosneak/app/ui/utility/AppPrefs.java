package io.xlogistx.nosneak.app.ui.utility;

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
 * </ul>
 *
 * Readers return null when nothing is saved or the saved directory no longer exists; writers
 * ignore null and blank values.
 */
public final class AppPrefs {

    private static final Preferences PREFS = Preferences.userNodeForPackage(AppPrefs.class);
    static final String STORE_LOCATION = "store.location";
    static final String FILE_DIRECTORY = "file.directory";

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
