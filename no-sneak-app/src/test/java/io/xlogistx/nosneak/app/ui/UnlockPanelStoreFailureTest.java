package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NSAppUtil.UnlockPage;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A store that does not open (2026-11-12; the maintainer: "when you open the vault step catch
 * datastore open issues as when it fail the login window gets crooked"): whatever the opener
 * throws, an {@code Error} included, is reported under the store form as a wrapped reason, the
 * form keeps its width, Open is usable again and step 1 stays the active one. The same when the
 * store opens and the host cannot build the application on it. With {@code -Drender.dir} (or
 * {@code RENDER_DIR}) the screen is painted after each failure, in each theme.
 */
class UnlockPanelStoreFailureTest {

    /** What H2 says through the connection pool when another process holds the file: one long line with the path. */
    private static final String IN_USE = "Database may be already in use: \"D:/Users/operator/NoSneak/installations/office-segment/no-sneak.mv.db\". "
            + "Possible solutions: close all other connection(s); use the server mode [90020-232]";
    private static File dir;

    @BeforeAll
    static void anInstallation() throws Exception {
        System.setProperty("java.awt.headless", "true");
        FlatLaf.registerCustomDefaultsSource("themes");
        dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        // a real installation, closed again: the screen then offers Open, not Create
        ShiroDSDomainSecurityManager dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(),
                new NoSneakStore.FirstRun("operator.local", "Operat0r-pass!".toCharArray(), "", null, null));
        dsm.getDataStore().close();
    }

    @Test
    void theReasonIsAPlainSentenceOrTheCausesFirstLine() {
        RuntimeException pool = new RuntimeException("Failed to initialize pool: " + IN_USE, new SQLException(IN_USE));
        assertTrue(UnlockPanel.storeFailureReason(pool).startsWith("The database file is in use by another program"), "the driver's cause is found under the pool's wrapper");
        assertEquals("no vault at C:\\somewhere", UnlockPanel.storeFailureReason(new java.io.IOException("no vault at C:\\somewhere")));
        assertEquals("first line", UnlockPanel.storeFailureReason(new IllegalStateException("first line\n\tat some.Frame\n\tat another.Frame")));
        String blank = UnlockPanel.storeFailureReason(new NoClassDefFoundError());
        assertTrue(blank.contains("NoClassDefFoundError"), blank);
        String longOne = UnlockPanel.storeFailureReason(new IllegalStateException("word ".repeat(300)));
        assertTrue(longOne.length() <= UnlockPanel.FAILURE_MAX + 30 && longOne.endsWith("(the rest is in the log)"), longOne);
        // a path has no space to wrap at: it is broken after a separator, nothing is dropped
        String path = "the directory was D:\\dev\\data\\java\\projects\\no-sneak\\no-sneak-app\\target\\no-sneak-setup-test\\46ce0a11 and so on";
        String broken = UnlockPanel.breakLongWords(path);
        assertEquals(path, broken.replace("\n", ""), "only line breaks are added");
        for (String line : broken.split("\n")) {
            for (String word : line.split(" ")) assertTrue(word.length() <= UnlockPanel.WORD_MAX * 2, word);
        }
        assertTrue(broken.contains("\\\n"), "the break follows a separator: " + broken);
        assertEquals("short words stay as they are", UnlockPanel.breakLongWords("short words stay as they are"));
        RuntimeException loop = new RuntimeException("outer");
        loop.initCause(new RuntimeException("inner", loop));
        assertEquals("outer", UnlockPanel.storeFailureReason(loop), "a cause that points back does not hang");
    }

    @Test
    void aFailedOpenLeavesTheScreenInShape() throws Exception {
        Throwable[] failures = {
                new RuntimeException("Failed to initialize pool: " + IN_USE, new SQLException(IN_USE)),
                new IllegalStateException("the data store holds no no-sneak app: run H2PSetup command=setup on its vault, then open the installation again; "
                        + "the directory was " + dir + " and the message goes on well past the width of the form to prove that it wraps instead of stretching it"),
                new NoClassDefFoundError("org/h2/Driver"),
        };
        for (NSAppUtil.Theme theme : NSAppUtil.Theme.values()) {
            for (int i = 0; i < failures.length; i++) {
                Throwable failure = failures[i];
                UnlockPanel panel = onEDT(() -> {
                    NoSneakMain.installLookAndFeel(theme);
                    UnlockPanel p = new UnlockPanel((location, password, firstRun) -> {
                        if (failure instanceof Error e) throw e;
                        throw (RuntimeException) failure;
                    }, _ -> fail("nothing opened"));
                    p.setLocation(dir);
                    return p;
                });
                check(panel, theme, "open-" + i, "The store could not be opened.");
            }
            // the store opens, the host fails to build the application on it
            UnlockPanel panel = onEDT(() -> {
                UnlockPanel p = new UnlockPanel((location, password, firstRun) -> null, _ -> {
                    throw new IllegalStateException("the application could not be built: a page failed while it was laid out");
                });
                p.setLocation(dir);
                return p;
            });
            check(panel, theme, "host", "The store opened, but the application could not start on it.");
        }
    }

    private static void check(UnlockPanel panel, NSAppUtil.Theme theme, String what, String message) throws Exception {
        JPasswordField vault = find(panel, UnlockPage.VAULT_PASSWORD_FIELD.getName());
        JButton open = find(panel, UnlockPage.OPEN.getName());
        assertNotNull(vault);
        assertNotNull(open, "an installation is there, so the button is Open");
        layout(panel);
        Rectangle before = onEDT(() -> SwingUtilities.convertRectangle(vault, new Rectangle(0, 0, vault.getWidth(), vault.getHeight()), panel));
        int preferred = onEDT(() -> panel.getPreferredSize().width);

        onEDT(() -> {
            vault.setText("V4ult-pass!");
            open.doClick();
            return null;
        });
        long deadline = System.currentTimeMillis() + 15_000;
        while (onEDT(panel::getStoreFailure).isEmpty()) {
            assertTrue(System.currentTimeMillis() < deadline, "the failure is reported: " + what);
            Thread.sleep(50);
        }
        layout(panel);
        String at = what + ", " + theme;
        assertEquals(message, onEDT(panel::getStoreMessage), at);
        String reason = onEDT(panel::getStoreFailure);
        assertFalse(reason.contains("\n") || reason.contains("\tat "), "one paragraph, no stack trace: " + reason);
        assertFalse(onEDT(panel::isStoreOpen), "step 1 is still open: " + at);
        assertTrue(onEDT(open::isEnabled), "Open can be pressed again: " + at);
        Rectangle after = onEDT(() -> SwingUtilities.convertRectangle(vault, new Rectangle(0, 0, vault.getWidth(), vault.getHeight()), panel));
        assertEquals(before.x, after.x, "the form did not move: " + at);
        assertEquals(before.width, after.width, "the form did not get wider: " + at);
        assertEquals(preferred, onEDT(() -> panel.getPreferredSize().width), "the screen asks for the same width: " + at);
        JComponent label = find(panel, UnlockPage.STORE_FAILURE.getName());
        Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(label, new Rectangle(0, 0, label.getWidth(), label.getHeight()), panel));
        assertTrue(r.x >= 0 && r.x + r.width <= panel.getWidth(), "the reason is inside the window: " + r + ", " + at);
        Rectangle button = onEDT(() -> SwingUtilities.convertRectangle(open, new Rectangle(0, 0, open.getWidth(), open.getHeight()), panel));
        assertTrue(r.y + r.height <= button.y, "the reason ends above the button: " + r + " / " + button + ", " + at);
        render(panel, "unlock-failure-" + what + "-" + theme.name().toLowerCase() + ".png");
    }

    // ---- helpers ----

    private static void layout(JComponent panel) throws Exception {
        for (int pass = 0; pass < 3; pass++) {
            onEDT(() -> {
                panel.setSize(1100, 760);
                for (int i = 0; i < 3; i++) layoutAll(panel);
                return null;
            });
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T find(Container root, String name) {
        for (Component c : root.getComponents()) {
            if (name.equals(c.getName())) return (T) c;
            if (c instanceof Container k) {
                T hit = find(k, name);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    private static void render(JComponent c, String file) throws Exception {
        String out = System.getProperty("render.dir", System.getenv("RENDER_DIR")); // the env form is for an IDE run
        if (out == null) return;
        onEDT(() -> {
            BufferedImage img = new BufferedImage(c.getWidth(), c.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            c.paint(g);
            g.dispose();
            ImageIO.write(img, "png", new File(out, file));
            return null;
        });
    }

    private static void layoutAll(Component c) {
        c.invalidate();
        if (c instanceof Container k) {
            for (Component child : k.getComponents()) layoutAll(child);
            k.doLayout();
            for (Component child : k.getComponents()) layoutAll(child);
        }
    }

    private static <T> T onEDT(Callable<T> work) throws Exception {
        AtomicReference<T> out = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                out.set(work.call());
            } catch (Exception e) {
                failure.set(e);
            }
        });
        if (failure.get() != null) throw failure.get();
        return out.get();
    }
}
