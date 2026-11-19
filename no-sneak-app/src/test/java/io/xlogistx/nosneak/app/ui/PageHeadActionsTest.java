package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.gui.PagePanel;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The head of the pages built on gui-audio's {@code PagePanel} (2026-11-12; the maintainer, after
 * the Probe library, Probe groups and Scan history pages: "do the same for the chat, capture,
 * skills and providers"): the page's actions follow the title on its line, on the left, and none
 * is narrower than its preferred width, in the whole application at a wide and a narrow window,
 * in each theme. With {@code -Drender.dir} (or {@code RENDER_DIR}) every page is painted.
 */
class PageHeadActionsTest {

    private static final String OPERATOR = "operator.local", OPERATOR_PWD = "Operat0r-pass!";
    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        // not headless: the assistant's skill editor asks the toolkit for the menu shortcut key,
        // which a headless toolkit refuses; no window is opened, the shell is laid out and painted off screen
        FlatLaf.registerCustomDefaultsSource("themes");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(),
                new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null));
    }

    @AfterAll
    static void closeStore() {
        if (dsm != null) dsm.getDataStore().close();
    }

    @Test
    void theActionsFollowTheTitleAndKeepTheirWidth() throws Exception {
        NSAppUtil.Screen[] screens = {NSAppUtil.Screen.CHAT, NSAppUtil.Screen.CAPTURE, NSAppUtil.Screen.SKILLS,
                NSAppUtil.Screen.PROVIDERS, NSAppUtil.Screen.API_KEYS};
        for (NSAppUtil.Theme theme : NSAppUtil.Theme.values()) {
            AppContext ctx = new AppContext(dsm);
            ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
            try {
                AppShell shell = onEDT(() -> {
                    NoSneakMain.installLookAndFeel(theme);
                    AppShell s = new AppShell(ctx);
                    ctx.session().replayAuthenticated();
                    return s;
                });
                for (NSAppUtil.Screen screen : screens) {
                    for (int width : new int[]{1280, 760}) {
                        for (int pass = 0; pass < 2; pass++) {
                            onEDT(() -> {
                                ctx.nav().show(screen);
                                shell.setSize(width, 800);
                                for (int i = 0; i < 3; i++) layoutAll(shell);
                                return null;
                            });
                        }
                        String at = screen + ", " + theme + " at " + width;
                        // the header (2026-11-12, "move user and sign out to the left and make sign out
                        // does not shrink"): Sign out follows the subject on the left, whole
                        JButton signOut = find(shell, NSAppUtil.Shell.SIGN_OUT.getName());
                        assertNotNull(signOut, "Sign out is in the header");
                        Rectangle so = onEDT(() -> SwingUtilities.convertRectangle(signOut, new Rectangle(0, 0, signOut.getWidth(), signOut.getHeight()), shell));
                        assertTrue(so.width >= onEDT(() -> signOut.getPreferredSize().width), "Sign out is not shrunk: " + so + ", " + at);
                        assertTrue(so.x >= 0 && so.x + so.width <= width, "Sign out is inside the window: " + so + ", " + at);
                        assertTrue(so.x + so.width < 640, "Sign out is on the left: " + so + ", " + at);
                        // the bars (2026-11-14, "do the same to chat window left align", then "do the same
                        // for skills and providers"): the first button follows the count, the last is whole
                        String[] bar = screen == NSAppUtil.Screen.CHAT ? new String[]{"chatHistory.count", "chatHistory.open", "chatHistory.delete"}
                                : screen == NSAppUtil.Screen.SKILLS ? new String[]{"skills.count", "skills.edit", "skills.delete"}
                                : screen == NSAppUtil.Screen.PROVIDERS ? new String[]{"providers.count", "providers.edit", "providers.remove"} : null;
                        if (bar != null && width == 1280) {
                            JComponent count = find(shell, bar[0]);
                            JButton open = find(shell, bar[1]), delete = find(shell, bar[2]);
                            assertNotNull(count, bar[0]);
                            assertNotNull(open, bar[1]);
                            assertNotNull(delete, bar[2]);
                            int countEnd = onEDT(() -> SwingUtilities.convertPoint(count, count.getWidth(), 0, shell).x);
                            int openX = onEDT(() -> SwingUtilities.convertPoint(open, 0, 0, shell).x);
                            assertTrue(openX >= countEnd && openX - countEnd <= 16, bar[1] + " follows the count: " + countEnd + " then " + openX + ", " + at);
                            assertTrue(onEDT(delete::getWidth) >= onEDT(() -> delete.getPreferredSize().width), bar[2] + " is whole, " + at);
                        }
                        if (screen == NSAppUtil.Screen.CAPTURE) {
                            // each column's buttons follow its note (2026-11-14, "do the same for the capture page")
                            // and in a narrow column they wrap to a second line whole, never cut with dots
                            for (String[] col : new String[][]{{"capture.areas.note", "capture.areas.rename", "capture.areas.redraw", "capture.areas.remove"},
                                    {"capture.captures.note", "capture.captures.open", "capture.captures.send", "capture.captures.rename",
                                            "capture.captures.delete", "capture.captures.deleteAll"}}) {
                                JComponent note = find(shell, col[0]);
                                assertNotNull(note, col[0]);
                                Rectangle n = onEDT(() -> SwingUtilities.convertRectangle(note, new Rectangle(0, 0, note.getWidth(), note.getHeight()), shell));
                                for (int i = 1; i < col.length; i++) {
                                    JButton b = find(shell, col[i]);
                                    assertNotNull(b, col[i]);
                                    Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(b, new Rectangle(0, 0, b.getWidth(), b.getHeight()), shell));
                                    assertTrue(r.width >= onEDT(() -> b.getPreferredSize().width), col[i] + " is whole: " + r + ", " + at);
                                    assertTrue(r.x + r.width <= width, col[i] + " is inside the window: " + r + ", " + at);
                                    if (i == 1 && width == 1280) assertTrue(r.x >= n.x + n.width && r.x - (n.x + n.width) <= 16, col[i] + " follows the note: " + n + " then " + r + ", " + at);
                                }
                            }
                        }
                        PagePanel page = onEDT(() -> visiblePage(shell));
                        assertNotNull(page, "a PagePanel is showing: " + at);
                        JPanel titleLine = (JPanel) ((JPanel) page.getComponent(0)).getComponent(0);
                        assertTrue(titleLine.getComponentCount() > 1, "the page has an action: " + at);
                        Component title = titleLine.getComponent(0);
                        int pageX = onEDT(() -> SwingUtilities.convertPoint(page, 0, 0, shell).x);
                        int pageW = onEDT(page::getWidth);
                        Rectangle t = onEDT(() -> SwingUtilities.convertRectangle(title, new Rectangle(0, 0, title.getWidth(), title.getHeight()), shell));
                        int x = t.x;
                        for (int i = 1; i < titleLine.getComponentCount(); i++) {
                            Component action = titleLine.getComponent(i);
                            Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(action, new Rectangle(0, 0, action.getWidth(), action.getHeight()), shell));
                            int mid = t.y + t.height / 2;
                            assertTrue(x < r.x, "after the title, in order: action " + i + ", " + at);
                            assertTrue(r.y <= mid && mid <= r.y + r.height, "on the title's line: action " + i + ", " + at);
                            assertTrue(r.width >= onEDT(() -> action.getPreferredSize().width), "not shrunk: action " + i + ", " + at);
                            assertTrue(r.x + r.width <= pageX + pageW - 24, "inside the page: action " + i + " " + r + ", " + at);
                            if (width == 1280) assertTrue(r.x + r.width < pageX + pageW * 2 / 3, "on the left: action " + i + " " + r + ", " + at);
                            x = r.x;
                        }
                        render(shell, "page-" + screen.name().toLowerCase() + "-" + theme.name().toLowerCase() + "-" + width + ".png");
                    }
                }
                // pages with no head action: painted only, for a look at them beside the others
                for (NSAppUtil.Screen screen : new NSAppUtil.Screen[]{NSAppUtil.Screen.PROFILE, NSAppUtil.Screen.SETTINGS}) {
                    for (int width : new int[]{1280, 760}) {
                        for (int pass = 0; pass < 2; pass++) {
                            onEDT(() -> {
                                ctx.nav().show(screen);
                                shell.setSize(width, 800);
                                for (int i = 0; i < 3; i++) layoutAll(shell);
                                return null;
                            });
                        }
                        render(shell, "page-" + screen.name().toLowerCase() + "-" + theme.name().toLowerCase() + "-" + width + ".png");
                    }
                    // the whole page, past the fold: a window tall enough to show every block
                    for (int pass = 0; pass < 2; pass++) {
                        onEDT(() -> {
                            shell.setSize(1280, 1900);
                            for (int i = 0; i < 3; i++) layoutAll(shell);
                            return null;
                        });
                    }
                    render(shell, "page-" + screen.name().toLowerCase() + "-" + theme.name().toLowerCase() + "-tall.png");
                }
                // a selected API key: Edit and Delete follow its label (2026-11-14, "do the same for the api keys page")
                ctx.session().storeAPIKey("claude-" + theme.name().toLowerCase(), "The team's key", null, null, "sk-test-not-a-real-key",
                        "Claude", "https://api.anthropic.com", null, null, true);
                JTable keys = find(shell, NSAppUtil.ApiKeysPage.TABLE.getName());
                assertNotNull(keys, "the keys table");
                long until = System.currentTimeMillis() + 15_000;
                while (onEDT(keys::getRowCount) == 0 && System.currentTimeMillis() < until) Thread.sleep(50);
                assertTrue(onEDT(keys::getRowCount) > 0, "the stored key is listed, " + theme);
                for (int width : new int[]{1280, 760}) {
                    for (int pass = 0; pass < 2; pass++) {
                        onEDT(() -> {
                            ctx.nav().show(NSAppUtil.Screen.API_KEYS);
                            keys.setRowSelectionInterval(0, 0);
                            shell.setSize(width, 800);
                            for (int i = 0; i < 3; i++) layoutAll(shell);
                            return null;
                        });
                    }
                    String at = "API key detail, " + theme + " at " + width;
                    JComponent title = find(shell, NSAppUtil.ApiKeysPage.KEY_TITLE.getName());
                    JButton edit = find(shell, NSAppUtil.ApiKeysPage.EDIT.getName());
                    assertNotNull(title, "the key's label");
                    assertNotNull(edit, "the key's Edit");
                    JButton delete = (JButton) onEDT(() -> edit.getParent().getComponent(edit.getParent().getComponentCount() - 1));
                    int titleEnd = onEDT(() -> SwingUtilities.convertPoint(title, title.getWidth(), 0, shell).x);
                    Rectangle e = onEDT(() -> SwingUtilities.convertRectangle(edit, new Rectangle(0, 0, edit.getWidth(), edit.getHeight()), shell));
                    Rectangle d = onEDT(() -> SwingUtilities.convertRectangle(delete, new Rectangle(0, 0, delete.getWidth(), delete.getHeight()), shell));
                    assertTrue(e.x >= titleEnd && e.x - titleEnd <= 16, "Edit follows the label: " + titleEnd + " then " + e + ", " + at);
                    assertTrue(d.x >= e.x + e.width && d.x - (e.x + e.width) <= 16, "Delete follows Edit: " + e + " then " + d + ", " + at);
                    assertTrue(e.width >= onEDT(() -> edit.getPreferredSize().width), "Edit is whole, " + at);
                    assertTrue(d.width >= onEDT(() -> delete.getPreferredSize().width), "Delete is whole, " + at);
                    render(shell, "page-api_keys-selected-" + theme.name().toLowerCase() + "-" + width + ".png");
                }
            } finally {
                ctx.session().logout();
            }
        }
    }

    // ---- helpers ----

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

    /** The PagePanel on screen: the walk follows visible children only, so a hidden card is skipped. */
    private static PagePanel visiblePage(Container root) {
        for (Component c : root.getComponents()) {
            if (!c.isVisible()) continue;
            if (c instanceof PagePanel p) return p;
            if (c instanceof Container k) {
                PagePanel hit = visiblePage(k);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    private static void render(JComponent c, String file) throws Exception {
        String dir = System.getProperty("render.dir", System.getenv("RENDER_DIR")); // the env form is for an IDE run
        if (dir == null) return;
        onEDT(() -> {
            BufferedImage img = new BufferedImage(c.getWidth(), c.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            c.paint(g);
            g.dispose();
            ImageIO.write(img, "png", new File(dir, file));
            return null;
        });
    }

    /**
     * One pass over the tree: everything invalidated, then laid out from the top down. Until
     * 2026-11-14 this recursed into every child twice per level, so the work doubled with each
     * level of nesting and the whole shell took about four minutes; the callers repeat the pass,
     * which is what a late size (a wrapping label's height) needs.
     */
    private static void layoutAll(Component c) {
        invalidateAll(c);
        layoutDown(c);
    }

    private static void invalidateAll(Component c) {
        c.invalidate();
        if (c instanceof Container k) for (Component child : k.getComponents()) invalidateAll(child);
    }

    private static void layoutDown(Component c) {
        if (c instanceof Container k) {
            k.doLayout();
            for (Component child : k.getComponents()) layoutDown(child);
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
