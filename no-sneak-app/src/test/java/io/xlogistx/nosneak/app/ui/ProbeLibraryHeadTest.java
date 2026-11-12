package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
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
 * The head of the Probe library, Probe groups and Scan history pages (2026-11-12; the
 * maintainer: "move write with assistant and New Probe to the left and make sure the New probe
 * button does not shrink", then "do the same for the probe groups page and scan history
 * page"): the buttons follow the title on its line, and at any window width each keeps its
 * preferred width, so its text is never cut. With {@code -Drender.dir} (or {@code RENDER_DIR}) the page is painted at each
 * width, in each theme.
 */
class ProbeLibraryHeadTest {

    private static final String OPERATOR = "operator.local", OPERATOR_PWD = "Operat0r-pass!";
    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        System.setProperty("java.awt.headless", "true");
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
    void theButtonsSitOnTheLeftAndKeepTheirWidth() throws Exception {
        for (NSAppUtil.Theme theme : NSAppUtil.Theme.values()) {
            AppContext ctx = new AppContext(dsm);
            ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
            try {
                ScanPanel panel = onEDT(() -> {
                    NoSneakMain.installLookAndFeel(theme);
                    CardLayout cards = new CardLayout();
                    JPanel host = new JPanel(cards);
                    Navigator nav = new Navigator(cards, host);
                    ctx.setNavigator(nav);
                    ScanPanel p = new ScanPanel(ctx, (t, n, c) -> {});
                    nav.register(NSAppUtil.Screen.PROBES, p, () -> p.show(ScanPanel.SECTION_PROBES));
                    nav.register(NSAppUtil.Screen.SCAN, p, () -> p.show(ScanPanel.SECTION_SCAN));
                    ctx.session().replayAuthenticated();
                    return p;
                });
                check(panel, theme, "scan", () -> panel.show(ScanPanel.SECTION_SCAN), null, NSAppUtil.ScanPage.NEW_SCAN);
                check(panel, theme, "library", () -> panel.show(ScanPanel.SECTION_PROBES),
                        NSAppUtil.ProbeLibraryPage.TITLE, NSAppUtil.ProbeLibraryPage.WRITE_WITH_ASSISTANT, NSAppUtil.ProbeLibraryPage.NEW_PROBE);
                check(panel, theme, "groups", panel::showProbeGroups,
                        NSAppUtil.ProbeGroupsPage.TITLE, NSAppUtil.ProbeGroupsPage.BACK, NSAppUtil.ProbeGroupsPage.NEW_GROUP);
                check(panel, theme, "history", () -> panel.show(ScanPanel.SECTION_HISTORY),
                        NSAppUtil.ScanHistoryPage.TITLE, NSAppUtil.ScanHistoryPage.NEW_SCAN);

                // the Scan form (2026-11-12, "fix the scan form width"): both cards end inside the page
                for (int width : new int[]{1000, 900}) {
                    settle(panel, () -> panel.show(ScanPanel.SECTION_SCAN), width, 760);
                    for (NSAppUtil.ScanForm card : new NSAppUtil.ScanForm[]{NSAppUtil.ScanForm.TARGET_CARD, NSAppUtil.ScanForm.SETUP_CARD}) {
                        JComponent c = find(panel, card.getName());
                        Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(c, new Rectangle(0, 0, c.getWidth(), c.getHeight()), panel));
                        assertTrue(r.x + r.width <= width - 24, card.getName() + " ends inside the page: " + r + ", " + theme + " at " + width);
                    }
                    for (NSAppUtil.ScanForm box : new NSAppUtil.ScanForm[]{NSAppUtil.ScanForm.SERVICE_DETECTION, NSAppUtil.ScanForm.DISCOVERY_ONLY,
                            NSAppUtil.ScanForm.SKIP_PING, NSAppUtil.ScanForm.UP_ONLY, NSAppUtil.ScanForm.OPEN_ONLY}) {
                        JComponent c = find(panel, box.getName());
                        assertNotNull(c, box.getName());
                        Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(c, new Rectangle(0, 0, c.getWidth(), c.getHeight()), panel));
                        assertTrue(r.x + r.width <= width - 24 && r.width >= onEDT(() -> c.getPreferredSize().width), box.getName() + " is whole and inside the page: " + r + ", " + theme + " at " + width);
                    }
                    render(panel, "scan-form-" + theme.name().toLowerCase() + "-" + width + ".png");
                }

                // the group editor (2026-11-12, "the save and cancel button sometimes it shrinks"):
                // on a page shorter than its checklist the two buttons keep their size
                JButton newGroup = find(panel, NSAppUtil.ProbeGroupsPage.NEW_GROUP.getName());
                for (int height : new int[]{760, 420, 300}) {
                    settle(panel, () -> {
                        panel.showProbeGroups();
                        newGroup.doClick();
                    }, 900, height);
                    for (NSAppUtil.ProbeGroupEditor name : new NSAppUtil.ProbeGroupEditor[]{NSAppUtil.ProbeGroupEditor.SAVE, NSAppUtil.ProbeGroupEditor.CANCEL}) {
                        JButton b = find(panel, name.getName());
                        assertNotNull(b, name.getName());
                        Dimension pref = onEDT(b::getPreferredSize);
                        Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(b, new Rectangle(0, 0, b.getWidth(), b.getHeight()), panel));
                        assertTrue(r.width >= pref.width && r.height >= pref.height, name.getName() + " keeps its size: " + r + " for " + pref + ", " + theme + " at height " + height);
                        assertTrue(r.y + r.height <= height, name.getName() + " is on the page: " + r + ", " + theme + " at height " + height);
                    }
                    render(panel, "group-editor-" + theme.name().toLowerCase() + "-" + height + ".png");
                }
            } finally {
                ctx.session().logout();
            }
        }
    }

    // ---- helpers ----

    /** Shows a card at a size and lays it out until it settles (resize listeners run between the EDT calls). */
    private static void settle(ScanPanel panel, Runnable show, int width, int height) throws Exception {
        onEDT(() -> {
            show.run();
            return null;
        });
        for (int pass = 0; pass < 3; pass++) {
            onEDT(() -> {
                panel.setSize(width, height);
                for (int i = 0; i < 3; i++) layoutAll(panel);
                return null;
            });
        }
    }

    /** The page's title, then its buttons in the given order, each at least as wide as it asks to be. */
    private static void check(ScanPanel panel, NSAppUtil.Theme theme, String page, Runnable show,
                              org.zoxweb.shared.util.GetName titleName, org.zoxweb.shared.util.GetName... buttonNames) throws Exception {
        // the Scan page's title has no constant of its own (it reads the Screen's): it is the first of its button's line
        Component title = titleName != null ? find(panel, titleName.getName())
                : ((JComponent) find(panel, buttonNames[0].getName())).getParent().getComponent(0);
        assertNotNull(title, page);
        for (int width : new int[]{1400, 1000, 640, 420}) {
            onEDT(() -> {
                show.run(); // the login's reset lands on the Scan card
                panel.setSize(width, 760);
                for (int i = 0; i < 3; i++) layoutAll(panel); // a wrapping bar settles its height on a later pass
                return null;
            });
            // the history bar re-arranges itself in a resize listener, which runs between two EDT calls
            for (int pass = 0; pass < 2; pass++) {
                onEDT(() -> {
                    for (int i = 0; i < 3; i++) layoutAll(panel);
                    return null;
                });
            }
            String at = page + ", " + theme + " at " + width;
            int x = onEDT(() -> SwingUtilities.convertPoint(title, 0, 0, panel).x);
            int y = onEDT(() -> SwingUtilities.convertPoint(title, 0, title.getHeight() / 2, panel).y);
            int end = 0;
            for (org.zoxweb.shared.util.GetName name : buttonNames) {
                JButton b = find(panel, name.getName());
                assertNotNull(b, name.getName());
                Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(b, new Rectangle(0, 0, b.getWidth(), b.getHeight()), panel));
                assertTrue(x < r.x, "in order, left to right: " + name.getName() + ", " + at);
                assertTrue(r.y <= y && y <= r.y + r.height, "on the title's line: " + name.getName() + ", " + at);
                assertTrue(r.width >= onEDT(() -> b.getPreferredSize().width), "not shrunk: " + name.getName() + ", " + at);
                x = r.x;
                end = r.x + r.width;
            }
            if (width == 1000) assertTrue(end < 650, "the buttons are on the left: " + at + ", they end at " + end);
            if ("history".equals(page)) {
                // the action bar (2026-11-12: "fix the scan history bar so the last button fits"):
                // every action is whole and inside the page's margins, on as many lines as it takes
                JTable table = find(panel, NSAppUtil.ScanHistoryPage.TABLE.getName());
                int tableTop = onEDT(() -> SwingUtilities.convertPoint(table.getParent().getParent(), 0, 0, panel).y);
                for (NSAppUtil.ScanHistoryPage action : new NSAppUtil.ScanHistoryPage[]{NSAppUtil.ScanHistoryPage.VIEW, NSAppUtil.ScanHistoryPage.AGAIN,
                        NSAppUtil.ScanHistoryPage.DISCOVERED_ONLY, NSAppUtil.ScanHistoryPage.COPY_COMMAND, NSAppUtil.ScanHistoryPage.COPY_RESULT,
                        NSAppUtil.ScanHistoryPage.SEND, NSAppUtil.ScanHistoryPage.DELETE, NSAppUtil.ScanHistoryPage.DELETE_ALL}) {
                    JComponent b = find(panel, action.getName());
                    assertNotNull(b, action.getName());
                    Rectangle r = onEDT(() -> SwingUtilities.convertRectangle(b, new Rectangle(0, 0, b.getWidth(), b.getHeight()), panel));
                    assertTrue(r.x >= 24 && r.x + r.width <= width - 24, "inside the page: " + action.getName() + " " + r + ", " + at);
                    assertTrue(r.width >= onEDT(() -> b.getPreferredSize().width), "not shrunk: " + action.getName() + ", " + at);
                    assertTrue(r.y + r.height <= tableTop, "above the table: " + action.getName() + " " + r + ", table at " + tableTop + ", " + at);
                }
            }
            render(panel, page + "-head-" + theme.name().toLowerCase() + "-" + width + ".png");
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

    /** Paints the panel as it is laid out to {@code render.dir/file}; nothing without the property. */
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
