package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.scan.ScanFormPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.scan.data.ReportContent;
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
 * <b>Discovered hosts only</b> (2026-11-10; the maintainer: "a check box for rerunning the scan on
 * the discovered host, I don't want to execute host discovery again … you always check if the host
 * is alive before you probe, that is mandatory"), end to end on a real store: a stored discovery
 * scan of a /24 with two hosts up, the history bar's box ticked, <i>Scan again</i> — the form
 * holds those two hosts as targets with host discovery on and no {@code -sn}; unticked, the scan
 * comes back as it was defined. On the Scan page the form's own box follows the result shown.
 * With {@code -Drender.dir} (or the environment variable {@code RENDER_DIR}) both pages are painted under the app's look, in each theme.
 */
class ScanRerunDiscoveredTest {

    private static final String OPERATOR = "operator.local", OPERATOR_PWD = "Operat0r-pass!";
    private static final String REPORT = """
            {"scanner":"XNMap","startTime":"2026-11-10T09:14:02Z","durationMs":2100,"targets":254,"up":2,
             "command":"10.0.0.0/24 -sn","cancelled":false,
             "hosts":[
               {"host":"10.0.0.12","ip":"10.0.0.12","hostname":"nas.lan","up":true,"reason":"arp-reply","mac":"00:11:22:33:44:55","ports":[]},
               {"host":"10.0.0.23","ip":"10.0.0.23","up":true,"reason":"arp-reply","ports":[]},
               {"host":"10.0.0.9","up":false,"ports":[]}
             ]}""";
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
    void scanAgainOnTheDiscoveredHostsChecksOnlyThem() throws Exception {
        for (NSAppUtil.Theme theme : NSAppUtil.Theme.values()) {
            AppContext ctx = new AppContext(dsm);
            ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
            try {
                ctx.session().deleteAllScanResults();
                ReportContent r = new ReportContent();
                r.setName("Office segment");
                r.setDescription("10.0.0.0/24 -sn");
                r.setContent(REPORT);
                r.getProperties().build("command", "10.0.0.0/24 -sn");
                r.getProperties().build("hostsUp", "2");
                r.getProperties().build("openPorts", "0");
                ctx.session().saveScanResult(r);

                ScanPanel panel = onEDT(() -> {
                    NoSneakMain.installLookAndFeel(theme);
                    CardLayout cards = new CardLayout();
                    JPanel host = new JPanel(cards);
                    Navigator nav = new Navigator(cards, host);
                    ctx.setNavigator(nav);
                    ScanPanel p = new ScanPanel(ctx, (t, n, c) -> {});
                    nav.register(NSAppUtil.Screen.SCAN, p, () -> p.show(ScanPanel.SECTION_SCAN));
                    nav.register(NSAppUtil.Screen.SCAN_HISTORY, p, () -> p.show(ScanPanel.SECTION_HISTORY));
                    ctx.session().replayAuthenticated();
                    return p;
                });
                JTable table = find(panel, NSAppUtil.ScanHistoryPage.TABLE.getName());
                JCheckBox box = find(panel, NSAppUtil.ScanHistoryPage.DISCOVERED_ONLY.getName());
                JButton again = find(panel, NSAppUtil.ScanHistoryPage.AGAIN.getName());
                ScanFormPanel form = find(panel, NSAppUtil.ScanForm.PANEL.getName());
                JCheckBox formBox = find(panel, NSAppUtil.ScanForm.DISCOVERED_ONLY.getName());
                await(() -> table.getRowCount() == 1, "the stored scan is listed");

                // nothing selected: the box is greyed like the row actions
                assertFalse(onEDT(box::isEnabled));
                onEDT(() -> {
                    panel.show(ScanPanel.SECTION_HISTORY);
                    table.setRowSelectionInterval(0, 0);
                    return null;
                });
                assertTrue(onEDT(box::isEnabled));
                render(panel, "history-discovered-" + theme.name().toLowerCase() + ".png");

                // unticked: the scan as it was defined
                onEDT(() -> {
                    again.doClick();
                    return null;
                });
                assertEquals("10.0.0.0/24 -sn", onEDT(form::getCommand));

                // ticked: the two hosts found up, discovery on, the ports scanned
                onEDT(() -> {
                    box.setSelected(true);
                    again.doClick();
                    return null;
                });
                await(() -> "10.0.0.12 10.0.0.23".equals(form.getCommand()), "the discovered hosts are the targets");
                assertTrue(onEDT(() -> form.toConfig().discovery), "each host is checked again before it is scanned");
                assertNull(onEDT(() -> form.toConfig().ports), "-sn is dropped");
                assertEquals("Office segment", onEDT(form::getScanName));

                // the Scan page: the form's box follows the result on the page
                assertFalse(onEDT(formBox::isEnabled), "no result on the page yet");
                onEDT(() -> {
                    form.setCommand("10.0.0.0/24 -sn");
                    panel.showResult("Office segment", REPORT);
                    return null;
                });
                assertTrue(onEDT(formBox::isEnabled));
                onEDT(() -> {
                    formBox.doClick();
                    return null;
                });
                assertEquals("10.0.0.12 10.0.0.23", onEDT(form::getCommand));
                render(panel, "scan-discovered-" + theme.name().toLowerCase() + ".png");

                // the Targets area with more addresses than its rows hold, then empty
                StringBuilder many = new StringBuilder();
                for (int i = 1; i <= 60; i++) many.append("192.168.100.").append(i).append(' ');
                onEDT(() -> {
                    form.setCommand(many.toString().trim() + " -p 22,443");
                    return null;
                });
                assertEquals(60, onEDT(() -> form.toConfig().targets.size()));
                render(panel, "scan-many-" + theme.name().toLowerCase() + ".png");
                onEDT(() -> {
                    JButton clear = find(panel, NSAppUtil.ScanForm.TARGETS_CLEAR.getName());
                    clear.doClick();
                    return null;
                });
                assertEquals("-p 22,443", onEDT(form::getCommand));
                render(panel, "scan-empty-" + theme.name().toLowerCase() + ".png");
            } finally {
                ctx.session().logout();
            }
        }
    }

    // ---- helpers ----

    private static void await(Callable<Boolean> condition, String what) throws Exception {
        long deadline = System.currentTimeMillis() + 15_000;
        while (System.currentTimeMillis() < deadline) {
            if (Boolean.TRUE.equals(onEDT(condition))) return;
            Thread.sleep(50);
        }
        fail("timed out: " + what);
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

    /** Paints the panel's visible card to {@code render.dir/file}; nothing without the property. */
    private static void render(JComponent c, String file) throws Exception {
        String dir = System.getProperty("render.dir", System.getenv("RENDER_DIR")); // the env form is for an IDE run
        if (dir == null) return;
        onEDT(() -> {
            c.setSize(Integer.getInteger("render.width", System.getenv("RENDER_WIDTH") != null ? Integer.parseInt(System.getenv("RENDER_WIDTH")) : 1000), 760);
            layoutAll(c);
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
