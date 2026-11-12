package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.scan.ReportView;
import io.xlogistx.nosneak.app.ui.scan.ScanFormPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.scan.data.ReportContent;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Live, opt-in</b> (environment variable {@code LIVE_SCAN_TARGET}, e.g. {@code 127.0.0.1}): the
 * real pages, the real Run button and the real engine on a throw-away store. A host discovery
 * of the target, then <i>Scan again</i> with the history bar's <i>Discovered hosts only</i> box
 * and probes ticked on the Scan page, then Run: the rerun must carry the ticked probes (the
 * maintainer, 2026-11-11: "you only scan the selected ones and the associated ports"). Prints
 * each run's command, probes, duration and open ports. Never runs in a normal suite: it puts
 * packets on a wire, so the target is the caller's choice.
 */
@EnabledIfEnvironmentVariable(named = "LIVE_SCAN_TARGET", matches = ".+")
class LiveDiscoveredRerunTest {

    @Test
    void aDiscoveredRerunKeepsTheTickedProbes() throws Exception {
        String target = System.getenv("LIVE_SCAN_TARGET").trim();
        System.setProperty("java.awt.headless", "true");
        FlatLaf.registerCustomDefaultsSource("themes");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory());
        ShiroDSDomainSecurityManager dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(),
                new NoSneakStore.FirstRun("operator.local", "Operat0r-pass!".toCharArray(), "", null, null));
        AppContext ctx = new AppContext(dsm);
        try {
            ctx.session().loginUsernamePassword("operator.local", "Operat0r-pass!".toCharArray());
            ScanPanel panel = onEDT(() -> {
                NoSneakMain.installLookAndFeel(NSAppUtil.Theme.LIGHT);
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
            JButton again = find(panel, NSAppUtil.ScanHistoryPage.AGAIN.getName());
            JCheckBox historyBox = find(panel, NSAppUtil.ScanHistoryPage.DISCOVERED_ONLY.getName());
            ScanFormPanel form = find(panel, NSAppUtil.ScanForm.PANEL.getName());
            JButton run = find(panel, NSAppUtil.ScanForm.RUN.getName());
            JCheckBox serviceDetection = find(panel, NSAppUtil.ScanForm.SERVICE_DETECTION.getName());
            await(() -> panel.probeCount() > 0, "the probes are loaded", 15);

            // 1. a host discovery, through the Run button
            onEDT(() -> {
                form.setCommand(target + " -sn");
                form.setScanName("live discovery");
                run.doClick();
                return null;
            });
            await(() -> table.getRowCount() == 1, "the discovery is saved", 120);
            print(ctx, "1. host discovery");

            // 2. probes ticked on the Scan page (Service detection = every probe)
            String only = System.getenv("LIVE_SCAN_PROBES"); // e.g. https-scan,ssh; unset = every probe
            onEDT(() -> {
                if (only != null && !only.isBlank()) panel.tickProbes(only);
                else serviceDetection.doClick();
                return null;
            });
            int ticked = onEDT(() -> panel.prepareRun().cfg().probeNames.size());
            assertTrue(ticked > 0, "probes are ticked");

            // 3. Scan History: the row, Discovered hosts only, Scan again
            onEDT(() -> {
                panel.show(ScanPanel.SECTION_HISTORY);
                table.setRowSelectionInterval(0, 0);
                historyBox.setSelected(true);
                again.doClick();
                return null;
            });
            await(() -> !form.getCommand().isEmpty() && !form.getCommand().contains("-sn"), "the discovered hosts are loaded", 30);
            ScanPanel.RunRequest request = onEDT(panel::prepareRun);
            System.out.println("LIVE loaded command: " + request.command());
            System.out.println("LIVE probes going to the engine: " + request.cfg().probeNames.size() + " (ticked before: " + ticked + ")");
            assertEquals(ticked, request.cfg().probeNames.size(), "the ticked probes survive the discovered rerun");
            assertNull(request.cfg().ports, "no port typed: the probes' ports");
            assertTrue(request.cfg().discovery, "each host is checked alive first");

            // 4. Run it
            onEDT(() -> {
                run.doClick();
                return null;
            });
            await(() -> table.getRowCount() == 2, "the rerun is saved", 300);
            print(ctx, "2. discovered rerun with probes");
        } finally {
            ctx.session().closeNio();
            ctx.session().logout();
            dsm.getDataStore().close();
        }
    }

    /** Prints the newest stored scan: command, probes, duration, hosts up and open ports. */
    private static void print(AppContext ctx, String label) {
        ReportContent newest = null;
        for (ReportContent r : ctx.session().getAllScanResults()) {
            if (newest == null || r.getCreationTime() > newest.getCreationTime()) newest = r;
        }
        assertNotNull(newest);
        ReportContent full = ctx.session().getScanResult(newest.getGUID());
        ReportView.Report report = ReportView.parse(full.getContent());
        Object probes = full.getProperties().getValue("probes");
        java.util.regex.Matcher d = java.util.regex.Pattern.compile("\"durationMs\"\\s*:\\s*(\\d+)").matcher(full.getContent());
        java.util.regex.Matcher w = java.util.regex.Pattern.compile("\"warnings\"\\s*:\\s*\\[[^\\]]*\\]").matcher(full.getContent());
        List<String> up = report.discoveredTargets();
        System.out.println("LIVE " + label + ": command=[" + full.getProperties().getValue("command") + "] probes=[" + probes
                + "] durationMs=" + (d.find() ? d.group(1) : "?") + " hostsUp=" + up
                + " openPorts=" + full.getProperties().getValue("openPorts") + (w.find() ? " " + w.group() : " no warnings"));
    }

    private static void await(Callable<Boolean> condition, String what, int seconds) throws Exception {
        long deadline = System.currentTimeMillis() + seconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            if (Boolean.TRUE.equals(onEDT(condition))) return;
            Thread.sleep(100);
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
