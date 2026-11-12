package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.scan.ScanFormPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.scan.data.ProbeType;
import io.xlogistx.scan.data.ReportContent;
import io.xlogistx.scan.model.ProbeDefinition;
import io.xlogistx.scan.model.ProbeDefinitionLoader;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Run reads the form, every time</b> (2026-11-10; the maintainer: "when I run a saved probe the
 * scan is stale, it is not reading all the parameters like port, probes … whenever I hit scan
 * button read all the parameters and run the scan accordingly"). On a real store: a stored scan
 * is loaded with <i>Scan again</i>, and after every change — the Ports field, the chips, the
 * command, a probe edited in the library — what Run would hand the engine
 * ({@link ScanPanel#prepareRun}) is what the page shows.
 */
class ScanRunReadsTheFormTest {

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
    void runScansWhatThePageShows() throws Exception {
        AppContext ctx = new AppContext(dsm);
        ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            // two of the subject's probes that declare ports
            List<ProbeType> two = new ArrayList<>();
            for (ProbeType p : ctx.session().getAllProbes()) {
                ProbeDefinition d = ProbeDefinitionLoader.parse(p.getDefinition(), p.getName());
                if (d.getPorts() != null && d.getPorts().length > 0 && two.size() < 2) two.add(p);
            }
            assertEquals(2, two.size(), "the seeded probes");
            String n1 = two.get(0).getName(), n2 = two.get(1).getName();

            ctx.session().deleteAllScanResults();
            ReportContent r = new ReportContent();
            r.setName("Saved scan");
            r.setDescription("10.0.0.5 -p 8443 -sV");
            r.setContent("{\"scanner\":\"XNMap\",\"command\":\"10.0.0.5 -p 8443 -sV\",\"hosts\":[]}");
            r.getProperties().build("command", "10.0.0.5 -p 8443 -sV");
            r.getProperties().build("probes", n1 + ", " + n2);
            ctx.session().saveScanResult(r);

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
            ScanFormPanel form = find(panel, NSAppUtil.ScanForm.PANEL.getName());
            JTextComponent ports = find(panel, NSAppUtil.ScanForm.PORTS_FIELD.getName());
            JCheckBox serviceDetection = find(panel, NSAppUtil.ScanForm.SERVICE_DETECTION.getName());
            await(() -> table.getRowCount() == 1, "the stored scan is listed");
            await(() -> panel.probeCount() > 0, "the probes are loaded");

            // Scan again: the stored scan as it was defined
            onEDT(() -> {
                panel.show(ScanPanel.SECTION_HISTORY);
                table.setRowSelectionInterval(0, 0);
                again.doClick();
                return null;
            });
            ScanPanel.RunRequest run = onEDT(panel::prepareRun);
            assertEquals(List.of("10.0.0.5"), run.cfg().targets);
            assertArrayEquals(new int[]{8443}, run.cfg().ports, "the stored ports");
            assertTrue(run.cfg().probeScan);
            assertEquals(new TreeSet<>(List.of(n1, n2)), names(run), "the stored probes");
            assertEquals(new TreeSet<>(List.of(n1, n2)), new TreeSet<>(run.cfg().probeNames));
            assertEquals("Saved scan", run.name());
            assertEquals("10.0.0.5 -p 8443 -sV", run.command());

            // other ports typed in the field
            onEDT(() -> {
                ports.setText("9000-9001");
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertArrayEquals(new int[]{9000, 9001}, run.cfg().ports, "the typed ports");
            assertEquals("10.0.0.5 -p 9000-9001 -sV", run.command());
            assertEquals(new TreeSet<>(List.of(n1, n2)), names(run));

            // no ports: the ticked probes decide (the engine resolves them from a null list)
            onEDT(() -> {
                ports.setText("");
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertNull(run.cfg().ports);
            assertEquals("10.0.0.5 -sV", run.command());

            // the command edited by hand
            onEDT(() -> {
                form.setCommand("10.0.0.9 10.0.0.10 -p 21 -sV -T4");
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertEquals(List.of("10.0.0.9", "10.0.0.10"), run.cfg().targets);
            assertArrayEquals(new int[]{21}, run.cfg().ports);
            assertEquals(new TreeSet<>(List.of(n1, n2)), names(run), "the chips are not in the command and stay");

            // a --probes typed in the command never adds to the chips
            onEDT(() -> {
                form.setCommand("10.0.0.9 -p 21 -sV --probes nosuchprobe");
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertEquals(new TreeSet<>(List.of(n1, n2)), new TreeSet<>(run.cfg().probeNames), "only the chips");

            // a command that does not parse is refused, not scanned without what it carried
            onEDT(() -> {
                form.setCommand("10.0.0.9 -p 21 --no-such-flag");
                return null;
            });
            assertThrows(IllegalArgumentException.class, () -> onEDT(panel::prepareRun));
            onEDT(() -> {
                form.setCommand("10.0.0.9 10.0.0.10 -p 21 -sV -T4");
                return null;
            });

            // a probe edited in the library since: the run takes it as it is stored now
            ProbeType edited = two.get(0);
            String before = edited.getDefinition();
            ProbeDefinition def = ProbeDefinitionLoader.parse(before, n1);
            int oldPort = def.getPorts()[0];
            String changed = before.replaceFirst("(\"ports\"\\s*:\\s*\\[\\s*)" + oldPort + "\\b", "$165000");
            assertNotEquals(before, changed, "the definition names its port " + oldPort);
            edited.setDefinition(changed);
            ctx.session().saveProbe(edited);
            ProbeDefinition stored = ProbeDefinitionLoader.parse(ctx.session().getProbe(edited.getGUID()).getDefinition(), n1);
            assertTrue(java.util.Arrays.stream(stored.getPorts()).anyMatch(p -> p == 65000),
                    "the store holds the edit: " + n1 + " was " + oldPort + ", ports now " + java.util.Arrays.toString(stored.getPorts())
                            + ", definition " + changed);
            onEDT(() -> {
                panel.reloadProbes();
                return null;
            });
            await(() -> {
                for (ProbeDefinition d : panel.prepareRun().cfg().extraProbes) {
                    if (d.getName().equals(n1)) for (int p : d.getPorts()) if (p == 65000) return true;
                }
                return false;
            }, "the edited probe's port reaches the run");

            // Service detection unticked: no chip, no probing
            onEDT(() -> {
                serviceDetection.doClick();
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertFalse(run.cfg().probeScan);
            assertTrue(run.cfg().extraProbes.isEmpty());
            assertTrue(run.cfg().probeNames.isEmpty());
            assertEquals("", run.probeNames());
        } finally {
            ctx.session().logout();
        }
    }

    private static final String DISCOVERY_REPORT = """
            {"scanner":"XNMap","startTime":"2026-11-10T09:14:02Z","durationMs":2100,"targets":254,"up":2,
             "command":"10.0.0.0/24 -sn","cancelled":false,
             "hosts":[
               {"host":"10.0.0.12","ip":"10.0.0.12","up":true,"reason":"arp-reply","ports":[]},
               {"host":"10.0.0.23","ip":"10.0.0.23","up":true,"reason":"arp-reply","ports":[]},
               {"host":"10.0.0.9","up":false,"ports":[]}
             ]}""";

    /**
     * The maintainer's rule (2026-11-11): "when the discovered host is checked and probes are
     * selected you only scan the selected ones and the associated ports, unless the ports are
     * set specifically". Both ways in: the history bar's box and the Scan form's box.
     */
    @Test
    void discoveredHostsWithProbesScanOnlyTheProbesAndTheirPorts() throws Exception {
        AppContext ctx = new AppContext(dsm);
        ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            List<ProbeType> two = new ArrayList<>();
            for (ProbeType p : ctx.session().getAllProbes()) {
                ProbeDefinition d = ProbeDefinitionLoader.parse(p.getDefinition(), p.getName());
                if (d.getPorts() != null && d.getPorts().length > 0 && two.size() < 2) two.add(p);
            }
            assertEquals(2, two.size(), "the seeded probes");
            String n1 = two.get(0).getName(), n2 = two.get(1).getName();

            ctx.session().deleteAllScanResults();
            // a probing scan, saved with its probes; then a host discovery, saved with none
            ReportContent probing = new ReportContent();
            probing.setName("A probing scan");
            probing.setDescription("10.0.0.0/24 -sV");
            probing.setContent(DISCOVERY_REPORT);
            probing.getProperties().build("command", "10.0.0.0/24 -sV");
            probing.getProperties().build("probes", n1 + ", " + n2);
            ctx.session().saveScanResult(probing);
            Thread.sleep(20);
            ReportContent discovery = new ReportContent();
            discovery.setName("B discovery");
            discovery.setDescription("10.0.0.0/24 -sn");
            discovery.setContent(DISCOVERY_REPORT);
            discovery.getProperties().build("command", "10.0.0.0/24 -sn");
            ctx.session().saveScanResult(discovery);

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
            JCheckBox formBox = find(panel, NSAppUtil.ScanForm.DISCOVERED_ONLY.getName());
            JTextComponent ports = find(panel, NSAppUtil.ScanForm.PORTS_FIELD.getName());
            await(() -> table.getRowCount() == 2, "both scans are listed");
            await(() -> panel.probeCount() > 0, "the probes are loaded");
            int probingRow = -1, discoveryRow = -1;
            for (int i = 0; i < 2; i++) {
                int row = i;
                String name = String.valueOf(onEDT(() -> table.getValueAt(row, 0)));
                if (name.startsWith("A")) probingRow = i;
                else discoveryRow = i;
            }
            int pRow = probingRow, dRow = discoveryRow;
            TreeSet<String> both = new TreeSet<>(List.of(n1, n2));
            TreeSet<Integer> probePorts = new TreeSet<>();
            for (ProbeType p : two) {
                for (int port : ProbeDefinitionLoader.parse(p.getDefinition(), p.getName()).getPorts()) probePorts.add(port);
            }

            // the history bar's box on the probing scan
            onEDT(() -> {
                panel.show(ScanPanel.SECTION_HISTORY);
                table.setRowSelectionInterval(pRow, pRow);
                historyBox.setSelected(true);
                again.doClick();
                return null;
            });
            await(() -> "10.0.0.12 10.0.0.23 -sV".equals(form.getCommand()), "the discovered hosts are loaded");
            ScanPanel.RunRequest run = onEDT(panel::prepareRun);
            assertOnlyTheProbes(run, both, probePorts);

            // the same box on the host discovery, which saved no probe: the ticks on the page stay
            onEDT(() -> {
                panel.show(ScanPanel.SECTION_HISTORY);
                table.setRowSelectionInterval(dRow, dRow);
                historyBox.setSelected(true);
                again.doClick();
                return null;
            });
            await(() -> form.getCommand().startsWith("10.0.0.12 10.0.0.23") && !form.getCommand().contains("-sn")
                    && "B discovery".equals(form.getScanName()), "the discovered hosts are loaded");
            run = onEDT(panel::prepareRun);
            assertOnlyTheProbes(run, both, probePorts);

            // the Scan form's box over a discovery result on the page
            onEDT(() -> {
                form.setCommand("10.0.0.0/24 -sn");
                panel.showResult("B discovery", DISCOVERY_REPORT);
                formBox.doClick();
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertOnlyTheProbes(run, both, probePorts);

            // ports set specifically win
            onEDT(() -> {
                ports.setText("8080");
                return null;
            });
            run = onEDT(panel::prepareRun);
            assertArrayEquals(new int[]{8080}, run.cfg().ports);
            assertEquals(both, names(run));
            assertEquals(List.of("10.0.0.12", "10.0.0.23"), run.cfg().targets);
        } finally {
            ctx.session().logout();
        }
    }

    /** Only the two discovered hosts, alive-checked, only the ticked probes, no port typed: the engine takes the probes' ports. */
    private static void assertOnlyTheProbes(ScanPanel.RunRequest run, TreeSet<String> probes, TreeSet<Integer> probePorts) {
        assertEquals(List.of("10.0.0.12", "10.0.0.23"), run.cfg().targets);
        assertTrue(run.cfg().discovery, "each host is checked alive first");
        assertTrue(run.cfg().probeScan);
        assertFalse(run.cfg().bundledCatalog, "nothing but the ticked probes");
        assertEquals(probes, names(run));
        assertEquals(probes, new TreeSet<>(run.cfg().probeNames));
        assertNull(run.cfg().ports, "no port typed: the engine scans the probes' ports");
        TreeSet<Integer> resolved = new TreeSet<>();
        for (int p : io.xlogistx.scan.nmap.NMap.probePorts(run.cfg().extraProbes).tcp()) resolved.add(p);
        assertEquals(probePorts, resolved, "the ports the run covers");
    }

    private static TreeSet<String> names(ScanPanel.RunRequest run) {
        TreeSet<String> out = new TreeSet<>();
        for (ProbeDefinition d : run.cfg().extraProbes) out.add(d.getName());
        return out;
    }

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
