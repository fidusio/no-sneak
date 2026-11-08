package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.scan.nmap.NMap;
import io.xlogistx.scan.nmap.NMapConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The form is a view over the command: a command put in the field fills the form and comes back
 * out of {@code toConfig} unchanged, a configuration set on the form prints as its command, and
 * flags the form has no control for survive a round trip through it.
 */
public class ScanFormPanelTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void aTypedCommandFillsTheFormAndComesBackOut() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            String typed = "10.0.0.0/24 -p 1-1024 -sV -T5 --min-rtt-timeout 200 --up-only --open";
            form.setCommand(typed);
            NMapConfig cfg = form.toConfig();
            NMapConfig expected = NMap.parseCommand(typed);
            assertEquals(expected.targets, cfg.targets);
            assertArrayEquals(expected.ports, cfg.ports);
            assertTrue(cfg.probeScan);
            assertTrue(cfg.upOnly);
            assertTrue(cfg.openOnly);
            assertEquals(200, cfg.minRttTimeoutMs);
            assertEquals(NMapConfig.Timing.T5.maxInFlight, cfg.maxInFlight);
            assertEquals(typed, form.getCommand(), "the typed text is kept as typed");
            return null;
        });
    }

    @Test
    void aConfigurationPrintsAsItsCommand() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            NMapConfig cfg = NMap.parseCommand("10.0.0.1 example.com -p 22,80,443 -sV -T4 --open");
            form.setConfig(cfg);
            assertEquals("10.0.0.1 example.com -p 22,80,443 -sV -T4 --open", form.getCommand());
            NMapConfig back = form.toConfig();
            assertEquals(cfg.targets, back.targets);
            assertArrayEquals(cfg.ports, back.ports);
            assertTrue(back.openOnly);
            assertEquals(NMapConfig.Timing.T4.maxInFlight, back.maxInFlight);
            return null;
        });
    }

    /** The Match segment is {@code --probe-match} (2026-10-31): first is the default and prints nothing. */
    @Test
    void theMatchSegmentFollowsTheCommandBothWays() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            form.setCommand("10.0.0.1 -sV --probe-match all");
            assertEquals(NMapConfig.ProbeMatch.ALL, form.toConfig().probeMatch, "the command sets the segment");
            form.setConfig(NMap.parseCommand("10.0.0.1 -sV"));
            assertEquals("10.0.0.1 -sV", form.getCommand(), "first is the default and is not printed");
            assertEquals(NMapConfig.ProbeMatch.FIRST, form.toConfig().probeMatch);
            form.setConfig(NMap.parseCommand("10.0.0.1 -p 443 -sV --probe-match all"));
            assertEquals("10.0.0.1 -p 443 -sV --probe-match all", form.getCommand(), "the segment prints into the command");
            return null;
        });
    }

    /** The Ports placeholder is the owner's to set (2026-10-31); it starts on the engine's default. */
    @Test
    void thePortsPlaceholderIsSetByTheOwner() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            assertEquals(ScanFormPanel.PORTS_DEFAULT_HINT, form.portsPlaceholder());
            form.setPortsPlaceholder("22,443 (ticked probes)");
            assertEquals("22,443 (ticked probes)", form.portsPlaceholder());
            form.setPortsPlaceholder(null);
            assertEquals(ScanFormPanel.PORTS_DEFAULT_HINT, form.portsPlaceholder(), "null is the default again");
            return null;
        });
    }

    @Test
    void flagsWithoutAControlSurvive() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            form.setCommand("10.0.0.0/24 -sn -PR -n");
            NMapConfig cfg = form.toConfig();
            assertEquals(0, cfg.ports.length, "discovery only");
            assertTrue(cfg.discoveryArp);
            assertFalse(cfg.discoveryIcmp);
            assertFalse(cfg.discoveryTcp);
            assertEquals(NMapConfig.ReverseDns.NEVER, cfg.reverseDns);
            assertEquals("10.0.0.0/24 -sn -PR -n", NMap.formatCommand(cfg));
            return null;
        });
    }

    @Test
    void noTargetIsRefusedAndAResetFormIsEmpty() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            assertThrows(IllegalArgumentException.class, form::toConfig);
            form.setCommand("10.0.0.1 -p 22");
            assertEquals("10.0.0.1", form.toConfig().targets.get(0));
            form.reset();
            assertEquals("", form.getCommand());
            assertEquals("", form.getScanName());
            assertThrows(IllegalArgumentException.class, form::toConfig);
            return null;
        });
    }

    /**
     * 2026-10-25, found on the maintainer's first run: {@code 80,443} typed, "Host discovery only"
     * ticked, the command read {@code -sn} and the result said 0 open ports with nothing on the
     * form explaining why. The two are exclusive now, last action wins, and nothing is greyed: a
     * first fix disabled the Ports field and read as "I can no longer specify the port range".
     */
    @Test
    void discoveryOnlyAndPortsAreExclusiveLastActionWins() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            form.setCommand("10.0.0.0/24 -p 80,443 -sV --open --up-only");

            // ticking the box after ports were typed: the box wins, the form says so
            form.discoveryOnlyBox().doClick();
            assertTrue(form.portsField().isEnabled(), "never greyed");
            assertEquals("80,443", form.portsField().getText(), "the text is kept");
            assertEquals(0, form.toConfig().ports.length, "-sn scans no ports");
            assertTrue(form.getCommand().contains("-sn"), form.getCommand());
            assertFalse(form.getCommand().contains("-p "), form.getCommand());
            assertTrue(form.messageLabel().hasMessage(), "the form says the ports are not scanned");
            assertTrue(form.messageLabel().getText().contains("80,443"), form.messageLabel().getText());

            // typing ports while the box is ticked: the ports win, the box unticks itself
            form.portsField().setText("");
            form.portsField().getDocument().insertString(0, "22", null);
            assertFalse(form.discoveryOnlyBox().isSelected(), "typing ports unticks Host discovery only");
            assertArrayEquals(new int[]{22}, form.toConfig().ports);
            assertEquals("10.0.0.0/24 -p 22 -sV --open --up-only", form.getCommand());
            assertFalse(form.messageLabel().hasMessage());

            // a parsed command does not count as typing: -sn from the command stays ticked
            form.setCommand("10.0.0.0/24 -sn");
            assertTrue(form.discoveryOnlyBox().isSelected());
            assertEquals("", form.portsField().getText());
            assertTrue(form.portsField().isEnabled());
            return null;
        });
    }

    /**
     * Local networks (2026-11-06): the menu lists the blocks it is given, a pick appends the
     * block to the targets once (a second pick of the same block changes nothing) and the
     * command follows; with no block the menu is one disabled line. Last in either case, under a
     * separator, a Refresh item that reads the interfaces again.
     */
    @Test
    void aLocalNetworkPickAppendsItToTheTargets() throws Exception {
        onEDT(() -> {
            ScanFormPanel form = new ScanFormPanel();
            JPopupMenu menu = form.networksMenu(new String[]{"192.168.1.0/24", "10.8.0.0/16"});
            assertEquals(4, menu.getComponentCount(), "two blocks, a separator, Refresh");
            assertEquals(NSAppUtil.ScanForm.NETWORKS_REFRESH.getDisplayName(), ScanFormPanel.refreshItem(menu).getText());
            assertTrue(ScanFormPanel.refreshItem(menu).isEnabled());
            JMenuItem first = (JMenuItem) menu.getComponent(0);
            assertEquals("192.168.1.0/24", first.getText());
            assertTrue(first.isEnabled());

            first.doClick();
            assertEquals(List.of("192.168.1.0/24"), form.toConfig().targets);
            assertEquals("192.168.1.0/24", form.getCommand(), "the command follows the pick");

            first.doClick();
            ((JMenuItem) menu.getComponent(1)).doClick();
            assertEquals(List.of("192.168.1.0/24", "10.8.0.0/16"), form.toConfig().targets, "no duplicate, the second block appended");

            form.setCommand("example.com -p 443");
            form.addTarget("10.8.0.0/16");
            assertEquals(List.of("example.com", "10.8.0.0/16"), form.toConfig().targets, "appended after typed targets");
            assertArrayEquals(new int[]{443}, form.toConfig().ports, "the rest of the command is kept");

            JPopupMenu none = form.networksMenu(null);
            assertEquals(3, none.getComponentCount(), "the empty line, a separator, Refresh");
            assertEquals(NSAppUtil.ScanForm.NETWORKS_REFRESH.getDisplayName(), ScanFormPanel.refreshItem(none).getText());
            JMenuItem line = (JMenuItem) none.getComponent(0);
            assertFalse(line.isEnabled());
            assertEquals(NSAppUtil.ScanForm.NETWORKS_EMPTY.getDisplayName(), line.getText());
            assertFalse(form.networksMenu(new String[0]).getComponent(0).isEnabled(), "an empty array reads as none too");
            return null;
        });
    }

    private static <T> T onEDT(java.util.concurrent.Callable<T> work) throws Exception {
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
