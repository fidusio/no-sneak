package io.xlogistx.nosneak.app.ui;

import com.formdev.flatlaf.FlatLaf;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import net.miginfocom.swing.MigLayout;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The maintainer's report of 2026-11-06: "a lot of button text is truncated, '+ New Sc..'; you
 * cannot put dots, you have to be explicit to the user". Cause: FlatLaf hands
 * {@code Component.focusWidth} to MigLayout as every button's visual padding, and MigLayout
 * clamps that padding at the container's edge, so a button that ends a row flush with its
 * container is laid out that much narrower than its preferred width and FlatLaf clips the text
 * with an ellipsis. The app's {@code themes/FlatLaf.properties} set the width to 1 (and FlatLaf's
 * macOS Dark palette sets 2 of its own); it is 0 now, for every theme. This test installs each
 * theme <b>with the app's theme files registered</b>, as {@code NoSneakMain.main} does — a
 * harness that skips the registration measures stock FlatLaf and sees nothing — lays out the
 * page head and the command row of the Scan page, and checks that every button gets exactly the
 * width it asked for, so nothing is cut.
 */
class ButtonTextNotClippedTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
        FlatLaf.registerCustomDefaultsSource("themes");
    }

    @ParameterizedTest
    @EnumSource(NSAppUtil.Theme.class)
    void aButtonThatEndsARowGetsItsWholeWidth(NSAppUtil.Theme theme) throws Exception {
        List<String> problems = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            NoSneakMain.installLookAndFeel(theme);
            int focusWidth = UIManager.getInt("Component.focusWidth");
            if (focusWidth != 0) problems.add(theme + ": Component.focusWidth is " + focusWidth + ", the app's theme files set no focus ring");

            // the Scan page head: title, then the primary New scan at the row's end
            JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
            JLabel title = new JLabel(NSAppUtil.Screen.SCAN.getDisplayName());
            title.setFont(UITokens.font(Font.BOLD, 6));
            head.add(title, "wmin 0");
            JButton newScan = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ScanPage.NEW_SCAN));
            head.add(newScan);

            // the command row: the field, then Help, Run and Stop, the last flush with the edge
            JPanel cmdRow = new JPanel(new MigLayout("insets 0, gapx 10, fillx", "[grow,fill][][][]"));
            cmdRow.add(new JTextField(), "growx");
            cmdRow.add(GUIUtil.applyProp(new JButton(new IconUtil.InfoIcon(16)), NSAppUtil.ScanForm.HELP));
            JButton run = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/run.svg", 16, Color.WHITE)), NSAppUtil.ScanForm.RUN));
            cmdRow.add(run);
            JButton stop = GUIUtil.applyProp(new JButton(new IconUtil.StopIcon(16)), NSAppUtil.ScanForm.STOP);
            stop.setEnabled(false);
            cmdRow.add(stop);

            // a toolbar-type Copy at the end of a label row, as the command head has it
            JPanel cmdHead = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[]"));
            cmdHead.add(new JLabel(NSAppUtil.ScanForm.COMMAND.getDisplayName()));
            JButton copy = GUIUtil.applyProp(new JButton(new IconUtil.CopyIcon(14)), NSAppUtil.ScanForm.COPY);
            copy.putClientProperty("JButton.buttonType", "toolBarButton");
            cmdHead.add(copy);

            JPanel page = new JPanel(new MigLayout("insets 20, wrap 1, gapy 14, fillx", "[grow,fill]"));
            page.add(head, "growx");
            page.add(cmdHead, "growx");
            page.add(cmdRow, "growx");
            page.setSize(900, 300);
            page.doLayout();
            for (Component c : new Component[]{head, cmdHead, cmdRow}) c.doLayout();

            for (JButton b : new JButton[]{newScan, run, stop, copy}) {
                int pref = b.getPreferredSize().width;
                if (b.getWidth() != pref)
                    problems.add(theme + ": " + b.getText() + " asked " + pref + " px, laid out " + b.getWidth());
                // what FlatLaf would draw: the text fits the room left inside the insets
                Insets in = b.getInsets();
                int room = b.getWidth() - in.left - in.right - (b.getIcon() != null ? b.getIcon().getIconWidth() + b.getIconTextGap() : 0);
                int text = b.getFontMetrics(b.getFont()).stringWidth(b.getText());
                if (text > room)
                    problems.add(theme + ": " + b.getText() + " needs " + text + " px of text room, has " + room);
            }
        });
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }
}
