package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.ChipPanel;
import io.xlogistx.gui.FormPanel;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.InlineMessage;
import io.xlogistx.gui.SegmentedControl;
import io.xlogistx.gui.TextAreaWidget;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.scan.nmap.NMap;
import io.xlogistx.scan.nmap.NMapConfig;
import io.xlogistx.scan.nmap.WellKnownPorts;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.server.net.NetUtil;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The scan set-up (board 2 of the redesign canvas, 2026-10-24): targets, ports, a name, the
 * option checkboxes, the timing template, the two pacing knobs, the probe chips, and the
 * <b>command</b> the form generates — which stays editable, and refills the form when edited.
 * <p>
 * The command is the truth and the form is a view over it: {@link #toConfig()} parses the
 * command field (so flags the form has no control for, {@code -PR} or {@code --dns-servers},
 * survive) and overlays the fields on it; every field change re-prints the command through
 * {@code NMap.formatCommand}; every command edit re-parses into the fields. A guard stops the two
 * from echoing. A command that does not parse shows its reason inline and leaves the fields alone.
 * Probes are not in the command: the chips belong to the owner ({@code ScanPanel}), which applies
 * ticked probes to the configuration at run time, as it always did. What an <b>empty Ports
 * field</b> means depends on the chips (2026-10-31: the ticked probes' declared ports, else
 * 1-1024), so the owner tells the form through {@link #setPortsPlaceholder} and the placeholder
 * says it; the <b>Match</b> segment ({@code --probe-match}) is the form's own. <b>Local
 * networks</b> beside the Targets label (2026-11-06) lists this machine's IPv4 CIDR blocks
 * ({@code NetUtil.allV4CIDRBlocks}) and a pick appends one to the targets. <b>Discovered hosts
 * only</b> (2026-11-10), last in the Options row, swaps the targets for the hosts the result on
 * the page found up and keeps host discovery on, so a rerun checks only those hosts and scans
 * the ones that still answer.
 */
public class ScanFormPanel extends JPanel {

    /** What an empty Ports field means when no probe is ticked: the engine's default list ({@link NSAppUtil.ScanForm#PORTS_FIELD}'s placeholder). */
    public static final String PORTS_DEFAULT_HINT = NSAppUtil.ScanForm.PORTS_FIELD.getDisplayName();

    // every component is named, worded and described by NSAppUtil.ScanForm (the maintainer's rule, 2026-11-01)
    /**
     * Targets: gui-audio's {@link TextAreaWidget} since 2026-11-10 (the maintainer: "the text field
     * is ugly and confusing" with many addresses) — three wrapping rows that scroll, Enter runs.
     */
    private final TextAreaWidget targets = GUIUtil.applyProp(new TextAreaWidget(3), NSAppUtil.ScanForm.TARGETS_FIELD);
    /** {@code 23 targets}, beside the links; empty with none. */
    private final JLabel targetCount = GUIUtil.applyProp(new JLabel(), NSAppUtil.ScanForm.TARGETS_COUNT);
    /** Local networks (2026-11-06): a link beside the Targets label that opens {@link #networksMenu}. */
    private final JButton networks = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ScanForm.NETWORKS));
    /** Clear (2026-11-10): a link beside Local networks that empties the targets. */
    private final JButton clearTargets = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ScanForm.TARGETS_CLEAR));
    private final JTextField ports = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.PORTS_FIELD);
    private final JTextField name = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.NAME_FIELD);
    private final JCheckBox serviceDetection = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.SERVICE_DETECTION);
    private final JCheckBox discoveryOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.DISCOVERY_ONLY);
    private final JCheckBox skipPing = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.SKIP_PING);
    private final JCheckBox upOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.UP_ONLY);
    private final JCheckBox openOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.OPEN_ONLY);
    /**
     * Discovered hosts only (2026-11-10): a form helper, not an engine flag. Ticked, the targets
     * become the hosts the result on the page found up ({@link #setDiscoveredHosts}) with host
     * discovery left on, so each is checked again before it is scanned or probed.
     */
    private final JCheckBox discoveredOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.DISCOVERED_ONLY);
    /** The up hosts of the result on the page; empty when there is none. */
    private List<String> discovered = List.of();
    /** What the tick replaced, put back by an untick: the targets, Skip ping, Host discovery only. */
    private String targetsBeforeDiscovered = "";
    private boolean skipPingBeforeDiscovered;
    private boolean discoveryOnlyBeforeDiscovered;
    private final SegmentedControl timing = GUIUtil.applyProp(new SegmentedControl(NMapConfig.Timing.values()), NSAppUtil.ScanForm.TIMING_CONTROL);
    /** First / All — {@code --probe-match} (2026-10-31); the enum carries the labels and tooltips. */
    private final SegmentedControl probeMatch = GUIUtil.applyProp(new SegmentedControl(NMapConfig.ProbeMatch.values()), NSAppUtil.ScanForm.MATCH_CONTROL);
    private final JTextField maxInFlight = GUIUtil.applyProp(new JTextField(6), NSAppUtil.ScanForm.MAX_IN_FLIGHT_FIELD);
    private final JTextField minRtt = GUIUtil.applyProp(new JTextField(6), NSAppUtil.ScanForm.MIN_RTT_FIELD);
    /** Two wrapping rows (2026-11-10, the maintainer: "make command textarea as well"): a long target list no longer runs off one line. */
    private final TextAreaWidget command = GUIUtil.applyProp(new TextAreaWidget(2), NSAppUtil.ScanForm.COMMAND_FIELD);
    private final InlineMessage message = GUIUtil.applyProp(new InlineMessage(), NSAppUtil.ScanForm.MESSAGE);
    private final JButton run = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/run.svg", 16, Color.WHITE)), NSAppUtil.ScanForm.RUN));
    private final JButton stop = GUIUtil.applyProp(new JButton(new IconUtil.StopIcon(16)), NSAppUtil.ScanForm.STOP);
    /** The Command label's line: label, Help, Run scan, Stop, Copy, the hint. */
    private final JPanel commandLine = new JPanel(new MigLayout("insets 0, gapx 8"));
    // tinted with the theme's text colour (2026-11-12): the svg's own stroke is dark and painted nothing on the dark theme
    private final JButton help = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/info.svg", 16, UITokens.text())), NSAppUtil.ScanForm.HELP);
    private final JPanel probeSlot = GUIUtil.applyProp(new JPanel(new BorderLayout()), NSAppUtil.ScanForm.PROBE_SLOT);
    private boolean syncing;

    /** A flag's box and its command-line spelling as one piece, so a wrap never parts them. */
    private static JPanel flag(JCheckBox box, NSAppUtil.ScanForm spelling) {
        // the right inset is the gap to the next flag: FlowLayout's own gap would also indent the first one
        JPanel p = new JPanel(new MigLayout("insets 0 0 0 28, gapx 18"));
        p.setOpaque(false);
        p.add(box);
        p.add(mono(spelling));
        return p;
    }

    public ScanFormPanel() {
        super(new MigLayout("insets 0, fillx, wrap 1, gapy 12, hidemode 3", "[grow,fill]"));
        GUIUtil.applyProp(this, NSAppUtil.ScanForm.PANEL);
        setOpaque(false);
        // two cards (2026-11-10, the maintainer: "group target, Local networks, port and Name in
        // a panel by itself"): what is scanned, then how
        JPanel targetCard = card(NSAppUtil.ScanForm.TARGET_CARD);
        JPanel setupCard = card(NSAppUtil.ScanForm.SETUP_CARD);
        add(targetCard, "growx");
        add(setupCard, "growx");

        targets.setFont(UITokens.mono(0));
        ports.setFont(UITokens.mono(0));
        maxInFlight.setFont(UITokens.mono(0));
        minRtt.setFont(UITokens.mono(0));
        command.setFont(UITokens.mono(-0.5f));
        command.getTextArea().setBackground(UITokens.color("xlogistx.chip", null, 0xF7F7FA));

        // the target card (the maintainer's line, 2026-11-10: "next to Targets put Name (optional)
        // [name], Ports [ports], Local networks, Clear"): one head line, the targets area under it
        JPanel targetHead = new JPanel(new MigLayout("insets 0, gapx 8", "[][]20[][]20[][]20[][]"));
        // both fields a fixed 20 characters wide (15 at first) (the maintainer, 2026-11-10); longer text scrolls inside
        name.setColumns(20);
        // a scan's name is at most NAME_MAX characters (the maintainer, 2026-11-10)
        GUIUtil.limitLength(name, NAME_MAX);
        ports.setColumns(20);
        targetHead.setOpaque(false);
        targetCount.setForeground(UITokens.muted());
        targetCount.setFont(UITokens.font(Font.PLAIN, -1f));
        targetHead.add(label(NSAppUtil.ScanForm.TARGETS));
        targetHead.add(targetCount);
        targetHead.add(label(NSAppUtil.ScanForm.NAME));
        targetHead.add(name);
        targetHead.add(label(NSAppUtil.ScanForm.PORTS));
        targetHead.add(ports);
        targetHead.add(networks);
        targetHead.add(clearTargets);
        targetCard.add(targetHead, "growx 0, alignx left");
        // the command a fixed 80 characters wide (the maintainer, 2026-11-10); longer text wraps and scrolls.
        // The targets area is exactly as wide as the head line above it ("make the target text area
        // equal to the length of the Targets line above it"): one size group, the head's width winning
        // 2026-11-11 ("the 2 text area remove length limitation and make their resize natural"):
        // no fixed width any more, both areas fill their card and follow the window
        targetCard.add(targets, "growx, wmin 0");
        io.xlogistx.gui.WrapLabel targetsHint = GUIUtil.applyProp(FormPanel.hint(NSAppUtil.ScanForm.TARGETS_HINT.getDisplayName()), NSAppUtil.ScanForm.TARGETS_HINT);
        targetsHint.setWrapWidth(560);
        targetCard.add(targetsHint, "wmin 0");
        networks.addActionListener(_ -> showNetworks());
        clearTargets.addActionListener(_ -> clearTargets());

        // row 2: options
        // the five flags wrap (2026-11-12, "fix the scan form width"): on one fixed line they were
        // wider than a 1000-point page and pushed both cards past its right edge
        JPanel options = new JPanel(new MigLayout("insets 0, gapx 8, gapy 6, wrap 2", "[][grow,fill]"));
        options.setOpaque(false);
        JPanel flags = new JPanel(new io.xlogistx.gui.WrapLayout(FlowLayout.LEFT, 0, 2));
        flags.setOpaque(false);
        flags.add(flag(serviceDetection, NSAppUtil.ScanForm.SERVICE_DETECTION_FLAG));
        flags.add(flag(discoveryOnly, NSAppUtil.ScanForm.DISCOVERY_ONLY_FLAG));
        flags.add(flag(skipPing, NSAppUtil.ScanForm.SKIP_PING_FLAG));
        flags.add(flag(upOnly, NSAppUtil.ScanForm.UP_ONLY_FLAG));
        flags.add(flag(openOnly, NSAppUtil.ScanForm.OPEN_ONLY_FLAG));
        // a wrapping panel knows its height only once it has its width: lay the form out again then
        flags.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                flags.revalidate();
            }
        });
        options.add(label(NSAppUtil.ScanForm.OPTIONS), "aligny top, gaptop 4, gapright 8");
        options.add(flags, "growx, wmin 0");
        // on its own line under the flags: it is a helper over the targets, not a flag
        options.add(discoveredOnly, "skip 1");
        // Match sits under the options (the maintainer, 2026-11-11: "Match section put under
        // options"), no longer beside the Probes label
        options.add(label(NSAppUtil.ScanForm.MATCH), "gapright 8");
        options.add(probeMatch, "growx 0");
        discoveredOnly.setOpaque(false);
        discoveredOnly.addActionListener(_ -> discoveredToggled());
        setDiscoveredHosts(null);
        for (JCheckBox b : new JCheckBox[]{serviceDetection, discoveryOnly, skipPing, upOnly, openOnly}) {
            b.setOpaque(false);
            b.addActionListener(_ -> fieldsChanged());
        }
        serviceDetection.addActionListener(_ -> {
            if (serviceDetectionToggled != null) serviceDetectionToggled.accept(serviceDetection.isSelected());
        });
        setupCard.add(options, "growx, wmin 0");

        // row 3: timing · knobs · probes
        JPanel row3 = new JPanel(new MigLayout("insets 0, gapx 18, fillx", "[]"));
        row3.setOpaque(false);
        JPanel timingBox = new JPanel(new MigLayout("insets 0, wrap 1, gapy 6"));
        timingBox.setOpaque(false);
        timingBox.add(label(NSAppUtil.ScanForm.TIMING));
        timingBox.add(timing);
        row3.add(timingBox, "aligny top");
        row3.add(field(NSAppUtil.ScanForm.MAX_IN_FLIGHT, maxInFlight, null), "aligny top, w 120!");
        row3.add(field(NSAppUtil.ScanForm.MIN_RTT, minRtt, null), "aligny top, w 150!");
        JPanel probeBox = new JPanel(new MigLayout("insets 0, wrap 1, gapy 6, fillx", "[grow,fill]"));
        probeBox.setOpaque(false);
        JPanel probeHead = new JPanel(new MigLayout("insets 0, gapx 8", "[]"));
        probeHead.setOpaque(false);
        probeHead.add(label(NSAppUtil.ScanForm.PROBES));
        probeBox.add(probeHead, "growx");
        probeSlot.setOpaque(false);
        probeBox.add(probeSlot, "growx, wmin 0");
        row3.add(probeBox, "aligny top, growx, pushx, wmin 200");
        setupCard.add(row3, "growx");

        // row 4: the command
        JPanel cmdHead = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[]"));
        cmdHead.setOpaque(false);
        JLabel cmdLabel = label(NSAppUtil.ScanForm.COMMAND);
        JLabel cmdHint = GUIUtil.applyProp(FormPanel.hint(NSAppUtil.ScanForm.COMMAND_HINT.getDisplayName()), NSAppUtil.ScanForm.COMMAND_HINT);
        JPanel cmdLabels = commandLine;
        cmdLabels.setOpaque(false);
        cmdLabels.add(cmdLabel);
        // Help, Run scan and Stop sit beside the Command label (the maintainer, 2026-11-11: "next
        // to command move info, run scan and stop"); the area has its row to itself
        cmdLabels.add(help);
        cmdLabels.add(run);
        stop.setEnabled(false);
        cmdLabels.add(stop);
        JButton copy = GUIUtil.applyProp(new JButton(new IconUtil.CopyIcon(14)), NSAppUtil.ScanForm.COPY);
        copy.putClientProperty("JButton.buttonType", "toolBarButton");
        copy.addActionListener(_ -> {
            String text = command.getText();
            if (!text.isBlank()) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        });
        // Copy sits next to Stop (the maintainer, 2026-11-11: "move copy next to stop"), then the hint
        cmdLabels.add(copy);
        cmdLabels.add(cmdHint);
        cmdHead.add(cmdLabels);
        JPanel cmdRow = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]"));
        cmdRow.setOpaque(false);
        cmdRow.add(command, "growx, wmin 0");
        JPanel cmdBox = new JPanel(new MigLayout("insets 14 0 0 0, wrap 1, gapy 6, fillx", "[grow,fill]"));
        cmdBox.setOpaque(false);
        cmdBox.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UITokens.border()));
        cmdBox.add(cmdHead, "growx");
        cmdBox.add(cmdRow, "growx");
        cmdBox.add(message, "growx");
        setupCard.add(cmdBox, "growx");

        // wiring: fields → command, command → fields
        DocumentListener fields = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                fieldsChanged();
            }

            public void removeUpdate(DocumentEvent e) {
                fieldsChanged();
            }

            public void changedUpdate(DocumentEvent e) {
                fieldsChanged();
            }
        };
        targets.getDocument().addDocumentListener(fields);
        targets.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                countTargets();
            }

            public void removeUpdate(DocumentEvent e) {
                countTargets();
            }

            public void changedUpdate(DocumentEvent e) {
                countTargets();
            }
        });
        ports.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                portsTyped();
            }

            public void removeUpdate(DocumentEvent e) {
                portsTyped();
            }

            public void changedUpdate(DocumentEvent e) {
                portsTyped();
            }
        });
        maxInFlight.getDocument().addDocumentListener(fields);
        minRtt.getDocument().addDocumentListener(fields);
        probeMatch.select(NMapConfig.ProbeMatch.FIRST);
        probeMatch.onChange(_ -> fieldsChanged());
        timing.onChange(_ -> {
            // picking a template resets the knobs to its values; the fields follow
            syncing = true;
            try {
                NMapConfig.Timing t = timing.<NMapConfig.Timing>selectedSource();
                if (t != null) maxInFlight.setText(Integer.toString(t.maxInFlight));
            } finally {
                syncing = false;
            }
            fieldsChanged();
        });
        command.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                commandChanged();
            }

            public void removeUpdate(DocumentEvent e) {
                commandChanged();
            }

            public void changedUpdate(DocumentEvent e) {
                commandChanged();
            }
        });
        command.addActionListener(_ -> run.doClick());
        targets.addActionListener(_ -> run.doClick());

        reset();
    }

    // ---- public API ----

    /**
     * What an empty Ports field means right now, shown as its placeholder (2026-10-31): the owner
     * sets the ticked probes' ports ({@code 22,443,2222,8443 (ticked probes)}) or
     * {@link #PORTS_DEFAULT_HINT} when no chip declares any.
     */
    public void setPortsPlaceholder(String text) {
        String hint = text != null ? text : PORTS_DEFAULT_HINT;
        ports.putClientProperty("JTextField.placeholderText", hint);
        ports.setToolTipText(NSAppUtil.ScanForm.PORTS_EMPTY.getDisplayName() + ": " + hint + ". "
                + NSAppUtil.ScanForm.PORTS_FIELD.getDescription()); // the field is narrow
        ports.repaint();
    }

    /** The Ports field's current placeholder (tests). */
    public String portsPlaceholder() {
        Object v = ports.getClientProperty("JTextField.placeholderText");
        return v != null ? v.toString() : "";
    }

    /** The component that shows the probe chips; the owner puts its {@link ChipPanel} here. */
    public void setProbeControl(JComponent control) {
        probeSlot.removeAll();
        probeSlot.add(control, BorderLayout.CENTER);
        probeSlot.revalidate();
    }

    public JButton getRunButton() {
        return run;
    }

    public JButton getStopButton() {
        return stop;
    }

    public JButton getHelpButton() {
        return help;
    }

    /** The longest name a scan may carry, typed or made up from its targets (the maintainer, 2026-11-10). */
    public static final int NAME_MAX = 30;

    /** The subject's own name for the scan, or empty. */
    public String getScanName() {
        return name.getText().trim();
    }

    /** Fills the Name field (a stored scan being run again keeps its name). */
    public void setScanName(String text) {
        name.setText(text != null ? text : "");
    }

    /** The command as it stands, trimmed. */
    public String getCommand() {
        return command.getText().trim();
    }

    /** Shows a problem under the command (an engine refusal, a bad probe). */
    public void showError(String text) {
        message.error(text);
    }

    /** A note under the command that is not a refusal (a group with members that no longer exist, 2026-11-01). */
    public void showNote(String text) {
        message.info(text);
    }

    public void clearMessage() {
        message.clear();
    }

    /**
     * The "Host discovery only" ({@code -sn}) tick. It and the Ports field are exclusive, last
     * action wins: typing ports unticks it, ticking it with ports typed keeps the text but the
     * inline message says those ports are not scanned (2026-10-25: a scan with {@code 80,443}
     * typed and this box ticked ran {@code -sn} and reported no open ports with nothing on the
     * form explaining why; a first fix greyed the field, which read as "ports disabled").
     */
    JCheckBox discoveryOnlyBox() {
        return discoveryOnly;
    }

    /** The Ports field, for tests. */
    JTextField portsField() {
        return ports;
    }

    /** The inline message under the command, for tests. */
    InlineMessage messageLabel() {
        return message;
    }

    /**
     * The hosts the result on the page found up (2026-11-10), from the owner each time a result
     * is shown or cleared. The <i>Discovered hosts only</i> box is enabled only while there is
     * one. A ticked box <b>stays ticked</b> over a new result that has hosts (2026-11-11; the
     * maintainer: "when I check the box and click scan it should always be validated") and the
     * targets follow the new list at once; with no host left the box unticks and the targets stand.
     */
    public void setDiscoveredHosts(List<String> hosts) {
        discovered = hosts != null ? List.copyOf(hosts) : List.of();
        boolean keep = discoveredOnly.isSelected() && !discovered.isEmpty();
        discoveredOnly.setSelected(keep);
        if (keep) applyDiscovered();
        discoveredOnly.setEnabled(!discovered.isEmpty());
        discoveredOnly.setToolTipText(discovered.isEmpty()
                ? NSAppUtil.ScanForm.DISCOVERED_ONLY_NONE.getDisplayName()
                : NSAppUtil.ScanForm.DISCOVERED_ONLY.getDescription() + " (" + discovered.size() + ")");
    }

    /** The <i>Discovered hosts only</i> box, for tests. */
    JCheckBox discoveredOnlyBox() {
        return discoveredOnly;
    }

    /** The Skip ping box, for tests. */
    JCheckBox skipPingBox() {
        return skipPing;
    }

    /** The Targets field, for tests. */
    TextAreaWidget targetsField() {
        return targets;
    }

    /** The count beside the Targets links, for tests. */
    JLabel targetCountLabel() {
        return targetCount;
    }

    /** {@code 1 target} / {@code 23 targets} beside the links, nothing with none; a range or a block is one. */
    private void countTargets() {
        int n = 0;
        for (String t : targets.getText().trim().split("\\s+")) if (!t.isEmpty()) n++;
        targetCount.setText(n == 0 ? "" : n == 1 ? "1 target" : n + " targets");
    }

    /**
     * A tick puts the discovered hosts in Targets and unticks Skip ping and Host discovery only
     * (the hosts are checked again, then their ports scanned); an untick puts back what the tick
     * replaced, unless the targets were edited meanwhile, which then stand.
     */
    /**
     * The ticked box enforced: the targets are the discovered hosts and host discovery is on
     * (no Skip ping, no Host discovery only), whatever was typed since; the command follows.
     */
    private void applyDiscovered() {
        syncing = true;
        try {
            targets.setText(String.join(" ", discovered));
            skipPing.setSelected(false);
            discoveryOnly.setSelected(false);
        } finally {
            syncing = false;
        }
        fieldsChanged();
    }

    private void discoveredToggled() {
        String list = String.join(" ", discovered);
        syncing = true;
        try {
            if (discoveredOnly.isSelected()) {
                targetsBeforeDiscovered = targets.getText();
                skipPingBeforeDiscovered = skipPing.isSelected();
                discoveryOnlyBeforeDiscovered = discoveryOnly.isSelected();
                targets.setText(list);
                skipPing.setSelected(false);
                discoveryOnly.setSelected(false);
            } else if (targets.getText().trim().equals(list)) {
                targets.setText(targetsBeforeDiscovered);
                skipPing.setSelected(skipPingBeforeDiscovered);
                discoveryOnly.setSelected(discoveryOnlyBeforeDiscovered);
            }
        } finally {
            syncing = false;
        }
        fieldsChanged();
    }

    /** Ticks Service detection programmatically (the chips mirror into it); the toggle listener is not told. */
    public void setServiceDetection(boolean on) {
        if (serviceDetection.isSelected() == on) return;
        serviceDetection.setSelected(on);
        fieldsChanged();
    }

    private java.util.function.Consumer<Boolean> serviceDetectionToggled;

    /**
     * Told when the <i>user</i> clicks Service detection (2026-10-26): the owner turns a tick into
     * "all probes" and an untick into "none", since the ticked probes are the only source of
     * probing. Programmatic changes ({@link #setServiceDetection}, a parsed command) do not fire it.
     */
    public void onServiceDetectionToggled(java.util.function.Consumer<Boolean> listener) {
        this.serviceDetectionToggled = listener;
    }

    /**
     * The configuration the form describes: the command field parsed, with the fields laid over
     * it. Probes are the owner's business and are not applied here.
     *
     * @throws IllegalArgumentException with the engine's reason when the command or a field is invalid
     */
    public NMapConfig toConfig() {
        NMapConfig cfg = configOf();
        if (cfg.targets.isEmpty()) throw new IllegalArgumentException("at least one target is required");
        return cfg;
    }

    /**
     * The configuration for a press of Run (2026-11-10; the maintainer: "whenever I hit scan
     * button read all the parameters and run the scan accordingly"): as {@link #toConfig},
     * read now from the command and every field, except that a command which does not parse is
     * refused with the engine's reason. A field edit re-prints the command, so a broken one is
     * the subject's own last edit; scanning the fields without it would drop what it carried.
     *
     * @throws IllegalArgumentException when the command or a field is invalid, or no target is given
     */
    public NMapConfig toRunConfig() {
        // Discovered hosts only is validated at every Run (2026-11-11): ticked, the scan is on
        // the discovered hosts with discovery on, even if the targets or the command were edited since
        if (discoveredOnly.isSelected() && !discovered.isEmpty()) applyDiscovered();
        String typed = command.getText().trim();
        if (!typed.isEmpty()) NMap.parseCommand(typed);
        return toConfig();
    }

    /** The command parsed with the fields laid over it, targets or not. */
    private NMapConfig configOf() {
        NMapConfig cfg;
        String typed = command.getText().trim();
        try {
            cfg = typed.isEmpty() ? new NMapConfig() : NMap.parseCommand(typed);
        } catch (IllegalArgumentException e) {
            cfg = new NMapConfig();
        }
        overlay(cfg);
        return cfg;
    }

    /**
     * Clear: no target left, the rest of the form as it stands. The command is re-printed without
     * targets and no error is shown — an empty Targets field after Clear is what was asked for;
     * Run still refuses it.
     */
    void clearTargets() {
        syncing = true;
        try {
            discoveredOnly.setSelected(false);
            targets.setText("");
            try {
                command.setText(NMap.formatCommand(configOf()));
            } catch (IllegalArgumentException e) {
                command.setText("");
            }
            message.clear();
        } finally {
            syncing = false;
        }
        targets.requestFocusInWindow();
    }

    /** The Clear link, for tests. */
    JButton clearTargetsButton() {
        return clearTargets;
    }

    /** One of the form's two cards: white, bordered, the form's insets. */
    private static JPanel card(NSAppUtil.ScanForm ref) {
        JPanel p = GUIUtil.applyProp(new JPanel(new MigLayout("insets 20, fillx, wrap 1, gapy 12, hidemode 3", "[grow,fill]")), ref);
        p.setBackground(UITokens.surface());
        p.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        return p;
    }

    /** Fills the fields from a configuration and prints its command. */
    public void setConfig(NMapConfig cfg) {
        syncing = true;
        try {
            fill(cfg);
            command.setText(NMap.formatCommand(cfg));
            message.clear();
        } finally {
            syncing = false;
        }
    }

    /** Puts a command in the field and fills the form from it, as if the subject had typed it. */
    public void setCommand(String text) {
        command.setText(text != null ? text : "");
    }

    /** Empties every field and the command (logout, or a new scan from scratch). */
    public void reset() {
        syncing = true;
        try {
            targets.setText("");
            ports.setText("");
            name.setText("");
            serviceDetection.setSelected(false);
            discoveryOnly.setSelected(false);
            skipPing.setSelected(false);
            upOnly.setSelected(false);
            openOnly.setSelected(false);
            discoveredOnly.setSelected(false);
            timing.select(3);
            probeMatch.select(NMapConfig.ProbeMatch.FIRST);
            maxInFlight.setText(Integer.toString(NMapConfig.DEFAULT_MAX_IN_FLIGHT));
            minRtt.setText(Integer.toString(NMapConfig.DEFAULT_MIN_RTT_TIMEOUT_MS));
            command.setText("");
            message.clear();
        } finally {
            syncing = false;
        }
    }

    // ---- local networks ----

    /** What reading the interfaces off the EDT gave: the blocks, or the reason there are none to show. */
    private record Networks(String[] blocks, String error) {
    }

    /**
     * Reads this machine's IPv4 CIDR blocks off the EDT (enumerating the interfaces can take a
     * moment on Windows) and drops {@link #networksMenu} under the link; a failure to read them
     * is said under the command, inline, like any other refusal.
     */
    private void showNetworks() {
        BackgroundTask.run(this, networks, () -> {
            try {
                return new Networks(NetUtil.allV4CIDRBlocks(), null);
            } catch (IOException e) {
                return new Networks(null, e.getMessage());
            }
        }, found -> {
            if (found.error() != null) {
                message.error(NSAppUtil.ScanForm.NETWORKS_FAILED.getDisplayName() + found.error());
                return;
            }
            if (networks.isShowing()) networksMenu(found.blocks()).show(networks, 0, networks.getHeight());
        });
    }

    /**
     * The Local networks menu: one item per IPv4 CIDR block of this machine's up, non-loopback
     * interfaces, in the order {@code NetUtil.allV4CIDRBlocks} reports them, a pick appending it
     * to Targets through {@link #addTarget}; one disabled line when no interface has an IPv4
     * address. Last, under a separator, <b>Refresh</b> (the maintainer, 2026-11-06: "add refresh
     * button to local network, in case a network gets activated"): it reads the interfaces again
     * and reopens the menu, so a VPN or a Wi-Fi that came up while the menu was open shows
     * without closing it. Package-private for {@code ScanFormPanelTest}, which feeds it blocks
     * of its own.
     */
    JPopupMenu networksMenu(String[] blocks) {
        JPopupMenu menu = new JPopupMenu();
        if (blocks == null || blocks.length == 0) {
            JMenuItem none = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.ScanForm.NETWORKS_EMPTY);
            none.setEnabled(false);
            menu.add(none);
        } else {
            for (String block : blocks) {
                JMenuItem item = new JMenuItem(block);
                item.setFont(UITokens.mono(0));
                item.addActionListener(_ -> addTarget(block));
                menu.add(item);
            }
        }
        menu.addSeparator();
        JMenuItem refresh = GUIUtil.applyProp(new JMenuItem("", new IconUtil.RefreshIcon(14)), NSAppUtil.ScanForm.NETWORKS_REFRESH);
        refresh.addActionListener(_ -> showNetworks());
        menu.add(refresh);
        return menu;
    }

    /** The Refresh item of a {@link #networksMenu}: its last component (tests). */
    static JMenuItem refreshItem(JPopupMenu menu) {
        return (JMenuItem) menu.getComponent(menu.getComponentCount() - 1);
    }

    /** Appends a target to the Targets field unless it is already one of them; the command follows as for typing. */
    void addTarget(String target) {
        String text = targets.getText().trim();
        List<String> have = new ArrayList<>();
        for (String t : text.split("\\s+")) if (!t.isEmpty()) have.add(t);
        if (have.contains(target)) return;
        have.add(target);
        targets.setText(String.join(" ", have));
    }

    // ---- sync ----

    /**
     * Ports typed by the subject mean a port scan, so they untick "Host discovery only"; the
     * field is never greyed. A programmatic fill (a command being parsed) goes through
     * {@link #fill} under the guard and does not untick anything.
     */
    private void portsTyped() {
        if (syncing) return;
        if (discoveryOnly.isSelected() && !ports.getText().trim().isEmpty()) discoveryOnly.setSelected(false);
        fieldsChanged();
    }

    /** The inline note that the typed ports are not scanned under {@code -sn}; nothing otherwise. */
    private void noteIgnoredPorts() {
        String spec = ports.getText().trim();
        if (discoveryOnly.isSelected() && !spec.isEmpty()) {
            message.info("Host discovery only (-sn): ports " + spec + " are not scanned. Untick it to scan them.");
        }
    }

    private void overlay(NMapConfig cfg) {
        cfg.targets.clear();
        for (String t : targets.getText().trim().split("\\s+")) if (!t.isEmpty()) cfg.target(t);
        String spec = ports.getText().trim();
        if (discoveryOnly.isSelected()) {
            cfg.ports(new int[0]);
            cfg.udpPorts(new int[0]);
        } else if (spec.isEmpty()) {
            cfg.ports = null;
            if (!cfg.udpScan) cfg.udpPorts = null;
        } else {
            NMap.PortSpec ps = NMap.parsePortSpec(spec);
            cfg.ports(ps.tcp());
            if (ps.udp().length > 0) cfg.udpPorts(ps.udp());
            else if (!cfg.udpScan) cfg.udpPorts = null;
        }
        cfg.probeScan(serviceDetection.isSelected());
        NMapConfig.ProbeMatch pm = probeMatch.<NMapConfig.ProbeMatch>selectedSource();
        cfg.probeMatch(pm != null ? pm : NMapConfig.ProbeMatch.FIRST);
        cfg.discovery(!skipPing.isSelected());
        cfg.upOnly(upOnly.isSelected());
        cfg.openOnly(openOnly.isSelected());
        NMapConfig.Timing t = timing.<NMapConfig.Timing>selectedSource();
        if (t != null) cfg.timing(t);
        Integer inFlight = intOf(maxInFlight.getText(), "Max in flight");
        if (inFlight != null) cfg.maxInFlight = Math.max(1, inFlight);
        Integer rtt = intOf(minRtt.getText(), "Min RTT timeout");
        if (rtt != null) cfg.minRttTimeoutMs(rtt);
        else cfg.minRttTimeoutMs(NMapConfig.DEFAULT_MIN_RTT_TIMEOUT_MS);
    }

    private static Integer intOf(String text, String what) {
        String s = text.trim();
        if (s.isEmpty()) return null;
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(what + " must be a number");
        }
    }

    private void fill(NMapConfig cfg) {
        targets.setText(String.join(" ", cfg.targets));
        boolean noTcp = cfg.ports != null && cfg.ports.length == 0;
        boolean noUdp = cfg.udpPorts == null || cfg.udpPorts.length == 0;
        boolean discovery = noTcp && noUdp && !cfg.udpScan;
        discoveryOnly.setSelected(discovery);
        if (discovery || cfg.ports == null && noUdp) {
            ports.setText("");
        } else {
            int[] udp = cfg.udpScan && cfg.udpPorts != null
                    && java.util.Arrays.equals(cfg.udpPorts, WellKnownPorts.TOP_20_UDP)
                    ? null : cfg.udpPorts;
            ports.setText(NMap.portSpec(cfg.ports, udp));
        }
        serviceDetection.setSelected(cfg.probeScan);
        probeMatch.select(cfg.probeMatch != null ? cfg.probeMatch : NMapConfig.ProbeMatch.FIRST);
        skipPing.setSelected(!cfg.discovery);
        upOnly.setSelected(cfg.upOnly);
        openOnly.setSelected(cfg.openOnly);
        NMapConfig.Timing t = NMapConfig.Timing.matching(cfg);
        if (t != null) timing.select(t);
        else {
            NMapConfig.Timing c = NMapConfig.Timing.closest(cfg);
            timing.select(c.matches(cfg) == 2 ? c : null);
        }
        maxInFlight.setText(Integer.toString(cfg.maxInFlight));
        minRtt.setText(Integer.toString(cfg.minRttTimeoutMs));
    }

    private void fieldsChanged() {
        if (syncing) return;
        syncing = true;
        try {
            NMapConfig cfg = toConfig();
            command.setText(NMap.formatCommand(cfg));
            message.clear();
            noteIgnoredPorts();
        } catch (IllegalArgumentException e) {
            message.error(e.getMessage());
        } finally {
            syncing = false;
        }
    }

    private void commandChanged() {
        if (syncing) return;
        syncing = true;
        try {
            String typed = command.getText().trim();
            if (typed.isEmpty()) {
                message.clear();
                return;
            }
            fill(NMap.parseCommand(typed));
            message.clear();
        } catch (IllegalArgumentException e) {
            message.error(e.getMessage());
        } finally {
            syncing = false;
        }
    }

    // ---- small builders ----

    /**
     * A labelled field with an optional hint. The hint wraps at a fixed width: driving its wrap
     * width from the panel's width ratchets (the label then reports that width as preferred, the
     * column grows, the width grows), which squeezed the Ports and Name columns to nothing.
     */
    private static JPanel field(NSAppUtil.ScanForm label, JComponent c, NSAppUtil.ScanForm hint) {
        return field(label, c, hint, null);
    }

    /** The same, with a helper (a link) at the right end of the label's line. */
    private static JPanel field(NSAppUtil.ScanForm label, JComponent c, NSAppUtil.ScanForm hint, JComponent helper) {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1, gapy 6, fillx", "[grow,fill]"));
        p.setOpaque(false);
        if (helper == null) p.add(label(label));
        else {
            JPanel head = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[]"));
            head.setOpaque(false);
            head.add(label(label));
            head.add(helper);
            p.add(head, "growx");
        }
        p.add(c, "growx, wmin 0");
        if (hint != null) {
            io.xlogistx.gui.WrapLabel h = GUIUtil.applyProp(FormPanel.hint(hint.getDisplayName()), hint);
            h.setWrapWidth(560);
            p.add(h, "wmin 0");
        }
        return p;
    }

    /** A field label worded and named by its descriptor. */
    private static JLabel label(NSAppUtil.ScanForm ref) {
        return GUIUtil.applyProp(FormPanel.fieldLabel(ref.getDisplayName(), false), ref);
    }

    /** The flag beside an option, in the mono face. */
    private static JLabel mono(NSAppUtil.ScanForm ref) {
        JLabel l = GUIUtil.applyProp(new JLabel(), ref);
        l.setFont(UITokens.mono(-1.5f));
        l.setForeground(UITokens.muted());
        return l;
    }
}
