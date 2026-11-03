package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.gui.ChipPanel;
import io.xlogistx.gui.FormPanel;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.InlineMessage;
import io.xlogistx.gui.SegmentedControl;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.scan.nmap.NMap;
import io.xlogistx.scan.nmap.NMapConfig;
import io.xlogistx.scan.nmap.WellKnownPorts;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

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
 * says it; the <b>Match</b> segment ({@code --probe-match}) is the form's own.
 */
public class ScanFormPanel extends JPanel {

    /** What an empty Ports field means when no probe is ticked: the engine's default list ({@link NSAppUtil.ScanForm#PORTS_FIELD}'s placeholder). */
    public static final String PORTS_DEFAULT_HINT = NSAppUtil.ScanForm.PORTS_FIELD.getDisplayName();

    // every component is named, worded and described by NSAppUtil.ScanForm (the maintainer's rule, 2026-11-01)
    private final JTextField targets = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.TARGETS_FIELD);
    private final JTextField ports = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.PORTS_FIELD);
    private final JTextField name = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.NAME_FIELD);
    private final JCheckBox serviceDetection = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.SERVICE_DETECTION);
    private final JCheckBox discoveryOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.DISCOVERY_ONLY);
    private final JCheckBox skipPing = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.SKIP_PING);
    private final JCheckBox upOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.UP_ONLY);
    private final JCheckBox openOnly = GUIUtil.applyProp(new JCheckBox(), NSAppUtil.ScanForm.OPEN_ONLY);
    private final SegmentedControl timing = GUIUtil.applyProp(new SegmentedControl(NMapConfig.Timing.values()), NSAppUtil.ScanForm.TIMING_CONTROL);
    /** First / All — {@code --probe-match} (2026-10-31); the enum carries the labels and tooltips. */
    private final SegmentedControl probeMatch = GUIUtil.applyProp(new SegmentedControl(NMapConfig.ProbeMatch.values()), NSAppUtil.ScanForm.MATCH_CONTROL);
    private final JTextField maxInFlight = GUIUtil.applyProp(new JTextField(6), NSAppUtil.ScanForm.MAX_IN_FLIGHT_FIELD);
    private final JTextField minRtt = GUIUtil.applyProp(new JTextField(6), NSAppUtil.ScanForm.MIN_RTT_FIELD);
    private final JTextField command = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanForm.COMMAND_FIELD);
    private final InlineMessage message = GUIUtil.applyProp(new InlineMessage(), NSAppUtil.ScanForm.MESSAGE);
    private final JButton run = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/run.svg", 16, Color.WHITE)), NSAppUtil.ScanForm.RUN));
    private final JButton stop = GUIUtil.applyProp(new JButton(new IconUtil.StopIcon(16)), NSAppUtil.ScanForm.STOP);
    private final JButton help = GUIUtil.applyProp(new JButton(new IconUtil.InfoIcon(16)), NSAppUtil.ScanForm.HELP);
    private final JPanel probeSlot = GUIUtil.applyProp(new JPanel(new BorderLayout()), NSAppUtil.ScanForm.PROBE_SLOT);
    private boolean syncing;

    public ScanFormPanel() {
        super(new MigLayout("insets 20, fillx, wrap 1, gapy 12, hidemode 3", "[grow,fill]"));
        GUIUtil.applyProp(this, NSAppUtil.ScanForm.PANEL);
        setBackground(UITokens.surface());
        setBorder(BorderFactory.createLineBorder(UITokens.border()));

        targets.setFont(UITokens.mono(0));
        ports.setFont(UITokens.mono(0));
        maxInFlight.setFont(UITokens.mono(0));
        minRtt.setFont(UITokens.mono(0));
        command.setFont(UITokens.mono(-0.5f));
        command.setBackground(UITokens.color("xlogistx.chip", null, 0xF7F7FA));

        // row 1: targets · ports · name
        JPanel row1 = new JPanel(new MigLayout("insets 0, gapx 14, fillx", "[grow 5,fill][grow 3,fill][grow 4,fill]"));
        row1.setOpaque(false);
        row1.add(field(NSAppUtil.ScanForm.TARGETS, targets, NSAppUtil.ScanForm.TARGETS_HINT), "wmin 0");
        row1.add(field(NSAppUtil.ScanForm.PORTS, ports, null), "wmin 0");
        row1.add(field(NSAppUtil.ScanForm.NAME, name, null), "wmin 0");
        add(row1, "growx");

        // row 2: options
        JPanel options = new JPanel(new MigLayout("insets 0, gapx 18, gapy 6", "[]"));
        options.setOpaque(false);
        options.add(label(NSAppUtil.ScanForm.OPTIONS), "gapright 8");
        options.add(serviceDetection);
        options.add(mono(NSAppUtil.ScanForm.SERVICE_DETECTION_FLAG), "gapright 10");
        options.add(discoveryOnly);
        options.add(mono(NSAppUtil.ScanForm.DISCOVERY_ONLY_FLAG), "gapright 10");
        options.add(skipPing);
        options.add(mono(NSAppUtil.ScanForm.SKIP_PING_FLAG), "gapright 10");
        options.add(upOnly);
        options.add(mono(NSAppUtil.ScanForm.UP_ONLY_FLAG), "gapright 10");
        options.add(openOnly);
        options.add(mono(NSAppUtil.ScanForm.OPEN_ONLY_FLAG));
        for (JCheckBox b : new JCheckBox[]{serviceDetection, discoveryOnly, skipPing, upOnly, openOnly}) {
            b.setOpaque(false);
            b.addActionListener(_ -> fieldsChanged());
        }
        serviceDetection.addActionListener(_ -> {
            if (serviceDetectionToggled != null) serviceDetectionToggled.accept(serviceDetection.isSelected());
        });
        add(options, "growx");

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
        JPanel probeHead = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[][]"));
        probeHead.setOpaque(false);
        probeHead.add(label(NSAppUtil.ScanForm.PROBES));
        probeHead.add(label(NSAppUtil.ScanForm.MATCH));
        probeHead.add(probeMatch);
        probeBox.add(probeHead, "growx");
        probeSlot.setOpaque(false);
        probeBox.add(probeSlot, "growx, wmin 0");
        row3.add(probeBox, "aligny top, growx, pushx, wmin 200");
        add(row3, "growx");

        // row 4: the command
        JPanel cmdHead = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[]"));
        cmdHead.setOpaque(false);
        JLabel cmdLabel = label(NSAppUtil.ScanForm.COMMAND);
        JLabel cmdHint = GUIUtil.applyProp(FormPanel.hint(NSAppUtil.ScanForm.COMMAND_HINT.getDisplayName()), NSAppUtil.ScanForm.COMMAND_HINT);
        JPanel cmdLabels = new JPanel(new MigLayout("insets 0, gapx 8"));
        cmdLabels.setOpaque(false);
        cmdLabels.add(cmdLabel);
        cmdLabels.add(cmdHint);
        cmdHead.add(cmdLabels);
        JButton copy = GUIUtil.applyProp(new JButton(new IconUtil.CopyIcon(14)), NSAppUtil.ScanForm.COPY);
        copy.putClientProperty("JButton.buttonType", "toolBarButton");
        copy.addActionListener(_ -> {
            String text = command.getText();
            if (!text.isBlank()) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        });
        cmdHead.add(copy);
        JPanel cmdRow = new JPanel(new MigLayout("insets 0, gapx 10, fillx", "[grow,fill][][][]"));
        cmdRow.setOpaque(false);
        cmdRow.add(command, "growx");
        cmdRow.add(help);
        cmdRow.add(run);
        stop.setEnabled(false);
        cmdRow.add(stop);
        JPanel cmdBox = new JPanel(new MigLayout("insets 14 0 0 0, wrap 1, gapy 6, fillx", "[grow,fill]"));
        cmdBox.setOpaque(false);
        cmdBox.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UITokens.border()));
        cmdBox.add(cmdHead, "growx");
        cmdBox.add(cmdRow, "growx");
        cmdBox.add(message, "growx");
        add(cmdBox, "growx");

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
        NMapConfig cfg;
        String typed = command.getText().trim();
        try {
            cfg = typed.isEmpty() ? new NMapConfig() : NMap.parseCommand(typed);
        } catch (IllegalArgumentException e) {
            cfg = new NMapConfig();
        }
        overlay(cfg);
        if (cfg.targets.isEmpty()) throw new IllegalArgumentException("at least one target is required");
        return cfg;
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
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1, gapy 6, fillx", "[grow,fill]"));
        p.setOpaque(false);
        p.add(label(label));
        p.add(c, "growx, wmin 0");
        if (hint != null) {
            io.xlogistx.gui.WrapLabel h = GUIUtil.applyProp(FormPanel.hint(hint.getDisplayName()), hint);
            h.setWrapWidth(360);
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
