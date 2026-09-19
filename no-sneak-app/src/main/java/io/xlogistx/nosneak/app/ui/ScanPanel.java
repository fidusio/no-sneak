package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.data.ReportContent;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;

import io.xlogistx.nosneak.nmap.NMap;
import io.xlogistx.nosneak.nmap.NMapConfig;
import io.xlogistx.nosneak.nmap.NMapScanner;
import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.task.CallableConsumerTask;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code SCAN} screen — the front end for {@code no-sneak-core}'s v2 scanning engine. Five
 * cards behind three selectors: run a scan, browse stored results, and manage the probe library.
 * <p>
 * Three things here are less obvious than they look:
 * <ul>
 *   <li><b>Ticked probes are applied to the parsed {@link NMapConfig}, never spliced into the
 *       command string.</b> A probe name is free text (an assistant-authored one is often
 *       {@code "Redis TLS handshake"}), and {@code NMap.parseCommand} splits on whitespace — so a
 *       name spliced into {@code --probes} used to turn its words into scan <i>targets</i>. The
 *       typed command is the only thing parsed; ticks become {@code probeScan(true)},
 *       {@code probe(name)} and {@code extraProbe(def)} on the result, and the muted line under
 *       the field shows them as a list. The stored report keeps the typed command in
 *       {@code command} and the probe names in {@code probes}, separately.</li>
 *   <li><b>Ticks are keyed by identity, not by name.</b> A bundled probe is {@code b:<name>}; a
 *       stored one is {@code s:<guid>}. A stored probe that happens to share a bundled name is a
 *       different checkbox with its own state, and renaming a stored probe does not orphan its
 *       tick.</li>
 *   <li><b>A probe's name always comes from its JSON</b>, never from the name field. The engine
 *       matches {@code --probes} on the name inside the definition, so a typed name that disagrees
 *       produces a probe you can tick but that resolves to "unknown probe". Saving a definition
 *       whose name already exists in the library <i>updates</i> that row rather than adding a
 *       second one, so a probe fixed twice in the assistant is still one probe.</li>
 * </ul>
 * Everything the previous subject left on screen is cleared on every login and logout
 * ({@link #resetPanel()}): a scan report is that subject's network topology.
 *
 * @see io.xlogistx.nosneak.nmap.NMap#parseCommand(String)
 */
public class ScanPanel extends JPanel {
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final CardStack cardStack = new CardStack();
    private final AppContext ctx;

    private ListSection<ReportContent> resultList;
    private ListSection<ProbeContent> probeList;
    private List<ReportContent> scanResults = List.of();
    private List<ProbeContent> probes = List.of();

    private final JTextField nameText = new JTextField(16);
    private final JTextField commandText = new JTextField(30);
    private final JLabel effectiveLabel = new JLabel(" ");
    private final JTextArea resultText = new JTextArea();
    private final JButton sendResultToChatButton = new JButton("Send to chat", new IconUtil.NextIcon(16));
    /** Enabled only while a scan runs; stops it through the scanner's handle. */
    private final JButton stopButton = new JButton("Stop", new IconUtil.StopIcon(16));
    /** The scan in progress, or null. Set on the worker, read on the EDT by the Stop button. */
    private volatile NMapScanner.ScanHandle running;
    private ReportContent selectedScan;
    private ProbeContent selectedProbe;

    private JTextArea viewScanTextArea;

    private JTextField viewProbeTitleArea;
    private JTextArea viewProbeTextArea;

    /** Tick keys — see {@link ProbeSelection#bundledKey} and {@link ProbeSelection#storedKey}. */
    private final Set<String> tickedProbes = new HashSet<>();
    private final JPanel probeSelector = new JPanel(new MigLayout("wrap 1, insets 8, gapy 2", "[grow]"));
    private List<ProbeDefinition> bundledProbes = List.of();

    private final BiConsumer<String, String> sendToChat;
    private String lastScanName = "";

    public ScanPanel(AppContext ctx, BiConsumer<String, String> sendToChat) {
        this.ctx = ctx;

        this.sendToChat = sendToChat;

        setLayout(new BorderLayout());
        cardStack.add(buildScanPanel(), "Scan");
        cardStack.add(buildProbePanel(), "Probe");
        cardStack.add(buildResultPanel(), "Result");
        cardStack.add(buildViewScanResult(), "View_scan");
        cardStack.add(buildEditProbe(), "Edit_probe");

        rebuildProbeSelector();

        ctx.session().onAuthChange(e -> SwingUtilities.invokeLater(() -> {
            // Login or logout, the previous subject's data leaves the screen first. Only a
            // signed-in subject then gets their own rows loaded back.
            resetPanel();
            if (Boolean.TRUE.equals(e.getNewValue())) {
                reloadScanResults();
                reloadProbes();
            }
        }));

        JToggleButton scanButton = new JToggleButton("Scanner");
        scanButton.addActionListener(e -> cardStack.show("Scan"));

        JToggleButton probeButton = new JToggleButton("Probe Library");
        probeButton.addActionListener(e -> cardStack.show("Probe"));

        JToggleButton resultButton = new JToggleButton("Result List");
        resultButton.addActionListener(e -> cardStack.show("Result"));

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), scanButton, resultButton, probeButton));
    }

    /**
     * Clears every field, list, selection and tick that could carry one subject's data to the
     * next, and returns to the Scanner card. Called on every auth change; safe to call at any
     * time from the EDT.
     */
    public void resetPanel() {
        nameText.setText("");
        commandText.setText("");
        effectiveLabel.setText(" ");
        resultText.setText("");
        lastScanName = "";
        sendResultToChatButton.setEnabled(false);
        selectedScan = null;
        selectedProbe = null;
        if (viewScanTextArea != null) viewScanTextArea.setText("");
        if (viewProbeTextArea != null) viewProbeTextArea.setText("");
        if (viewProbeTitleArea != null) viewProbeTitleArea.setText("");
        tickedProbes.clear();
        // A scan the departing subject started must not keep probing on their behalf.
        onStop();
        scanResults = List.of();
        probes = List.of();
        if (resultList != null) resultList.refresh();
        if (probeList != null) probeList.refresh();
        rebuildProbeSelector();
        cardStack.show("Scan");
    }

    private JPanel buildScanPanel() {
        JPanel out = new JPanel(new BorderLayout(0, 8));

        JPanel top = new JPanel(new BorderLayout(6, 0));
        JButton help = new JButton(new IconUtil.InfoIcon(16));
        help.setToolTipText("Usage");
        help.addActionListener(e -> showUsage());

        JButton run = new JButton("Run", new IconUtil.RunIcon(16));
        stopButton.setEnabled(false);
        stopButton.setToolTipText("Stop the running scan; what completed so far is shown, nothing is saved");
        stopButton.addActionListener(_ -> onStop());
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(help);
        actions.add(run);
        actions.add(stopButton);

        effectiveLabel.setFont(effectiveLabel.getFont().deriveFont(effectiveLabel.getFont().getSize2D() - 2f));
        effectiveLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel fields = new JPanel(new MigLayout("insets 0, gapx 10, wrap 3", "[180!][grow][]", "[][]"));
        fields.add(new JLabel("Name"));
        fields.add(new JLabel("Command"));
        fields.add(new JLabel());
        fields.add(nameText, "growx");
        fields.add(commandText, "growx");
        fields.add(actions);

        top.add(fields, BorderLayout.CENTER);
        top.add(effectiveLabel, BorderLayout.SOUTH);
        top.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        resultText.setEditable(false);

        JPanel result = new JPanel(new BorderLayout());
        sendResultToChatButton.setEnabled(false);
        sendResultToChatButton.addActionListener(_ -> setSendToChat(resultText.getText(), lastScanName));
        result.add(sendResultToChatButton, BorderLayout.NORTH);
        result.add(new JScrollPane(resultText), BorderLayout.CENTER);

        JSplitPane split = PanelBuilder.buildHorizontalSplitView(buildProbeSelector(), result, 320, 0);

        out.add(top, BorderLayout.NORTH);
        out.add(split, BorderLayout.CENTER);

        run.addActionListener(_ -> onRun(run));

        return out;
    }

    /**
     * What one press of Run produced. {@code json} is always the rendered report — partial when
     * the scan was stopped; {@code stopped} is the message to show in that case (timeout or the
     * Stop button), and null when the scan ran to completion.
     */
    private record ScanOutcome(String json, String stopped) {}

    /** Stop button: cancel the scan in flight. Idempotent; the worker delivers the partial report. */
    private void onStop() {
        NMapScanner.ScanHandle h = running;
        if (h != null) {
            h.cancel();
        }
        stopButton.setEnabled(false);
    }

    private void onRun(JButton run) {
        String typed = commandText.getText().trim();
        NMapConfig cfg;
        ProbeSelection.Selection selected;
        try {
            cfg = NMap.parseCommand(typed);
            selected = ProbeSelection.select(bundledProbes, probes, tickedProbes);
            ProbeSelection.applyTo(cfg, selected);
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage() + "\n\n" + NMap.usageText(),
                    "Invalid command", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String probeNames = ProbeSelection.describe(selected);
        effectiveLabel.setText(probeNames.isEmpty() ? " " : "probes: " + probeNames);
        String scanName = reportName(cfg);
        String subjectAtStart = ctx.session().getSubjectGUID();

        stopButton.setEnabled(true);
        BackgroundTask.run(this, run, () -> runScan(cfg), outcome -> {
            stopButton.setEnabled(false);
            if (outcome.stopped() != null) {
                // Stopped by the subject or by the wait budget: show what completed, save nothing.
                resultText.setText(outcome.json() == null ? "" : outcome.json());
                resultText.setCaretPosition(0);
                sendResultToChatButton.setEnabled(false);
                JOptionPane.showMessageDialog(this, outcome.stopped(), "Scan stopped",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            // The scan belongs to whoever started it. If that subject is gone, so is the report.
            if (!ctx.session().isAuthenticated()
                    || !Objects.equals(subjectAtStart, ctx.session().getSubjectGUID())) {
                JOptionPane.showMessageDialog(this,
                        "The session that started this scan has ended; the report was not saved.",
                        "Scan", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String json = outcome.json();
            resultText.setText(json);
            resultText.setCaretPosition(0);
            lastScanName = scanName;
            sendResultToChatButton.setEnabled(true);
            ReportContent r = new ReportContent();
            r.setName(scanName);
            r.setDescription(probeNames.isEmpty() ? typed : typed + "  ·  probes: " + probeNames);
            r.setContent(json);
            r.getProperties().build("command", typed);
            if (!probeNames.isEmpty()) r.getProperties().build("probes", probeNames);
            // Encrypting and inserting a report is store I/O: off the EDT, like every other
            // Session call in this file, and a failure is a dialog rather than a frozen UI.
            BackgroundTask.runCatching(this, null, () -> ctx.session().saveScanResult(r),
                    this::reloadScanResults);
        });
    }

    /**
     * The label a scan is filed under — the subject's own name for it, falling back to the
     * targets so a report is never nameless. It becomes the report's name, the Result List row
     * label, and the attachment label when the report is sent to a chat, so it is deliberately
     * short: the full command lives in the report's description.
     */
    private String reportName(NMapConfig cfg) {
        String typed = nameText.getText().trim();
        return typed.isEmpty() ? String.join(" ", cfg.targets) : typed;
    }

    /**
     * The pure half of the scanner card: how ticks map onto an {@link NMapConfig}, how they are
     * described, what a timeout says, and which stored row a saved definition replaces. Static
     * and Swing-free so {@code ScanPanelTest} can pin every rule without a display.
     */
    static final class ProbeSelection {

        /** What the ticks resolved to: bundled probes by name, stored probes as definitions. */
        record Selection(List<String> bundledNames, List<ProbeDefinition> stored) {
            boolean isEmpty() {
                return bundledNames.isEmpty() && stored.isEmpty();
            }
        }

        private ProbeSelection() {}

        static String bundledKey(String name) {
            return "b:" + name;
        }

        /** A stored row's identity; falls back to the name only for a row that was never saved. */
        static String storedKey(ProbeContent p) {
            String guid = p.getGUID();
            return SUS.isNotEmpty(guid) ? "s:" + guid : "s:name:" + p.getName();
        }

        /**
         * Resolves the ticked keys. A stored probe's JSON is parsed here so an invalid one is a
         * clear message naming the probe, not an engine failure later.
         *
         * @throws IllegalArgumentException when a ticked stored probe is not a valid definition
         */
        static Selection select(List<ProbeDefinition> bundled, List<ProbeContent> stored,
                                Set<String> ticks) {
            List<String> names = new ArrayList<>();
            for (ProbeDefinition d : bundled) {
                if (ticks.contains(bundledKey(d.getName()))) names.add(d.getName());
            }
            List<ProbeDefinition> extras = new ArrayList<>();
            for (ProbeContent p : stored) {
                if (p.getName() == null || !ticks.contains(storedKey(p))) continue;
                try {
                    extras.add(ProbeDefinitionLoader.parse(p.getContent(), p.getName()));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(
                            "Probe '" + p.getName() + "' is not valid: " + e.getMessage(), e);
                }
            }
            return new Selection(names, extras);
        }

        /**
         * Applies the selection to the parsed config. Ticking implies {@code -sV}: the probe
         * stage returns early when {@code probeScan} is false, so ticked probes with no
         * {@code -sV} would silently do nothing. Names never pass through the command string.
         */
        static void applyTo(NMapConfig cfg, Selection sel) {
            if (sel.isEmpty()) return;
            cfg.probeScan(true);
            for (String name : sel.bundledNames()) cfg.probe(name);
            for (ProbeDefinition d : sel.stored()) {
                cfg.extraProbe(d);
                cfg.probe(d.getName());
            }
        }

        /** The ticked names as a comma-separated list, for display and for the report. */
        static String describe(Selection sel) {
            List<String> names = new ArrayList<>(sel.bundledNames());
            for (ProbeDefinition d : sel.stored()) names.add(d.getName());
            return String.join(", ", names);
        }

        /** What the subject reads when the wait budget runs out. The scan has been stopped. */
        static String timeoutMessage(NMapConfig cfg, long budgetMs) {
            long seconds = Math.max(1, (budgetMs + 999) / 1000);
            return "Scan timed out after " + seconds + " s: " + String.join(" ", cfg.targets)
                    + "\nThe scan was stopped; what completed is shown and nothing was saved."
                    + " A narrower range, fewer ports, or -t with a longer per-connection timeout"
                    + " gives it room.";
        }

        /** What the subject reads after pressing Stop. */
        static String cancelledMessage(ScanReport report) {
            return NMapScanner.progress(report).cancelledLine()
                    + "\nWhat completed is shown; nothing was saved.";
        }

        /** The stored row a definition with this name would replace, or null when it is new. */
        static ProbeContent existingByName(List<ProbeContent> stored, String name) {
            if (name == null) return null;
            for (ProbeContent p : stored) {
                if (name.equals(p.getName()) && SUS.isNotEmpty(p.getGUID())) return p;
            }
            return null;
        }
    }

    private JComponent buildProbeSelector() {
        JScrollPane sp = new JScrollPane(probeSelector);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    /** One checkbox row: the label shown and the tick key behind it. */
    private record ProbeRow(String key, String label, String tooltip) {}

    private void rebuildProbeSelector() {
        probeSelector.removeAll();

        List<ProbeRow> bundledRows = new ArrayList<>();
        for (ProbeDefinition d : bundledProbes) {
            bundledRows.add(new ProbeRow(ProbeSelection.bundledKey(d.getName()), d.getName(), bundledTip(d)));
        }
        addProbeSection("Bundled probes", "", bundledRows, "None loaded");

        List<ProbeRow> myRows = new ArrayList<>();
        for (ProbeContent p : probes) {
            if (p.getName() != null && !p.getName().isBlank()) {
                myRows.add(new ProbeRow(ProbeSelection.storedKey(p), p.getName(), null));
            }
        }
        addProbeSection("My probes", "gaptop 10", myRows, "No probes yet");

        probeSelector.revalidate();
        probeSelector.repaint();
    }

    private void addProbeSection(String title, String titleGap, List<ProbeRow> rows, String emptyText) {
        probeSelector.add(sectionLabel(title), titleGap);

        if (rows.isEmpty()) {
            probeSelector.add(emptyLabel(emptyText));
            return;
        }

        List<String> keys = rows.stream().map(ProbeRow::key).toList();
        List<JCheckBox> rowBoxes = new ArrayList<>();
        JCheckBox allBox = new JCheckBox("All", tickedProbes.containsAll(keys));
        allBox.setToolTipText("Select every probe in this group");
        allBox.addActionListener(_ -> {
            boolean on = allBox.isSelected();
            for (JCheckBox b : rowBoxes) b.setSelected(on);
            if (on) tickedProbes.addAll(keys);
            else tickedProbes.removeAll(keys);
        });
        probeSelector.add(allBox, "growx");

        for (ProbeRow row : rows) {
            JCheckBox box = new JCheckBox(row.label(), tickedProbes.contains(row.key()));
            if (row.tooltip() != null) box.setToolTipText(row.tooltip());
            box.addActionListener(_ -> {
                if (box.isSelected()) tickedProbes.add(row.key());
                else tickedProbes.remove(row.key());
                allBox.setSelected(!rowBoxes.isEmpty() && rowBoxes.stream().allMatch(AbstractButton::isSelected));
            });
            rowBoxes.add(box);
            probeSelector.add(box, "growx, gapleft 12");
        }
    }

    private static String bundledTip(ProbeDefinition d) {
        StringBuilder sb = new StringBuilder();
        if (d.getService() != null) sb.append(d.getService());
        int[] ports = d.getPorts();
        if (ports != null && ports.length > 0) {
            if (!sb.isEmpty()) sb.append(" · ");
            for (int i = 0; i < ports.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(ports[i]);
            }
        }
        return sb.isEmpty() ? null : sb.toString();
    }

    private static JLabel sectionLabel(String text) {
        JLabel label = new JLabel(text.toUpperCase());
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() - 2f));
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        return label;
    }

    private static JLabel emptyLabel(String text) {
        JLabel label = new JLabel(text);
        label.setEnabled(false);
        return label;
    }

    private void showUsage() {
        JTextArea text = new JTextArea(NMap.usageText());
        text.setEditable(false);
        text.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JOptionPane.showMessageDialog(this, new JScrollPane(text), "Usage", JOptionPane.INFORMATION_MESSAGE);
    }

    private JPanel buildProbePanel() {
        probeList = ListSection.of(() -> probes)
                .title("Probe List")
                .label(ProbeContent::getName)
                .addButton("+ add probe", () -> onEditProbe(new ProbeContent()))
                .onEdit(p -> () -> onEditProbe(p))
                .onRemove(p -> () -> onRemoveProbe(p))
                .emptyText("No probes yet")
                .scrollable()
                .search()
                .build();

        return probeList;
    }

    private JPanel buildResultPanel() {
        resultList = ListSection.of(() -> scanResults)
                .title("Scan Results")
                .label(ReportContent::getName)
                .sublabel(ScanPanel::stampOf)
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Send to chat", s -> () -> onSendScanResult(s)))
                .action(new ListSection.RowAction<>(new IconUtil.VisibleIcon(16), "View", s -> () -> onViewScanResult(s)))
                .onRemove(s -> () -> onRemoveScanResult(s))
                .emptyText("No scans yet")
                .scrollable()
                .build();

        return resultList;
    }

    private void onSendScanResult(ReportContent row) {
        if (row == null) return;
        BackgroundTask.run(this, null, () -> ctx.session().getScanResult(row.getGUID()), full -> {
            if (full == null) {
                JOptionPane.showMessageDialog(this, "That scan result is no longer available.",
                        "Not found", JOptionPane.WARNING_MESSAGE);
                reloadScanResults();
                return;

            }
            setSendToChat(full.getContent(), full.getName());
        });
    }

    private static String stampOf(ReportContent scan) {
        long created = scan.getCreationTime();
        String when = created > 0 ? STAMP.format(Instant.ofEpochMilli(created)) : null;
        String command = SUS.trimOrNull(scan.getDescription());
        if (command == null) return when;
        return when == null ? command : command + "  ·  " + when;
    }

    private void reloadScanResults() {
        BackgroundTask.run(this, null, () -> ctx.session().getAllScanResults(), loaded -> {
            scanResults = loaded;
            resultList.refresh();
        });
    }

    private void reloadProbes() {
        BackgroundTask.run(this, null, () -> {
            if (bundledProbes.isEmpty()) bundledProbes = ProbeDefinitionLoader.loadBundled();
            return ctx.session().getAllProbes();
        }, loaded -> {
            probes = loaded;
            // A tick for a row that no longer exists (deleted, or another subject's) is dropped
            // here rather than kept forever in the set.
            Set<String> live = new HashSet<>();
            for (ProbeDefinition d : bundledProbes) live.add(ProbeSelection.bundledKey(d.getName()));
            for (ProbeContent p : probes) live.add(ProbeSelection.storedKey(p));
            tickedProbes.retainAll(live);
            probeList.refresh();
            rebuildProbeSelector();
        });
    }

    private void onViewScanResult(ReportContent row) {
        if (row == null) return;
        BackgroundTask.run(this, null, () -> ctx.session().getScanResult(row.getGUID()), full -> {
            if (full == null) {
                JOptionPane.showMessageDialog(this, "That scan result is no longer available.",
                        "Not found", JOptionPane.WARNING_MESSAGE);
                reloadScanResults();
                return;
            }
            this.selectedScan = full;
            viewScanTextArea.setText(full.getContent());
            viewScanTextArea.setCaretPosition(0);
            cardStack.show("View_scan");
        });
    }

    private JPanel buildViewScanResult() {
        viewScanTextArea = new JTextArea();
        viewScanTextArea.setEditable(false);
        viewScanTextArea.setLineWrap(true);
        viewScanTextArea.setWrapStyleWord(true);

        return PanelBuilder.detail("View Scan Result", () -> cardStack.show("Result"), content -> {
            JPanel body = new JPanel(new BorderLayout());

            JButton copy = new JButton(new IconUtil.CopyIcon(16));
            copy.addActionListener(e -> {
                StringSelection sel = new StringSelection(viewScanTextArea.getText());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            });
            JButton sendButton = new JButton("Send to chat", new IconUtil.NextIcon(16));
            sendButton.setEnabled(sendToChat != null);
            sendButton.addActionListener(e -> {
                if (selectedScan == null) return;
                setSendToChat(selectedScan.getContent(), selectedScan.getName());
            });
            content.add(copy, "gapbottom 6");
            content.add(sendButton, "gapbottom 6");

            body.add(new JScrollPane(viewScanTextArea), BorderLayout.CENTER);

            content.add(body, "grow, push");
        });
    }

    private void onRemoveScanResult(ReportContent reportContent) {
        BackgroundTask.runCatching(this, null, () -> ctx.session().deleteScanResult(reportContent),
                this::reloadScanResults);
    }

    private void onEditProbe(ProbeContent probeContent) {
        if (probeContent == null) return;
        this.selectedProbe = probeContent;
        viewProbeTextArea.setText(Objects.toString(probeContent.getContent(), ""));
        viewProbeTitleArea.setText(Objects.toString(probeContent.getName(), ""));
        viewProbeTextArea.setCaretPosition(0);
        cardStack.show("Edit_probe");
    }

    private JPanel buildEditProbe() {
        viewProbeTextArea = new JTextArea();
        viewProbeTextArea.setEditable(true);
        viewProbeTextArea.setLineWrap(true);
        viewProbeTextArea.setWrapStyleWord(true);

        viewProbeTitleArea = new JTextField();

        return PanelBuilder.detail("Edit Probe", () -> cardStack.show("Probe"), content -> {
            JPanel body = new JPanel(new BorderLayout());

            JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
            save.addActionListener(e -> {
                if (selectedProbe == null) return;
                ProbeContent p;
                try {
                    p = probeToSave(selectedProbe, viewProbeTitleArea.getText().trim(), viewProbeTextArea.getText());
                } catch (IllegalArgumentException ex) {
                    JOptionPane.showMessageDialog(this, ex.getMessage(), "Not a valid probe", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // The name is the definition's, so show what actually got stored.
                viewProbeTitleArea.setText(p.getName());
                BackgroundTask.run(this, save, () -> ctx.session().saveProbe(p), saved -> {
                    selectedProbe = saved;
                    reloadProbes();
                    cardStack.show("Probe");
                });
            });
            content.add(save, "gapbottom 6");

            body.add(viewProbeTitleArea, BorderLayout.NORTH);
            body.add(new JScrollPane(viewProbeTextArea), BorderLayout.CENTER);

            content.add(body, "grow, push");
        });
    }

    /**
     * Stores a probe authored elsewhere — the AI assistant's editor, today. The name comes from
     * the parsed definition, never the caller's: the engine matches {@code --probes} on the name
     * inside the JSON, so a typed one that disagrees would produce a probe that can't be selected.
     * A definition whose name is already in the library updates that row.
     *
     * @throws IllegalArgumentException when the content is not a valid probe — the caller owns
     *                                  the editor and shows the message there, so the draft stays
     *                                  open and dirty rather than reading as saved
     */
    public void saveProbeFromEditor(String name, String content) {
        ProbeContent p = probeToSave(new ProbeContent(), name, content);
        boolean updated = SUS.isNotEmpty(p.getGUID());
        BackgroundTask.run(this, null, () -> ctx.session().saveProbe(p), saved -> {
            reloadProbes();
            ctx.nav().show(Navigator.Screen.SCAN);
            cardStack.show("Probe");
            JOptionPane.showMessageDialog(this,
                    (updated ? "Updated probe \"" : "Saved probe \"") + p.getName() + "\".",
                    "Probe", JOptionPane.INFORMATION_MESSAGE);
        });
    }

    /**
     * Strips a markdown fence, validates, and returns the row to save: {@code target} itself when
     * it is an existing row, otherwise the library row that already carries the definition's name
     * (so a re-save updates instead of duplicating), otherwise {@code target} as a new row. Both
     * save paths go through here so they cannot diverge on fence handling, on where the name
     * comes from — always the parsed definition's — or on the dedupe rule.
     *
     * @throws IllegalArgumentException when the content is not a valid probe, with the reason
     */
    private ProbeContent probeToSave(ProbeContent target, String name, String content) {
        String json = fencedBlock(content);
        ProbeDefinition def = ProbeDefinitionLoader.parse(json, SUS.isEmpty(name) ? "probe" : name);
        ProbeContent row = target;
        if (SUS.isEmpty(target.getGUID())) {
            ProbeContent existing = ProbeSelection.existingByName(probes, def.getName());
            if (existing != null) row = existing;
        }
        row.setName(def.getName());
        row.setContent(json);
        return row;
    }

    private static String fencedBlock(String markdown) {
        if (markdown == null) return "";
        Matcher m = Pattern.compile("```[a-zA-Z]*\\s*\\n(.*?)```", Pattern.DOTALL).matcher(markdown);
        return m.find() ? m.group(1) : markdown.trim();
    }

    private void onRemoveProbe(ProbeContent probeContent) {
        BackgroundTask.runCatching(this, null, () -> ctx.session().deleteProbe(probeContent),
                this::reloadProbes);
    }

    public String scanNetwork(String command)
            throws ExecutionException, InterruptedException, TimeoutException {
        return scanNetwork(NMap.parseCommand(command));
    }

    public String scanNetwork(NMapConfig cfg)
            throws ExecutionException, InterruptedException, TimeoutException {
        ScanOutcome outcome = runScan(cfg);
        if (outcome.stopped() != null) {
            throw new TimeoutException(outcome.stopped());
        }
        return outcome.json();
    }

    /**
     * Runs one scan on the worker thread and always comes back with a rendered report. A wait
     * budget that runs out or a press of Stop cancels the scan through its handle — nothing keeps
     * running in the background — and the partial report is rendered with the reason.
     */
    private ScanOutcome runScan(NMapConfig cfg) throws ExecutionException, InterruptedException {
        long budgetMs = NMap.maxWaitMs(cfg);
        CompletableFuture<ScanReport> future = new CompletableFuture<>();
        NMapScanner.ScanHandle handle = NMapScanner.scan(ctx.session().getNio(), cfg,
                new CallableConsumerTask<ScanReport>().setConsumer(future::complete));
        running = handle;
        try {
            ScanReport report;
            String stopped = null;
            try {
                report = future.get(budgetMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                handle.cancel();
                stopped = ProbeSelection.timeoutMessage(cfg, budgetMs);
                try {
                    report = future.get(10, TimeUnit.SECONDS);
                } catch (TimeoutException late) {
                    return new ScanOutcome(null, stopped);
                }
            }
            String json = OutputFormat.formatter(OutputFormat.JSON).render(report);
            if (stopped == null && report.cancelled) {
                stopped = ProbeSelection.cancelledMessage(report);
            }
            return new ScanOutcome(json, stopped);
        } finally {
            running = null;
        }
    }

    public void setSendToChat(String content, String name) {
        if (SUS.isEmpty(content) || sendToChat == null) return;
        try {
            sendToChat.accept(content, SUS.isEmpty(name) ? "scan result" : name);
        } catch (AccessSecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Send to chat", JOptionPane.WARNING_MESSAGE);
            return;
        }
        ctx.nav().show(Navigator.Screen.ASSISTANT);
    }
}
