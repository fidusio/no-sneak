package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.nosneak.v2.data.ProbeContent;
import io.xlogistx.nosneak.v2.data.ReportContent;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;

import io.xlogistx.nosneak.v2.nmap.NMap;
import io.xlogistx.nosneak.v2.nmap.NMapConfig;
import io.xlogistx.nosneak.v2.nmap.NMapScanner;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.output.OutputFormat;
import net.miginfocom.swing.MigLayout;
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
 * Two things here are less obvious than they look:
 * <ul>
 *   <li><b>Ticked probes are merged into the command, not applied behind it.</b> The effective
 *       string (typed text plus {@code -sV --probes …}) is what runs, what is shown under the
 *       field, and what is stored with the report — so a saved report always reproduces the scan
 *       that made it. Ticking implies {@code -sV} because the probe stage is skipped otherwise.</li>
 *   <li><b>A probe's name always comes from its JSON</b>, never from the name field. The engine
 *       matches {@code --probes} on the name inside the definition, so a typed name that disagrees
 *       produces a probe you can tick but that resolves to "unknown probe".</li>
 * </ul>
 *
 * @see io.xlogistx.nosneak.v2.nmap.NMap#parseCommand(String)
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
    private ReportContent selectedScan;
    private ProbeContent selectedProbe;

    private JTextArea viewScanTextArea;

    private JTextField viewProbeTitleArea;
    private JTextArea viewProbeTextArea;

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
            reloadScanResults();
            reloadProbes();
        }));

        JToggleButton scanButton = new JToggleButton("Scanner");
        scanButton.addActionListener(e -> cardStack.show("Scan"));

        JToggleButton probeButton = new JToggleButton("Probe Library");
        probeButton.addActionListener(e -> cardStack.show("Probe"));

        JToggleButton resultButton = new JToggleButton("Result List");
        resultButton.addActionListener(e -> cardStack.show("Result"));

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), scanButton, resultButton, probeButton));
    }

    private JPanel buildScanPanel() {
        JPanel out = new JPanel(new BorderLayout(0, 8));

        JPanel top = new JPanel(new BorderLayout(6, 0));
        JButton help = new JButton(new IconUtil.InfoIcon(16));
        help.setToolTipText("Usage");
        help.addActionListener(e -> showUsage());

        JButton run = new JButton("Run", new IconUtil.RunIcon(16));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(help);
        actions.add(run);

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
        JButton sendResultToChatButton = new JButton("Send to chat", new IconUtil.NextIcon(16));
        sendResultToChatButton.setEnabled(false);
        sendResultToChatButton.addActionListener(_ -> setSendToChat(resultText.getText(), lastScanName));
        result.add(sendResultToChatButton, BorderLayout.NORTH);
        result.add(new JScrollPane(resultText), BorderLayout.CENTER);

        JSplitPane split = PanelBuilder.buildHorizontalSplitView(buildProbeSelector(), result, 320, 0);

        out.add(top, BorderLayout.NORTH);
        out.add(split, BorderLayout.CENTER);

        run.addActionListener(_ -> {
            String typed = commandText.getText().trim();
            String effective;
            List<ProbeDefinition> selected;
            NMapConfig cfg;
            try {
                selected = selectedDefinitions();
                effective = effectiveCommand(typed, selected);
                cfg = NMap.parseCommand(effective);
                for (ProbeDefinition d : selected) {
                    if (!bundledProbes.contains(d)) cfg.extraProbe(d);
                }
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage() + "\n\n" + NMap.usageText(),
                        "Invalid command", JOptionPane.ERROR_MESSAGE);
                return;
            }
            effectiveLabel.setText(effective.equals(typed) ? " " : "effective: " + effective);
            String scanName = reportName(cfg);
            BackgroundTask.run(this, run, () -> scanNetwork(cfg), json -> {
                resultText.setText(json);
                resultText.setCaretPosition(0);
                lastScanName = scanName;
                sendResultToChatButton.setEnabled(true);
                ReportContent r = new ReportContent();
                r.setName(scanName);
                r.setDescription(effective);
                r.setContent(json);
                r.getProperties().build("command", effective);
                ctx.session().saveScanResult(r);
                reloadScanResults();
            });
        });

        return out;
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

    private List<ProbeDefinition> selectedDefinitions() {
        List<ProbeDefinition> out = new ArrayList<>();
        for (ProbeDefinition d : bundledProbes) {
            if (tickedProbes.contains(d.getName())) out.add(d);
        }
        for (ProbeContent p : probes) {
            if (p.getName() == null || !tickedProbes.contains(p.getName())) continue;
            try {
                out.add(ProbeDefinitionLoader.parse(p.getContent(), p.getName()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Probe '" + p.getName() + "' is not valid: " + e.getMessage(), e);
            }
        }
        return out;
    }

    private String effectiveCommand(String typed, List<ProbeDefinition> selected) {
        if (selected.isEmpty()) return typed;
        if (selected.size() == bundledProbes.size() + countNamedProbes()) return typed + " -sV";
        StringBuilder names = new StringBuilder();
        for (ProbeDefinition d : selected) {
            if (!names.isEmpty()) names.append(',');
            names.append(d.getName());
        }
        return typed + " -sV --probes " + names;
    }

    private int countNamedProbes() {
        int n = 0;
        for (ProbeContent p : probes) {
            if (p.getName() != null && !p.getName().isBlank()) n++;
        }
        return n;
    }

    private JComponent buildProbeSelector() {
        JScrollPane sp = new JScrollPane(probeSelector);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    private void rebuildProbeSelector() {
        probeSelector.removeAll();

        List<String> bundledNames = new ArrayList<>();
        Map<String, String> tooltips = new HashMap<>();
        for (ProbeDefinition d : bundledProbes) {
            bundledNames.add(d.getName());
            String tip = bundledTip(d);
            if (tip != null) tooltips.put(d.getName(), tip);
        }
        addProbeSection("Bundled probes", "", bundledNames, tooltips, "None loaded");

        List<String> myNames = new ArrayList<>();
        for (ProbeContent p : probes) {
            if (p.getName() != null && !p.getName().isBlank()) myNames.add(p.getName());
        }
        addProbeSection("My probes", "gaptop 10", myNames, Map.of(), "No probes yet");

        probeSelector.revalidate();
        probeSelector.repaint();
    }

    private void addProbeSection(String title, String titleGap, List<String> names,
                                 Map<String, String> tooltips, String emptyText) {
        probeSelector.add(sectionLabel(title), titleGap);

        if (names.isEmpty()) {
            probeSelector.add(emptyLabel(emptyText));
            return;
        }

        List<JCheckBox> rowBoxes = new ArrayList<>();
        JCheckBox allBox = new JCheckBox("All", tickedProbes.containsAll(names));
        allBox.setToolTipText("Select every probe in this group");
        allBox.addActionListener(_ -> {
            boolean on = allBox.isSelected();
            for (JCheckBox b : rowBoxes) b.setSelected(on);
            if (on) tickedProbes.addAll(names);
            else tickedProbes.removeAll(names);
        });
        probeSelector.add(allBox, "growx");

        for (String name : names) {
            JCheckBox box = new JCheckBox(name, tickedProbes.contains(name));
            String tip = tooltips.get(name);
            if (tip != null) box.setToolTipText(tip);
            box.addActionListener(_ -> {
                if (box.isSelected()) tickedProbes.add(name);
                else tickedProbes.remove(name);
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
                ProbeContent p = selectedProbe;
                if (!fillProbe(p, viewProbeTitleArea.getText().trim(), viewProbeTextArea.getText())) return;
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
     */
    public void saveProbeFromEditor(String name, String content) {
        ProbeContent p = new ProbeContent();
        if (!fillProbe(p, name, content)) return;
        BackgroundTask.run(this, null, () -> ctx.session().saveProbe(p), saved -> {
            reloadProbes();
            ctx.nav().show(Navigator.Screen.SCAN);
            cardStack.show("Probe");
            JOptionPane.showMessageDialog(this, "Saved probe \"" + p.getName() + "\".",
                    "Probe", JOptionPane.INFORMATION_MESSAGE);
        });
    }

    /**
     * Strips a markdown fence, validates, and writes the definition onto {@code target}. Both save
     * paths go through here so they cannot diverge on fence handling or on where the name comes
     * from — it is always the parsed definition's, since the engine matches {@code --probes} on the
     * name inside the JSON and a typed one that disagrees yields a probe that can't be selected.
     *
     * @return false when the content is not a valid probe; the reason has already been shown
     */
    private boolean fillProbe(ProbeContent target, String name, String content) {
        String json = fencedBlock(content);
        try {
            ProbeDefinition def = ProbeDefinitionLoader.parse(json, SUS.isEmpty(name) ? "probe" : name);
            target.setName(def.getName());
            target.setContent(json);
            return true;
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Not a valid probe", JOptionPane.ERROR_MESSAGE);
            return false;
        }
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
        CompletableFuture<ScanReport> future = new CompletableFuture<>();
        NMapScanner.scan(ctx.session().getNio(), cfg,
                new CallableConsumerTask<ScanReport>().setConsumer(future::complete));
        ScanReport report = future.get(NMap.maxWaitMs(cfg), TimeUnit.MILLISECONDS);

        return OutputFormat.formatter(OutputFormat.JSON).render(report);
    }

    public void setSendToChat(String content, String name) {
        if (SUS.isEmpty(content) || sendToChat == null) return;
        try {
            sendToChat.accept(content, SUS.isEmpty(name) ? "scan result" : name);
        } catch (SecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Send to chat", JOptionPane.WARNING_MESSAGE);
            return;
        }
        ctx.nav().show(Navigator.Screen.ASSISTANT);
    }
}