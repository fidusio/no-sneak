package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.ui.scan.ProbeLibraryModel;
import io.xlogistx.nosneak.app.ui.scan.ScanFormPanel;
import io.xlogistx.nosneak.app.ui.scan.ScanResultView;
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
import javax.swing.table.TableRowSorter;
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

    private final HistoryModel historyModel = new HistoryModel();
    private final JTable historyTable = new JTable(historyModel);
    private final JButton historyDeleteAll = new JButton("Delete all", new IconUtil.DeleteIcon(16));
    private final TableRowSorter<HistoryModel> historySorter = new TableRowSorter<>(historyModel);
    private final JLabel historyCount = new JLabel();
    // The Probe library (2026-10-26): every probe a scan can run, bundled and stored, with a
    // detail pane that shows the selected one read-only; see buildProbePanel.
    private final ProbeLibraryModel libraryModel = new ProbeLibraryModel();
    private final JTable libraryTable = new JTable(libraryModel);
    private final TableRowSorter<ProbeLibraryModel> librarySorter = new TableRowSorter<>(libraryModel);
    private final JTextField librarySearch = new JTextField();
    private final SegmentedControl libraryFilter = new SegmentedControl("All", "Bundled", "Mine");
    private final JLabel libraryCount = new JLabel();
    private final CardStack libraryDetail = new CardStack();
    private final JLabel probeTitle = new JLabel();
    private final KeyValuePanel probeFacts = new KeyValuePanel(110);
    private final JTextArea probeSource = new JTextArea();
    private final InlineMessage probeProblem = new InlineMessage();
    private final JButton copyProbe = new JButton("Copy to my probes", new IconUtil.CopyIcon(16));
    private final JButton editProbe = new JButton("Edit", new IconUtil.EditIcon(16));
    private final JButton deleteProbe = new JButton("Delete", new IconUtil.DeleteIcon(16));
    /** The bundled files' JSON text by probe name, read once with the definitions. */
    private Map<String, String> bundledSources = Map.of();
    private MDViewerPanel definitionView;
    private List<ReportContent> scanResults = List.of();
    private List<ProbeContent> probes = List.of();

    /** The scan set-up: fields that generate the command, and the command that refills them (2026-10-24). */
    private final ScanFormPanel form = new ScanFormPanel();
    /** The ticked probes as chips; the ticks themselves live in {@link #tickedProbes}. */
    private final ChipPanel probeChips = new ChipPanel();
    /** The fresh run's report as tables, under the form. */
    private final ScanResultView resultView;
    /** A stored report opened from history, on its own card. */
    private final ScanResultView storedView;
    /** Enabled only while a scan runs; stops it through the scanner's handle. The form owns the button. */
    private final JButton stopButton;
    /** The scan in progress, or null. Set on the worker, read on the EDT by the Stop button. */
    private volatile NMapScanner.ScanHandle running;
    private ReportContent selectedScan;
    private ProbeContent selectedProbe;

    // The probe editor (2026-10-26): the name is read from the JSON, Check validates inline
    private final JLabel editTitle = new JLabel();
    private final JLabel editName = new JLabel();
    private final InlineMessage editCheck = new InlineMessage();
    private JTextArea viewProbeTextArea;

    /** Tick keys — see {@link ProbeSelection#bundledKey} and {@link ProbeSelection#storedKey}. */
    private final Set<String> tickedProbes = new HashSet<>();
    private List<ProbeDefinition> bundledProbes = List.of();

    /**
     * How this panel hands content to the assistant: a text attachment with a short label, and
     * (2026-10-26) optionally a request typed into the composer. Null composer text = attach only.
     * Throws {@link AccessSecurityException} when the assistant has nowhere to put it (no open chat).
     */
    @FunctionalInterface
    public interface ChatHandoff {
        void send(String text, String name, String composerText);
    }

    private final ChatHandoff sendToChat;

    public ScanPanel(AppContext ctx, ChatHandoff sendToChat) {
        this.ctx = ctx;
        this.sendToChat = sendToChat;
        this.stopButton = form.getStopButton();
        this.resultView = new ScanResultView(ScanPanel::copyToClipboard, this::setSendToChat);
        this.storedView = new ScanResultView(ScanPanel::copyToClipboard, this::setSendToChat);
        this.storedView.onRerun(() -> rerunScan(selectedScan));

        setLayout(new BorderLayout());
        cardStack.add(buildScanPanel(), "Scan");
        cardStack.add(buildProbePanel(), "Probe");
        cardStack.add(buildResultPanel(), "Result");
        cardStack.add(buildViewScanResult(), "View_scan");
        cardStack.add(buildEditProbe(), "Edit_probe");
        cardStack.add(buildProbeDefinitionCard(), "Probe_definition");

        refreshProbeChips();

        ctx.session().onAuthChange(e -> SwingUtilities.invokeLater(() -> {
            // Login or logout, the previous subject's data leaves the screen first. Only a
            // signed-in subject then gets their own rows loaded back.
            resetPanel();
            if (Boolean.TRUE.equals(e.getNewValue())) {
                reloadScanResults();
                reloadProbes();
            }
        }));

        add(cardStack.view(), BorderLayout.CENTER);
    }

    /** The sections the application's sidebar routes to (2026-10-24); the toggle column is gone. */
    public static final String SECTION_SCAN = "Scan";
    public static final String SECTION_HISTORY = "Result";
    public static final String SECTION_PROBES = "Probe";

    /** Shows one of the {@code SECTION_*} cards (the detail cards are reached from within). */
    public void show(String section) {
        cardStack.show(section);
    }

    /**
     * Clears every field, list, selection and tick that could carry one subject's data to the
     * next, and returns to the Scanner card. Called on every auth change; safe to call at any
     * time from the EDT.
     */
    public void resetPanel() {
        form.reset();
        resultView.clear();
        storedView.clear();
        selectedScan = null;
        selectedProbe = null;
        if (viewProbeTextArea != null) viewProbeTextArea.setText("");
        editCheck.clear();
        tickedProbes.clear();
        // A scan the departing subject started must not keep probing on their behalf.
        onStop();
        scanResults = List.of();
        probes = List.of();
        historyModel.setRows(scanResults);
        updateHistoryCount();
        refreshLibraryRows();
        refreshProbeChips();
        cardStack.show("Scan");
    }

    /** Shows a report on the scanner page as a finished, stored run; for hosts and renders. */
    public void showResult(String name, String json) {
        resultView.setReport(name, json, null, true);
    }

    private JPanel buildScanPanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        head.setOpaque(false);
        JLabel title = new JLabel("New scan");
        title.setFont(UITokens.font(Font.BOLD, 8f));
        head.add(title);
        JLabel sub = new JLabel("Assess what the hosts on a segment expose. Only ordinary handshakes are sent, from this machine's own address.");
        sub.setForeground(UITokens.muted());
        head.add(sub);
        out.add(head, "growx");

        probeChips.setEmptyText("none · no probing (tick Service detection for all)");
        probeChips.addAction("Add probe", this::showProbeMenu);
        probeChips.onRemove(key -> {
            tickedProbes.remove(key);
            refreshProbeChips();
        });
        form.setProbeControl(probeChips);
        // the Service detection box is the all / none shortcut for the chips (2026-10-26)
        form.onServiceDetectionToggled(on -> {
            if (on) tickAllProbes();
            else tickedProbes.clear();
            refreshProbeChips();
        });
        form.getHelpButton().addActionListener(_ -> showUsage());
        stopButton.addActionListener(_ -> onStop());
        form.getRunButton().addActionListener(_ -> onRun(form.getRunButton()));
        out.add(form, "growx");

        out.add(resultView, "grow, push");
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
        NMapConfig cfg;
        ProbeSelection.Selection selected;
        try {
            cfg = form.toConfig();
            selected = ProbeSelection.select(bundledProbes, probes, tickedProbes);
            ProbeSelection.applyTo(cfg, selected);
        } catch (IllegalArgumentException ex) {
            form.showError(ex.getMessage());
            return;
        }
        form.clearMessage();
        // what the report records as the command: the form's own print of what it is running,
        // probes aside (they are applied to the config, never written into the line)
        String typed = form.getCommand().isEmpty() ? NMap.formatCommand(cfg) : form.getCommand();
        String probeNames = ProbeSelection.describe(selected);
        String scanName = reportName(cfg);
        String subjectAtStart = ctx.session().getSubjectGUID();

        stopButton.setEnabled(true);
        BackgroundTask.run(this, run, () -> runScan(cfg), outcome -> {
            stopButton.setEnabled(false);
            if (outcome.stopped() != null) {
                // Stopped by the subject or by the wait budget: show what completed, save nothing.
                if (outcome.json() != null) resultView.setReport(scanName, outcome.json(), outcome.stopped(), false);
                else resultView.clear();
                form.showError(outcome.stopped().lines().findFirst().orElse("Scan stopped"));
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
            resultView.setReport(scanName, json, null, false);
            ReportContent r = new ReportContent();
            r.setName(scanName);
            r.setDescription(probeNames.isEmpty() ? typed : typed + "  ·  probes: " + probeNames);
            r.setContent(json);
            r.getProperties().build("command", typed);
            if (!probeNames.isEmpty()) r.getProperties().build("probes", probeNames);
            // the history table reads these off the projected row, so a report is never re-fetched to count
            try {
                io.xlogistx.nosneak.app.ui.scan.ReportView.Report parsed = io.xlogistx.nosneak.app.ui.scan.ReportView.parse(json);
                r.getProperties().build("hostsUp", Integer.toString(parsed.upHosts().size()));
                r.getProperties().build("openPorts", Integer.toString(parsed.openPortCount()));
            } catch (IllegalArgumentException ignore) {
                // an unparseable report still saves; the table shows a dash
            }
            // Encrypting and inserting a report is store I/O: off the EDT, like every other
            // Session call in this file, and a failure is a dialog rather than a frozen UI.
            BackgroundTask.runCatching(this, null, () -> ctx.session().saveScanResult(r), () -> {
                resultView.markSaved(true);
                reloadScanResults();
            });
        });
    }

    /**
     * The label a scan is filed under — the subject's own name for it, falling back to the
     * targets so a report is never nameless. It becomes the report's name, the Scan History row
     * label, and the attachment label when the report is sent to a chat, so it is deliberately
     * short: the full command lives in the report's description.
     */
    private String reportName(NMapConfig cfg) {
        String typed = form.getScanName();
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
         * Applies the selection to the parsed config. The selection is the only source of
         * probing (maintainer, 2026-10-26): ticked probes imply {@code -sV} and name the set;
         * <b>no ticks mean no probing</b>, whatever {@code -sV} or {@code --probes} the command
         * carried (a bare {@code -sV} would otherwise run the engine's whole catalog). Names never
         * pass through the command string.
         */
        static void applyTo(NMapConfig cfg, Selection sel) {
            if (sel.isEmpty()) {
                cfg.probeScan(false);
                cfg.probeNames.clear();
                cfg.extraProbes.clear();
                return;
            }
            cfg.probeScan(true);
            for (String name : sel.bundledNames()) cfg.probe(name);
            for (ProbeDefinition d : sel.stored()) {
                cfg.extraProbe(d);
                cfg.probe(d.getName());
            }
        }

        /**
         * The inverse of {@link #describe}: the ticks a report's saved {@code probes} property
         * stands for, against the probes known now (2026-10-25, for <i>Scan again</i>). A name is
         * matched to a bundled probe first, then to a stored one by name; a name that matches
         * nothing (a stored probe deleted since) is dropped. Null or blank gives no ticks.
         */
        static Set<String> keysForNames(String csv, List<ProbeDefinition> bundled, List<ProbeContent> stored) {
            Set<String> keys = new HashSet<>();
            if (csv == null || csv.isBlank()) return keys;
            for (String raw : csv.split(",")) {
                String name = raw.trim();
                if (name.isEmpty()) continue;
                boolean found = false;
                for (ProbeDefinition d : bundled) {
                    if (name.equals(d.getName())) {
                        keys.add(bundledKey(d.getName()));
                        found = true;
                        break;
                    }
                }
                if (found) continue;
                ProbeContent mine = existingByName(stored, name);
                if (mine != null) keys.add(storedKey(mine));
            }
            return keys;
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

    /** One selectable probe: the label shown and the tick key behind it. */
    private record ProbeRow(String key, String label, String tooltip, boolean stored) {}

    private List<ProbeRow> probeRows() {
        List<ProbeRow> rows = new ArrayList<>();
        for (ProbeDefinition d : bundledProbes) {
            rows.add(new ProbeRow(ProbeSelection.bundledKey(d.getName()), d.getName(), bundledTip(d), false));
        }
        for (ProbeContent p : probes) {
            if (p.getName() != null && !p.getName().isBlank()) {
                rows.add(new ProbeRow(ProbeSelection.storedKey(p), p.getName(), null, true));
            }
        }
        return rows;
    }

    /** The chips are the ticked probes; a stored one carries a "mine" badge. */
    private void refreshProbeChips() {
        List<ChipPanel.Chip> chips = new ArrayList<>();
        for (ProbeRow row : probeRows()) {
            if (tickedProbes.contains(row.key())) chips.add(new ChipPanel.Chip(row.key(), row.label(), row.stored() ? "mine" : null));
        }
        probeChips.setChips(chips);
        form.setServiceDetection(!chips.isEmpty()); // -sV mirrors the chips both ways, as applyTo does
    }

    /** Every bundled and stored probe ticked: what the Service detection box means on its own. */
    private void tickAllProbes() {
        for (ProbeRow row : probeRows()) tickedProbes.add(row.key());
    }

    /** The Add probe menu: a check item per bundled and stored probe, grouped, with an All per group. */
    private void showProbeMenu() {
        JPopupMenu menu = new JPopupMenu();
        List<ProbeRow> rows = probeRows();
        addProbeGroup(menu, "Bundled probes", rows.stream().filter(r -> !r.stored()).toList(), "None loaded");
        menu.addSeparator();
        addProbeGroup(menu, "My probes", rows.stream().filter(ProbeRow::stored).toList(), "No probes yet");
        JComponent anchor = probeChips;
        menu.show(anchor, 0, anchor.getHeight());
    }

    private void addProbeGroup(JPopupMenu menu, String title, List<ProbeRow> rows, String emptyText) {
        JMenuItem header = new JMenuItem(title.toUpperCase());
        header.setEnabled(false);
        header.setFont(UITokens.font(Font.BOLD, -2f));
        menu.add(header);
        if (rows.isEmpty()) {
            JMenuItem none = new JMenuItem(emptyText);
            none.setEnabled(false);
            menu.add(none);
            return;
        }
        List<String> keys = rows.stream().map(ProbeRow::key).toList();
        JCheckBoxMenuItem all = new JCheckBoxMenuItem("All", tickedProbes.containsAll(keys));
        all.addActionListener(_ -> {
            if (all.isSelected()) tickedProbes.addAll(keys);
            else tickedProbes.removeAll(keys);
            refreshProbeChips();
        });
        menu.add(all);
        for (ProbeRow row : rows) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(row.label(), tickedProbes.contains(row.key()));
            if (row.tooltip() != null) item.setToolTipText(row.tooltip());
            item.addActionListener(_ -> {
                if (item.isSelected()) tickedProbes.add(row.key());
                else tickedProbes.remove(row.key());
                refreshProbeChips();
            });
            menu.add(item);
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

    private void showUsage() {
        JTextArea text = new JTextArea(NMap.usageText());
        text.setEditable(false);
        text.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JOptionPane.showMessageDialog(this, new JScrollPane(text), "Usage", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * The Probe library (2026-10-26, on the maintainer's instruction: "the bundled probes can't
     * be read, and it doesn't explain how to create one"): a table of every probe a scan can run,
     * bundled and stored, with the selected one read-only in a detail pane; with nothing selected
     * the pane says what a probe is and the three ways to add one. Same shape as the history page.
     */
    private JPanel buildProbePanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = new JLabel("Probe library");
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = new JLabel("The service probes a scan can run: the bundled set and your own. Select one to read it.");
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        JButton withAssistant = new JButton("Write with the assistant", IconUtil.svgIcon("io/xlogistx/gui/icons/chat.svg", 16, UITokens.text()));
        withAssistant.setToolTipText("Hand the assistant the probe definition and ask it for a probe");
        withAssistant.addActionListener(_ -> onWriteProbeWithAssistant());
        head.add(withAssistant);
        JButton newProbe = UITokens.primary(new JButton("New probe", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        newProbe.addActionListener(_ -> newProbe());
        head.add(newProbe);
        out.add(head, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][][]push[]"));
        bar.setOpaque(false);
        librarySearch.putClientProperty("JTextField.placeholderText", "Search name, service, port");
        librarySearch.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(librarySearch, "growx");
        libraryFilter.select(0);
        libraryFilter.onChange(_ -> filterLibrary());
        bar.add(libraryFilter);
        libraryCount.setForeground(UITokens.muted());
        libraryCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(libraryCount);
        JButton definition = new JButton("Probe definition", IconUtil.svgIcon("io/xlogistx/gui/icons/book.svg", 16, UITokens.text()));
        definition.setToolTipText("The contract a probe file follows, with examples");
        definition.putClientProperty("JButton.buttonType", "toolBarButton");
        definition.addActionListener(_ -> showProbeDefinition());
        bar.add(definition);
        out.add(bar, "growx");

        Tables.style(libraryTable);
        Tables.width(libraryTable, ProbeLibraryModel.COL_NAME, 170);
        Tables.width(libraryTable, ProbeLibraryModel.COL_SERVICE, 100);
        Tables.width(libraryTable, ProbeLibraryModel.COL_PORTS, 150);
        Tables.width(libraryTable, ProbeLibraryModel.COL_TRANSPORT, 80);
        Tables.width(libraryTable, ProbeLibraryModel.COL_PRIORITY, 70);
        Tables.width(libraryTable, ProbeLibraryModel.COL_SOURCE, 90);
        libraryTable.getColumnModel().getColumn(ProbeLibraryModel.COL_NAME).setCellRenderer(new MonoRenderer());
        libraryTable.getColumnModel().getColumn(ProbeLibraryModel.COL_SOURCE).setCellRenderer(new SourceRenderer());
        libraryTable.setRowSorter(librarySorter);
        libraryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        libraryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showLibraryDetail(selectedLibraryRow());
        });
        libraryTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() != 2) return;
                ProbeLibraryModel.Row row = selectedLibraryRow();
                if (row == null) return;
                if (row.stored()) onEditProbe(row.content());
                else onCopyBundledProbe(row);
            }
        });
        librarySearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                filterLibrary();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                filterLibrary();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                filterLibrary();
            }
        });

        JScrollPane tableScroll = new JScrollPane(libraryTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        tableScroll.getViewport().setBackground(UITokens.surface());
        tableScroll.setMinimumSize(new Dimension(0, 0));

        libraryDetail.add(buildLibraryHowTo(), "howto");
        libraryDetail.add(buildLibraryProbeCard(), "probe");
        JComponent detail = libraryDetail.view();
        detail.setBackground(UITokens.surfaceAlt());
        detail.setOpaque(true);
        detail.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, UITokens.border()));
        detail.setMinimumSize(new Dimension(0, 0));
        libraryDetail.show("howto");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detail);
        split.setResizeWeight(0.58);
        split.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        split.setDividerSize(6);
        split.setMinimumSize(new Dimension(0, 0));
        out.add(split, "grow, push");
        return out;
    }

    /** The detail pane with nothing selected: what a probe is, and the three ways to add one. */
    private JPanel buildLibraryHowTo() {
        JPanel p = new JPanel(new MigLayout("insets 20, wrap 1, gapy 6", "[grow,fill]"));
        p.setOpaque(false);
        JLabel t = new JLabel("How to add a probe");
        t.setFont(UITokens.font(Font.BOLD, 2f));
        p.add(t, "gapbottom 4");
        WrapLabel what = new WrapLabel("A probe is one JSON file: a small state machine that connects, sends the minimum the "
                + "protocol needs, matches the reply and records the service. Select a probe on the left to read it. "
                + "Three ways to add one:");
        what.setWrapWidth(300);
        what.setForeground(UITokens.muted());
        p.add(what, "gapbottom 8");

        JButton copy = UITokens.link(new JButton("Copy a bundled probe"));
        copy.addActionListener(_ -> selectFirstBundledRow());
        p.add(copy, "growx 0");
        p.add(note("Pick one on the left, then Copy to my probes and change what you need."));

        JButton ask = UITokens.link(new JButton("Write with the assistant"));
        ask.addActionListener(_ -> onWriteProbeWithAssistant());
        p.add(ask, "growx 0, gaptop 8");
        p.add(note("It gets the probe definition and returns the JSON; one click on the reply saves it here."));

        JButton fresh = UITokens.link(new JButton("New probe"));
        fresh.addActionListener(_ -> newProbe());
        p.add(fresh, "growx 0, gaptop 8");
        p.add(note("Start from an empty editor, with the Probe definition one click away."));
        return p;
    }

    private static WrapLabel note(String text) {
        WrapLabel l = new WrapLabel(text);
        l.setWrapWidth(290);
        l.setForeground(UITokens.muted());
        l.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        return l;
    }

    /** The detail pane for a selected probe: its facts, its JSON read-only, and what you can do with it. */
    private JPanel buildLibraryProbeCard() {
        JPanel p = new JPanel(new MigLayout("insets 16, wrap 1, gapy 8, fill", "[grow,fill]", "[][][][grow,fill][]"));
        p.setOpaque(false);
        probeTitle.setFont(UITokens.font(Font.BOLD, 2f));
        p.add(probeTitle);
        p.add(probeFacts);
        p.add(probeProblem, "hidemode 3");
        probeSource.setEditable(false);
        probeSource.setFont(UITokens.mono(-1f));
        probeSource.setMargin(new Insets(10, 12, 10, 12));
        JScrollPane sourceScroll = new JScrollPane(probeSource);
        sourceScroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        sourceScroll.setMinimumSize(new Dimension(0, 0));
        p.add(sourceScroll, "grow, push");
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]"));
        actions.setOpaque(false);
        copyProbe.setToolTipText("Open the editor with this probe's JSON as your draft");
        copyProbe.addActionListener(_ -> onCopyBundledProbe(selectedLibraryRow()));
        editProbe.addActionListener(_ -> {
            ProbeLibraryModel.Row row = selectedLibraryRow();
            if (row != null && row.stored()) onEditProbe(row.content());
        });
        deleteProbe.setForeground(UITokens.danger());
        deleteProbe.addActionListener(_ -> {
            ProbeLibraryModel.Row row = selectedLibraryRow();
            if (row == null || !row.stored()) return;
            int ok = JOptionPane.showConfirmDialog(this, "Delete the probe \"" + row.name() + "\"?", "Delete probe",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveProbe(row.content());
        });
        for (JButton b : new JButton[]{copyProbe, editProbe, deleteProbe}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            actions.add(b, "hidemode 3");
        }
        p.add(actions);
        return p;
    }

    /** Fills the detail pane for {@code row}; null shows the how-to card. */
    private void showLibraryDetail(ProbeLibraryModel.Row row) {
        if (row == null) {
            libraryDetail.show("howto");
            return;
        }
        probeTitle.setText(row.name());
        probeFacts.clear();
        ProbeDefinition d = row.def();
        if (d != null) {
            WrapLabel description = probeFacts.put("Description", d.getDescription());
            if (description != null) description.setWrapWidth(230);
            probeFacts.put("Service", d.getService());
            probeFacts.put("Transport", d.getTransport());
            probeFacts.put("Ports", ProbeLibraryModel.ports(d));
            probeFacts.put("Priority", String.valueOf(d.getPriority()));
            probeFacts.put("Port-scoped", d.isPortScoped() ? "yes, declared ports only" : "no");
            if (d.getOverallTimeoutSec() != null) probeFacts.put("Watchdog", d.getOverallTimeoutSec() + " s");
            int states = d.getStates() == null ? 0 : d.getStates().size();
            probeFacts.putMono("States", states + ", start at " + d.getStart());
            probeProblem.clear();
        } else {
            probeProblem.error("This probe no longer loads: " + row.error());
        }
        probeFacts.put("Source", row.stored() ? "mine, stored under your account" : "bundled with no-sneak");
        probeProblem.setVisible(probeProblem.hasMessage());
        probeSource.setText(row.source());
        probeSource.setCaretPosition(0);
        copyProbe.setVisible(!row.stored());
        editProbe.setVisible(row.stored());
        deleteProbe.setVisible(row.stored());
        libraryDetail.show("probe");
    }

    private ProbeLibraryModel.Row selectedLibraryRow() {
        int row = libraryTable.getSelectedRow();
        return row < 0 ? null : libraryModel.at(libraryTable.convertRowIndexToModel(row));
    }

    private void selectFirstBundledRow() {
        for (int i = 0; i < libraryTable.getRowCount(); i++) {
            if (!libraryModel.at(libraryTable.convertRowIndexToModel(i)).stored()) {
                libraryTable.setRowSelectionInterval(i, i);
                libraryTable.scrollRectToVisible(libraryTable.getCellRect(i, 0, true));
                return;
            }
        }
    }

    /** Rebuilds the table from the bundled definitions and the stored probes (on the EDT; used by reset). */
    private void refreshLibraryRows() {
        refreshLibraryRows(ProbeLibraryModel.rows(bundledProbes, bundledSources, probes));
    }

    /** Installs rows built elsewhere (the reload builds them off the EDT); keeps the selection by name. */
    private void refreshLibraryRows(List<ProbeLibraryModel.Row> rows) {
        ProbeLibraryModel.Row before = selectedLibraryRow();
        libraryModel.setRows(rows);
        filterLibrary();
        if (before != null) {
            for (int i = 0; i < libraryTable.getRowCount(); i++) {
                ProbeLibraryModel.Row r = libraryModel.at(libraryTable.convertRowIndexToModel(i));
                if (r.stored() == before.stored() && r.name().equals(before.name())) {
                    libraryTable.setRowSelectionInterval(i, i);
                    return;
                }
            }
        }
        libraryTable.clearSelection();
        showLibraryDetail(null);
    }

    private void filterLibrary() {
        ProbeLibraryModel.Filter f = ProbeLibraryModel.Filter.values()[Math.max(0, libraryFilter.getSelectedIndex())];
        String q = librarySearch.getText();
        librarySorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ProbeLibraryModel, ? extends Integer> entry) {
                return ProbeLibraryModel.matches(entry.getModel().at(entry.getIdentifier()), f, q);
            }
        });
        int shown = libraryTable.getRowCount(), all = libraryModel.getRowCount();
        libraryCount.setText(all == 0 ? "" : shown == all ? all + " probes" : shown + " of " + all + " probes");
    }

    /** Opens the editor on an empty draft. */
    public void newProbe() {
        openProbeEditor(new ProbeContent(), "New probe");
    }

    /** Opens the editor with a bundled probe's JSON as a new draft (2026-10-26). */
    private void onCopyBundledProbe(ProbeLibraryModel.Row row) {
        if (row == null || row.stored()) return;
        ProbeContent draft = new ProbeContent();
        draft.setContent(row.source());
        openProbeEditor(draft, "Copy of " + row.name());
    }

    /**
     * Hands the assistant the probe definition and a request for a probe (2026-10-26): a small
     * dialog asks what to detect and where, then the Chat page opens with the request typed and
     * the definition attached, so only Send is left. With no chat open the assistant's own
     * message shows and the app goes to Chats, where one can be created.
     */
    private void onWriteProbeWithAssistant() {
        JTextField service = new JTextField(18);
        JTextField port = new JTextField(6);
        JPanel ask = new JPanel(new MigLayout("insets 0, wrap 2, gapy 6", "[][grow,fill]"));
        ask.add(new JLabel("Service"));
        ask.add(service);
        ask.add(new JLabel("Port"));
        ask.add(port, "growx 0");
        WrapLabel hint = new WrapLabel("The assistant gets PROBE-DEFINITION.md with the request and answers with one JSON object; "
                + "the reply carries a Save as probe button.");
        hint.setWrapWidth(360);
        hint.setForeground(UITokens.muted());
        ask.add(hint, "span 2, gaptop 6");
        int ok = JOptionPane.showConfirmDialog(this, ask, "Write a probe with the assistant",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        String prompt = ProbeLibraryModel.assistantPrompt(service.getText(), port.getText());
        try {
            sendToChat.send(ProbeDefinitionLoader.probeDefinition(), "Probe definition", prompt);
        } catch (AccessSecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Write with the assistant", JOptionPane.WARNING_MESSAGE);
            ctx.nav().show(Navigator.Screen.CHATS);
            return;
        }
        ctx.nav().show(Navigator.Screen.CHAT);
    }

    /** Shows PROBE-DEFINITION.md, the contract a probe file follows; rendered on first use. */
    public void showProbeDefinition() {
        if (definitionView.getMarkdown() == null || definitionView.getMarkdown().isEmpty()) {
            definitionView.setMarkdown(ProbeDefinitionLoader.probeDefinition());
        }
        cardStack.show("Probe_definition");
    }

    private JPanel buildProbeDefinitionCard() {
        definitionView = new MDViewerPanel();
        return PanelBuilder.detail("Probe definition", () -> cardStack.show("Probe"), content -> {
            JLabel sub = new JLabel("no-sneak-core/PROBE-DEFINITION.md: what a probe.json may contain, every action, the validation rules and worked examples.");
            sub.setForeground(UITokens.muted());
            content.add(sub, "gapbottom 6");
            content.add(definitionView, "grow, push");
        });
    }

    /** A "bundled" / "mine" badge in the Source column. */
    private static final class SourceRenderer implements javax.swing.table.TableCellRenderer {
        private final BadgeLabel bundled = new BadgeLabel("bundled", BadgeLabel.Tone.NEUTRAL);
        private final BadgeLabel mine = new BadgeLabel("mine", BadgeLabel.Tone.ACCENT);
        private final JPanel cell = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            cell.removeAll();
            cell.add("mine".equals(value) ? mine : bundled);
            cell.setOpaque(true);
            cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            return cell;
        }
    }

    /**
     * The history page (board 3 of the redesign canvas, 2026-10-24): a table of stored scans —
     * name and target, the command, when and how long, hosts up, open ports — with a search box
     * that filters every column and a toolbar that acts on the selected row (View, Scan again,
     * Copy command, Copy result, Send to assistant, Delete); a double-click views. Rows are the projected
     * {@link ReportContent}s (no content), so hosts and ports come from the {@code summary}
     * property a run records; older rows show a dash.
     */
    private JPanel buildResultPanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = new JLabel("Scan history");
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = new JLabel("Every completed scan you ran, kept in this store under your account only. Stopped scans are not saved.");
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        JButton newScan = UITokens.primary(new JButton("New scan", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        newScan.addActionListener(_ -> ctx.nav().show(Navigator.Screen.SCAN_NEW));
        head.add(newScan);
        out.add(head, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][][][][][][]"));
        bar.setOpaque(false);
        JTextField search = new JTextField();
        search.putClientProperty("JTextField.placeholderText", "Search by name, target or command");
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        historyCount.setForeground(UITokens.muted());
        historyCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(historyCount);
        JButton view = new JButton("View", new IconUtil.VisibleIcon(16));
        JButton again = new JButton("Scan again", IconUtil.svgIcon("io/xlogistx/gui/icons/refresh.svg", 16, UITokens.text()));
        again.setToolTipText("Load this scan's command, probes and name into New scan");
        JButton copyCommand = new JButton("Copy command", new IconUtil.TextBoxIcon(16));
        JButton copyResult = new JButton("Copy result", new IconUtil.CopyIcon(16));
        JButton send = new JButton("Send to assistant", IconUtil.svgIcon("io/xlogistx/gui/icons/chat.svg", 16, UITokens.text()));
        JButton delete = new JButton("Delete", new IconUtil.DeleteIcon(16));
        delete.setForeground(UITokens.danger());
        for (JButton b : new JButton[]{view, again, copyCommand, copyResult, send, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            b.setEnabled(false);
            bar.add(b);
        }
        // Delete all (2026-10-25): enabled whenever the history has rows, not by the selection
        historyDeleteAll.setForeground(UITokens.danger());
        historyDeleteAll.putClientProperty("JButton.buttonType", "toolBarButton");
        historyDeleteAll.setEnabled(false);
        historyDeleteAll.setToolTipText("Delete every scan in your history");
        bar.add(historyDeleteAll);
        out.add(bar, "growx");

        Tables.style(historyTable);
        Tables.width(historyTable, 0, 220);
        Tables.width(historyTable, 1, 360);
        Tables.width(historyTable, 2, 150);
        Tables.width(historyTable, 3, 80);
        Tables.width(historyTable, 4, 90);
        historyTable.getColumnModel().getColumn(1).setCellRenderer(new MonoRenderer());
        historyTable.setRowSorter(historySorter);
        historySorter.setSortKeys(List.of(new RowSorter.SortKey(2, SortOrder.DESCENDING)));
        // Multi-selection (2026-10-25): Delete takes every selected row; the single-row actions
        // need exactly one, so they grey out while several are selected
        historyTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            int selected = historyTable.getSelectedRowCount();
            for (JButton b : new JButton[]{view, again, copyCommand, copyResult, send}) b.setEnabled(selected == 1);
            delete.setEnabled(selected >= 1);
            delete.setText(selected > 1 ? "Delete " + selected : "Delete");
        });
        historyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) onViewScanResult(selectedHistoryRow());
            }
        });
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            private void filter() {
                String q = search.getText().trim();
                historySorter.setRowFilter(q.isEmpty() ? null : RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
                updateHistoryCount();
            }
        });
        view.addActionListener(_ -> onViewScanResult(selectedHistoryRow()));
        again.addActionListener(_ -> rerunScan(selectedHistoryRow()));
        copyCommand.addActionListener(_ -> onCopyScanCommand(selectedHistoryRow()));
        copyResult.addActionListener(_ -> onCopyScanResult(selectedHistoryRow()));
        send.addActionListener(_ -> onSendScanResult(selectedHistoryRow()));
        delete.addActionListener(_ -> {
            List<ReportContent> rows = selectedHistoryRows();
            if (rows.isEmpty()) return;
            String what = rows.size() == 1 ? "the scan \"" + rows.get(0).getName() + "\""
                    : "the " + rows.size() + " selected scans";
            int ok = JOptionPane.showConfirmDialog(this, "Delete " + what + "?", "Delete scan" + (rows.size() == 1 ? "" : "s"),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveScanResults(rows);
        });
        historyDeleteAll.addActionListener(_ -> {
            int all = historyModel.getRowCount();
            if (all == 0) return;
            int ok = JOptionPane.showConfirmDialog(this,
                    "Delete all " + all + " scan" + (all == 1 ? "" : "s") + " in your history? This cannot be undone.",
                    "Delete all scans", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveAllScanResults();
        });

        JScrollPane scroll = new JScrollPane(historyTable);
        scroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        scroll.getViewport().setBackground(UITokens.surface());
        out.add(scroll, "grow, push");
        return out;
    }

    /** The lead selected row, for the single-row actions; null when none or several are selected. */
    private ReportContent selectedHistoryRow() {
        if (historyTable.getSelectedRowCount() != 1) return null;
        int row = historyTable.getSelectedRow();
        return row < 0 ? null : historyModel.at(historyTable.convertRowIndexToModel(row));
    }

    /** Every selected row, in table order. */
    private List<ReportContent> selectedHistoryRows() {
        List<ReportContent> out = new ArrayList<>();
        for (int row : historyTable.getSelectedRows()) out.add(historyModel.at(historyTable.convertRowIndexToModel(row)));
        return out;
    }

    private void updateHistoryCount() {
        int shown = historyTable.getRowCount();
        int all = historyModel.getRowCount();
        historyCount.setText(all == 0 ? "No scans yet" : shown == all ? all + " scans" : shown + " of " + all + " scans");
        historyDeleteAll.setEnabled(all > 0);
    }

    /** The history rows: projections, re-fetched by GUID before anything reads their content. */
    private static final class HistoryModel extends javax.swing.table.AbstractTableModel {
        private static final String[] COLS = {"Scan", "Command", "When", "Hosts up", "Open ports"};
        private List<ReportContent> rows = List.of();

        void setRows(List<ReportContent> list) {
            rows = list != null ? list : List.of();
            fireTableDataChanged();
        }

        ReportContent at(int row) {
            return rows.get(row);
        }

        public int getRowCount() {
            return rows.size();
        }

        public int getColumnCount() {
            return COLS.length;
        }

        public String getColumnName(int c) {
            return COLS[c];
        }

        public Object getValueAt(int r, int c) {
            ReportContent s = rows.get(r);
            return switch (c) {
                case 0 -> s.getName();
                case 1 -> commandOf(s);
                case 2 -> s.getCreationTime() > 0 ? STAMP.format(Instant.ofEpochMilli(s.getCreationTime())) : "";
                case 3 -> property(s, "hostsUp");
                default -> property(s, "openPorts");
            };
        }

        private static String property(ReportContent s, String key) {
            Object v = s.getProperties() != null ? s.getProperties().getValue(key) : null;
            return v != null ? v.toString() : "—";
        }
    }

    /** The command column in the mono font, muted. */
    private static final class MonoRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setFont(UITokens.mono(-1.5f));
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
    }

    /**
     * Row action: copy the command the scan was run with, ready to paste back into the command
     * box. The typed command lives in the {@code command} property and the projected row carries
     * properties, so no re-fetch; a report saved before that property existed falls back to the
     * description (the command plus the probe names).
     */
    private void onCopyScanCommand(ReportContent row) {
        if (row == null) return;
        copyToClipboard(commandOf(row));
    }

    /**
     * <b>Scan again</b>: the stored report's command, probe ticks and name go back into the New
     * scan form, which then shows the scan exactly as it was defined, ready for Run. Nothing runs
     * until the subject presses Run, so the command can still be adjusted first. A report saved
     * before the command property existed falls back to its description, cut before the
     * {@code · probes:} suffix the description carries.
     */
    private void rerunScan(ReportContent scan) {
        if (scan == null) return;
        String command = commandOf(scan);
        if (command != null) command = command.split("\s+·\s+", 2)[0].trim();
        if (SUS.isEmpty(command)) {
            JOptionPane.showMessageDialog(this, "This report did not record its command.", "Scan again",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Object saved = scan.getProperties() != null ? scan.getProperties().getValue("probes") : null;
        tickedProbes.clear();
        tickedProbes.addAll(ProbeSelection.keysForNames(saved != null ? saved.toString() : null, bundledProbes, probes));
        form.setCommand(command);
        form.setScanName(scan.getName());
        refreshProbeChips();
        ctx.nav().show(Navigator.Screen.SCAN_NEW);
    }

    /** The typed command of a report: the {@code command} property, else the description. */
    static String commandOf(ReportContent scan) {
        Object typed = scan.getProperties() != null ? scan.getProperties().getValue("command") : null;
        String command = typed != null ? SUS.trimOrNull(typed.toString()) : null;
        return command != null ? command : SUS.trimOrNull(scan.getDescription());
    }

    /** Row action: copy the stored report. Rows are projections without content, so re-fetch first. */
    private void onCopyScanResult(ReportContent row) {
        if (row == null) return;
        BackgroundTask.run(this, null, () -> ctx.session().getScanResult(row.getGUID()), full -> {
            if (full == null) {
                JOptionPane.showMessageDialog(this, "That scan result is no longer available.",
                        "Not found", JOptionPane.WARNING_MESSAGE);
                reloadScanResults();
                return;
            }
            copyToClipboard(full.getContent());
        });
    }

    private static void copyToClipboard(String text) {
        if (SUS.isEmpty(text)) return;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
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
            historyModel.setRows(scanResults);
            updateHistoryCount();
        });
    }

    /** Re-reads the stored probes (and, once, the bundled set) off the EDT and refreshes the library and the chips. */
    public void reloadProbes() {
        BackgroundTask.run(this, null, () -> {
            if (bundledProbes.isEmpty()) bundledProbes = ProbeDefinitionLoader.loadBundled();
            if (bundledSources.isEmpty()) {
                Map<String, String> sources = new LinkedHashMap<>();
                for (ProbeDefinition d : bundledProbes) sources.put(d.getName(), ProbeDefinitionLoader.bundledSource(d.getName()));
                bundledSources = sources;
            }
            List<ProbeContent> stored = ctx.session().getAllProbes();
            // the library's rows (every stored probe parsed once) are built here, off the EDT
            return new ProbeLoad(stored, ProbeLibraryModel.rows(bundledProbes, bundledSources, stored));
        }, loaded -> {
            probes = loaded.probes();
            // A tick for a row that no longer exists (deleted, or another subject's) is dropped
            // here rather than kept forever in the set.
            Set<String> live = new HashSet<>();
            for (ProbeDefinition d : bundledProbes) live.add(ProbeSelection.bundledKey(d.getName()));
            for (ProbeContent p : probes) live.add(ProbeSelection.storedKey(p));
            tickedProbes.retainAll(live);
            refreshLibraryRows(loaded.rows());
            refreshProbeChips();
        });
    }

    /** What one probe reload produced: the stored rows and the library's rows built from them. */
    private record ProbeLoad(List<ProbeContent> probes, List<ProbeLibraryModel.Row> rows) {}

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
            storedView.setReport(full.getName(), full.getContent(), null, true);
            cardStack.show("View_scan");
        });
    }

    /** A stored report, in the same tables as a fresh run, with a way back to the history list. */
    private JPanel buildViewScanResult() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 10, fill", "[grow,fill]", "[]0[grow,fill]"));
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));
        JButton back = UITokens.link(new JButton("Back to history", new IconUtil.BackIcon(16)));
        back.addActionListener(_ -> cardStack.show("Result"));
        out.add(back, "alignx left");
        out.add(storedView, "grow, push");
        return out;
    }

    private void onRemoveScanResults(List<ReportContent> rows) {
        BackgroundTask.runCatching(this, null, () -> ctx.session().deleteScanResults(rows),
                this::reloadScanResults);
    }

    /** Every scan of the signed-in subject, after the confirm; the list reloads empty. */
    private void onRemoveAllScanResults() {
        BackgroundTask.run(this, historyDeleteAll, () -> ctx.session().deleteAllScanResults(), _ -> reloadScanResults());
    }

    private void onEditProbe(ProbeContent probeContent) {
        if (probeContent == null) return;
        openProbeEditor(probeContent, SUS.isEmpty(probeContent.getGUID()) ? "New probe" : "Edit probe");
    }

    /** Shows the editor on {@code probeContent} (a stored row, or a fresh draft) under {@code title}. */
    private void openProbeEditor(ProbeContent probeContent, String title) {
        this.selectedProbe = probeContent;
        editTitle.setText(title);
        viewProbeTextArea.setText(Objects.toString(probeContent.getContent(), ""));
        viewProbeTextArea.setCaretPosition(0);
        editCheck.clear();
        refreshEditName();
        cardStack.show("Edit_probe");
        viewProbeTextArea.requestFocusInWindow();
    }

    /** The name is whatever the JSON says; the label follows the draft so there is no field to disagree with it. */
    private void refreshEditName() {
        String name = null;
        try {
            name = ProbeDefinitionLoader.parse(fencedBlock(viewProbeTextArea.getText()), "draft").getName();
        } catch (RuntimeException ignored) {
            // not a valid probe yet; Check says why
        }
        editName.setText(name == null ? "Name: taken from the JSON once it is valid" : "Name: " + name);
    }

    /**
     * The probe editor (2026-10-26): mono text with no wrapping, a Check button that reports
     * inline, the name read from the JSON, and the two ways to get help one click away.
     */
    private JPanel buildEditProbe() {
        viewProbeTextArea = new JTextArea();
        viewProbeTextArea.setEditable(true);
        viewProbeTextArea.setFont(UITokens.mono(-1f));
        viewProbeTextArea.setTabSize(2);
        viewProbeTextArea.setMargin(new Insets(10, 12, 10, 12));

        JPanel content = new JPanel(new MigLayout("wrap 1, insets 10, gapy 6, fill", "[grow,fill]", "[][][][][][grow,fill]"));
        JButton back = GUIUtil.iconButton(new IconUtil.BackIcon(32), true);
        back.setToolTipText("Back to the library");
        back.addActionListener(_ -> cardStack.show("Probe"));
        content.add(back, "growx 0");
        editTitle.setFont(PanelBuilder.title("").getFont());
        content.add(editTitle, "gaptop 6");
        {
            JPanel help = new JPanel(new MigLayout("insets 0, gapx 4", "[][][][]"));
            help.setOpaque(false);
            JLabel one = new JLabel("One JSON object. See the");
            one.setForeground(UITokens.muted());
            help.add(one);
            JButton definition = UITokens.link(new JButton("Probe definition"));
            definition.setMargin(new Insets(0, 2, 0, 2));
            definition.addActionListener(_ -> showProbeDefinition());
            help.add(definition);
            JLabel or = new JLabel(", or let the");
            or.setForeground(UITokens.muted());
            help.add(or);
            JButton ask = UITokens.link(new JButton("assistant write it"));
            ask.setMargin(new Insets(0, 2, 0, 2));
            ask.addActionListener(_ -> onWriteProbeWithAssistant());
            help.add(ask);
            content.add(help);
            WrapLabel shadow = new WrapLabel("A stored probe with a bundled probe's name replaces that probe in your scans "
                    + "(the report says so); rename it in the JSON to keep both.");
            shadow.setWrapWidth(640);
            shadow.setForeground(UITokens.muted());
            content.add(shadow, "gapbottom 4");

            JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]push[]"));
            bar.setOpaque(false);
            JButton save = UITokens.primary(new JButton("Save", new IconUtil.SaveIcon(16, Color.WHITE)));
            JButton check = new JButton("Check", IconUtil.svgIcon("io/xlogistx/gui/icons/check.svg", 16, UITokens.text()));
            check.setToolTipText("Validate the draft the way the engine will");
            check.addActionListener(_ -> checkDraft());
            save.addActionListener(_ -> {
                if (selectedProbe == null) return;
                ProbeContent p;
                try {
                    p = probeToSave(selectedProbe, "", viewProbeTextArea.getText());
                } catch (IllegalArgumentException ex) {
                    editCheck.error(ex.getMessage());
                    JOptionPane.showMessageDialog(this, ex.getMessage(), "Not a valid probe", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                BackgroundTask.run(this, save, () -> ctx.session().saveProbe(p), saved -> {
                    selectedProbe = saved;
                    reloadProbes();
                    cardStack.show("Probe");
                });
            });
            bar.add(save);
            bar.add(check);
            editName.setForeground(UITokens.muted());
            bar.add(editName);
            bar.add(editCheck);
            content.add(bar, "growx");

            JScrollPane scroll = new JScrollPane(viewProbeTextArea);
            scroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
            content.add(scroll, "grow, push, w 100%");
        }
        return content;
    }

    /** The Check button: the loader's verdict on the draft, inline. */
    private void checkDraft() {
        if (viewProbeTextArea.getText().isBlank()) {
            editCheck.info("Paste or type the JSON first.");
            return;
        }
        try {
            editCheck.ok(ProbeLibraryModel.checkMessage(viewProbeTextArea.getText()));
        } catch (IllegalArgumentException e) {
            editCheck.error(e.getMessage());
        }
        refreshEditName();
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
            ctx.nav().show(Navigator.Screen.PROBES);
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
            sendToChat.send(content, SUS.isEmpty(name) ? "scan result" : name, null);
        } catch (AccessSecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Send to chat", JOptionPane.WARNING_MESSAGE);
            return;
        }
        ctx.nav().show(Navigator.Screen.CHAT);
    }
}
