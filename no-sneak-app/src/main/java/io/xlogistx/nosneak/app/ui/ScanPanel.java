package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
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
    private final TableRowSorter<HistoryModel> historySorter = new TableRowSorter<>(historyModel);
    private final JLabel historyCount = new JLabel();
    private ListSection<ProbeContent> probeList;
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

    private JTextField viewProbeTitleArea;
    private JTextArea viewProbeTextArea;

    /** Tick keys — see {@link ProbeSelection#bundledKey} and {@link ProbeSelection#storedKey}. */
    private final Set<String> tickedProbes = new HashSet<>();
    private List<ProbeDefinition> bundledProbes = List.of();

    private final BiConsumer<String, String> sendToChat;

    public ScanPanel(AppContext ctx, BiConsumer<String, String> sendToChat) {
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
        if (viewProbeTitleArea != null) viewProbeTitleArea.setText("");
        tickedProbes.clear();
        // A scan the departing subject started must not keep probing on their behalf.
        onStop();
        scanResults = List.of();
        probes = List.of();
        historyModel.setRows(scanResults);
        updateHistoryCount();
        if (probeList != null) probeList.refresh();
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

        probeChips.setEmptyText("none · service detection still identifies services");
        probeChips.addAction("Add probe", this::showProbeMenu);
        probeChips.onRemove(key -> {
            tickedProbes.remove(key);
            refreshProbeChips();
        });
        form.setProbeControl(probeChips);
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
        if (!chips.isEmpty()) form.setServiceDetection(true); // ticking implies -sV, as applyTo does
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

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][][][][][]"));
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
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            boolean on = historyTable.getSelectedRow() >= 0;
            for (JButton b : new JButton[]{view, again, copyCommand, copyResult, send, delete}) b.setEnabled(on);
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
            ReportContent row = selectedHistoryRow();
            if (row == null) return;
            int ok = JOptionPane.showConfirmDialog(this, "Delete the scan \"" + row.getName() + "\"?", "Delete scan",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveScanResult(row);
        });

        JScrollPane scroll = new JScrollPane(historyTable);
        scroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        scroll.getViewport().setBackground(UITokens.surface());
        out.add(scroll, "grow, push");
        return out;
    }

    private ReportContent selectedHistoryRow() {
        int row = historyTable.getSelectedRow();
        return row < 0 ? null : historyModel.at(historyTable.convertRowIndexToModel(row));
    }

    private void updateHistoryCount() {
        int shown = historyTable.getRowCount();
        int all = historyModel.getRowCount();
        historyCount.setText(all == 0 ? "No scans yet" : shown == all ? all + " scans" : shown + " of " + all + " scans");
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
            refreshProbeChips();
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
            sendToChat.accept(content, SUS.isEmpty(name) ? "scan result" : name);
        } catch (AccessSecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Send to chat", JOptionPane.WARNING_MESSAGE);
            return;
        }
        ctx.nav().show(Navigator.Screen.CHAT);
    }
}
