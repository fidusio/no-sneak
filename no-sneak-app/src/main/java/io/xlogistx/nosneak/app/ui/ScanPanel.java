package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.ui.scan.ProbeGroupModel;
import io.xlogistx.nosneak.app.ui.scan.ProbeLibraryModel;
import io.xlogistx.nosneak.app.ui.scan.ProbeSelection;
import io.xlogistx.nosneak.app.ui.scan.ScanFormPanel;
import io.xlogistx.nosneak.app.ui.scan.ScanResultView;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.data.ProbeGroup;
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
    private final JButton historyDeleteAll = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ScanHistoryPage.DELETE_ALL);
    private final TableRowSorter<HistoryModel> historySorter = new TableRowSorter<>(historyModel);
    private final JLabel historyCount = GUIUtil.applyProp(new JLabel(), NSAppUtil.ScanHistoryPage.COUNT);
    // The Probe library (2026-10-26): every probe a scan can run, bundled and stored, with a
    // detail pane that shows the selected one read-only; see buildProbePanel.
    private final ProbeLibraryModel libraryModel = new ProbeLibraryModel();
    private final JTable libraryTable = new JTable(libraryModel);
    private final TableRowSorter<ProbeLibraryModel> librarySorter = new TableRowSorter<>(libraryModel);
    private final JTextField librarySearch = new JTextField();
    private final SegmentedControl libraryFilter = new SegmentedControl(NSAppUtil.ProbeLibraryFilter.values());
    private final JLabel libraryCount = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeLibraryPage.COUNT);
    private final CardStack libraryDetail = new CardStack();
    private final JLabel probeTitle = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeLibraryPage.PROBE_TITLE);
    private final KeyValuePanel probeFacts = new KeyValuePanel(110);
    private final JTextArea probeSource = new JTextArea();
    private final InlineMessage probeProblem = new InlineMessage();
    private final JButton copyProbe = GUIUtil.applyProp(new JButton(new IconUtil.CopyIcon(16)), NSAppUtil.ProbeLibraryPage.COPY);
    private final JButton editProbe = GUIUtil.applyProp(new JButton(new IconUtil.EditIcon(16)), NSAppUtil.ProbeLibraryPage.EDIT);
    private final JButton deleteProbe = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ProbeLibraryPage.DELETE);
    /** The bundled files' JSON text by probe name, read once with the definitions. */
    private Map<String, String> bundledSources = Map.of();
    private MDViewerPanel definitionView;
    private List<ReportContent> scanResults = List.of();
    private List<ProbeContent> probes = List.of();

    // Probe groups (2026-11-01): named sets of probe names a subject ticks in one go. Managed
    // under the Probe library (buildProbeGroupsPanel), picked in the Add probe popup. The
    // groups never reach the engine: ticking one ticks its probes (ProbeGroupModel).
    private List<ProbeGroup> probeGroups = List.of();
    private final ProbeGroupModel groupModel = new ProbeGroupModel();
    private final JTable groupTable = new JTable(groupModel);
    private final TableRowSorter<ProbeGroupModel> groupSorter = new TableRowSorter<>(groupModel);
    private final JTextField groupSearch = new JTextField();
    private final JLabel groupCount = new JLabel();
    private final CardStack groupDetail = new CardStack();
    private final JLabel groupTitle = new JLabel();
    private final KeyValuePanel groupFacts = new KeyValuePanel(110);
    private final JPanel groupMembers = new JPanel(new MigLayout("insets 0, wrap 1, gapy 4", "[grow,fill]"));
    // the group editor (card Edit_probe_group): a name, a description, a searchable checklist
    private final JLabel groupEditTitle = new JLabel();
    private final JTextField groupEditName = new JTextField();
    private final JTextField groupEditDescription = new JTextField();
    private final JTextField groupEditSearch = new JTextField();
    private final JPanel groupEditList = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2", "[grow,fill]"));
    private final JLabel groupEditCount = new JLabel();
    private final InlineMessage groupEditCheck = new InlineMessage();
    private final Set<String> groupEditTicks = new HashSet<>();
    private ProbeGroup editingGroup;

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
    /**
     * The Scan page's own way to start over (2026-11-01, the maintainer: "I want to create a new
     * scan, create a button for it in the scan panel, I don't need to go back to the scan history
     * to do it"): empties the form, the chips and the result. Disabled while a scan runs.
     */
    private final JButton newScanButton = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ScanPage.NEW_SCAN));
    /** The scan in progress, or null. Set on the worker, read on the EDT by the Stop button. */
    private volatile NMapScanner.ScanHandle running;
    private ReportContent selectedScan;
    private ProbeContent selectedProbe;

    // The probe editor (2026-10-26): the name is read from the JSON, Check validates inline
    private final JLabel editTitle = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeEditor.TITLE);
    private final JLabel editName = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeEditor.NAME);
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
        cardStack.add(buildProbeGroupsPanel(), "Probe_groups");
        cardStack.add(buildEditProbeGroup(), "Edit_probe_group");

        refreshProbeChips();

        ctx.session().onAuthChange(e -> SwingUtilities.invokeLater(() -> {
            // Login or logout, the previous subject's data leaves the screen first. Only a
            // signed-in subject then gets their own rows loaded back.
            resetPanel();
            if (Boolean.TRUE.equals(e.getNewValue())) {
                reloadScanResults();
                reloadProbes();
                reloadProbeGroups();
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
        probeGroups = List.of();
        editingGroup = null;
        groupEditTicks.clear();
        groupEditCheck.clear();
        historyModel.setRows(scanResults);
        updateHistoryCount();
        refreshLibraryRows();
        refreshGroupRows();
        refreshProbeChips();
        cardStack.show("Scan");
    }

    /** Shows a report on the scanner page as a finished, stored run; for hosts and renders. */
    public void showResult(String name, String json) {
        resultView.setReport(name, json, null, true);
    }

    private JPanel buildScanPanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setName(NSAppUtil.ScanPage.PAGE.getName());
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        // the page is named like its sidebar item (2026-11-01: it said "New scan", which is now the button)
        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = new JLabel(NSAppUtil.Screen.SCAN.getDisplayName());
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = GUIUtil.applyProp(new JLabel(), NSAppUtil.ScanPage.SUBTITLE);
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        newScanButton.addActionListener(_ -> newScan());
        head.add(newScanButton);
        out.add(head, "growx");

        probeChips.setEmptyText(NSAppUtil.ScanPage.PROBES_EMPTY.getDisplayName());
        probeChips.addAction(NSAppUtil.ScanPage.ADD_PROBE.getDisplayName(), this::showProbeMenu);
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
     * New scan: the form, the chips and the result area back to how a fresh login finds them,
     * so the next scan starts from nothing without a trip through the history page. The
     * history, the probe library and a stored report open on their own cards are untouched.
     */
    private void newScan() {
        form.reset();
        tickedProbes.clear();
        refreshProbeChips();
        resultView.clear();
        form.getRunButton().requestFocusInWindow();
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
        newScanButton.setEnabled(false);
        BackgroundTask.run(this, run, () -> runScan(cfg), outcome -> {
            stopButton.setEnabled(false);
            newScanButton.setEnabled(true);
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
                        NSAppUtil.ScanPage.SESSION_ENDED_DIALOG.getDisplayName(), JOptionPane.INFORMATION_MESSAGE);
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
            if (tickedProbes.contains(row.key())) chips.add(new ChipPanel.Chip(row.key(), row.label(), row.stored() ? NSAppUtil.ScanPage.CHIP_MINE.getDisplayName() : null));
        }
        probeChips.setChips(chips);
        form.setServiceDetection(!chips.isEmpty()); // -sV mirrors the chips both ways, as applyTo does
        // an empty Ports field means the ticked probes' ports (2026-10-31): say which
        form.setPortsPlaceholder(ProbeSelection.portsPlaceholder(tickedDefinitions()));
    }

    /**
     * The definitions behind the ticks, for the Ports placeholder: bundled ones by name, stored
     * ones parsed; a stored probe that does not parse is left out here (the run reports it).
     */
    private List<ProbeDefinition> tickedDefinitions() {
        List<ProbeDefinition> defs = new ArrayList<>();
        for (ProbeDefinition d : bundledProbes) {
            if (tickedProbes.contains(ProbeSelection.bundledKey(d.getName()))) defs.add(d);
        }
        for (ProbeContent p : probes) {
            if (p.getName() == null || !tickedProbes.contains(ProbeSelection.storedKey(p))) continue;
            try {
                defs.add(ProbeDefinitionLoader.parse(p.getContent(), p.getName()));
            } catch (IllegalArgumentException ignored) {
                // the run says which probe is invalid; the placeholder just skips it
            }
        }
        return defs;
    }

    /** Every bundled and stored probe ticked: what the Service detection box means on its own. */
    private void tickAllProbes() {
        for (ProbeRow row : probeRows()) tickedProbes.add(row.key());
    }

    /**
     * The Add probe menu: a GROUPS section (2026-11-01: one check item per saved group, ticked
     * when every member that still exists is ticked; a tick adds exactly the members' keys, an
     * untick removes exactly them; a footer saves the current ticks as a group), then a check
     * item per bundled and stored probe, grouped, with an All per group.
     */
    private void showProbeMenu() {
        JPopupMenu menu = new JPopupMenu();
        addGroupSection(menu);
        menu.addSeparator();
        List<ProbeRow> rows = probeRows();
        addProbeGroup(menu, NSAppUtil.ProbeMenu.SECTION_BUNDLED, rows.stream().filter(r -> !r.stored()).toList(), NSAppUtil.ProbeMenu.EMPTY_BUNDLED);
        menu.addSeparator();
        addProbeGroup(menu, NSAppUtil.ProbeMenu.SECTION_MINE, rows.stream().filter(ProbeRow::stored).toList(), NSAppUtil.ProbeMenu.EMPTY_MINE);
        menu.addSeparator();
        JMenuItem saveAs = GUIUtil.applyProp(new JMenuItem("", IconUtil.svgIcon("io/xlogistx/gui/icons/folder.svg", 14, UITokens.text())), NSAppUtil.ProbeGroupMenu.SAVE_AS);
        saveAs.setEnabled(!tickedProbes.isEmpty());
        saveAs.addActionListener(_ -> saveTickedAsGroup());
        menu.add(saveAs);
        JComponent anchor = probeChips;
        menu.show(anchor, 0, anchor.getHeight());
    }

    private void addGroupSection(JPopupMenu menu) {
        JMenuItem header = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.ProbeGroupMenu.HEADER);
        header.setEnabled(false);
        header.setFont(UITokens.font(Font.BOLD, -2f));
        menu.add(header);
        if (probeGroups.isEmpty()) {
            JMenuItem none = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.ProbeGroupMenu.EMPTY);
            none.setEnabled(false);
            menu.add(none);
            return;
        }
        for (ProbeGroupModel.Row row : ProbeGroupModel.rows(probeGroups, List.of(), bundledProbes, probes)) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(row.name(), ProbeGroupModel.isTicked(tickedProbes, row.keys()));
            item.setToolTipText(groupTip(row));
            item.addActionListener(_ -> tickGroup(row, item.isSelected()));
            menu.add(item);
        }
    }

    /** The member names, a missing one suffixed; the tooltip of a group's check item. */
    private static String groupTip(ProbeGroupModel.Row row) {
        List<String> parts = new ArrayList<>();
        for (String name : ProbeGroupModel.members(row.group())) {
            parts.add(row.missing().contains(name) ? name + " (missing)" : name);
        }
        return parts.isEmpty() ? "No probes" : String.join(", ", parts);
    }

    /** Ticks what exists of the group (or unticks exactly that), and says what no longer exists. */
    private void tickGroup(ProbeGroupModel.Row row, boolean on) {
        ProbeGroupModel.applyTick(tickedProbes, row.keys(), on);
        refreshProbeChips();
        String note = ProbeGroupModel.missingNote(row.group(), row.missing());
        if (note != null && on) form.showNote(note);
    }

    /**
     * <i>Save ticked as group…</i>: a name (and a description) for the chips as they stand. The
     * group stores the probes' names in catalog order; a name already in use updates that group.
     */
    private void saveTickedAsGroup() {
        Set<String> names = ProbeGroupModel.namesFromTicks(tickedProbes, bundledProbes, probes);
        String csv = ProbeGroupModel.describe(names);
        JTextField name = new JTextField(22);
        JTextField description = new JTextField(22);
        JPanel ask = new JPanel(new MigLayout("insets 0, wrap 2, gapy 6", "[][grow,fill]"));
        ask.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupMenu.SAVE_AS_NAME));
        ask.add(GUIUtil.applyProp(name, NSAppUtil.ProbeGroupMenu.SAVE_AS_NAME_FIELD));
        ask.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupMenu.SAVE_AS_DESCRIPTION));
        ask.add(GUIUtil.applyProp(description, NSAppUtil.ProbeGroupMenu.SAVE_AS_DESCRIPTION_FIELD));
        WrapLabel members = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.ProbeGroupMenu.SAVE_AS_PROBES);
        members.setText(NSAppUtil.ProbeGroupMenu.SAVE_AS_PROBES.getDisplayName() + ": " + csv);
        members.setWrapWidth(360);
        members.setForeground(UITokens.muted());
        ask.add(members, "span 2, gaptop 6");
        while (true) {
            int ok = JOptionPane.showConfirmDialog(this, ask, NSAppUtil.ProbeGroupMenu.SAVE_AS_DIALOG.getDisplayName(),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) return;
            String problem = ProbeGroupModel.validate(name.getText(), names);
            if (problem == null) break;
            JOptionPane.showMessageDialog(this, problem, NSAppUtil.ProbeGroupMenu.SAVE_AS_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
        }
        ProbeGroup existing = ProbeGroupModel.existingByName(probeGroups, name.getText());
        ProbeGroup g = existing != null ? existing : new ProbeGroup();
        g.setName(name.getText().trim());
        if (existing == null || !description.getText().isBlank()) g.setDescription(description.getText().trim());
        g.setProbes(names);
        boolean updated = existing != null;
        BackgroundTask.run(this, null, () -> ctx.session().saveProbeGroup(g), saved -> {
            reloadProbeGroups();
            form.showNote((updated ? "Updated group \"" : "Saved group \"") + g.getName() + "\" — tick it under Add probe › Groups.");
        });
    }

    private void addProbeGroup(JPopupMenu menu, NSAppUtil.ProbeMenu section, List<ProbeRow> rows, NSAppUtil.ProbeMenu empty) {
        JMenuItem header = GUIUtil.applyProp(new JMenuItem(), section);
        header.setText(section.getDisplayName().toUpperCase());
        header.setEnabled(false);
        header.setFont(UITokens.font(Font.BOLD, -2f));
        menu.add(header);
        if (rows.isEmpty()) {
            JMenuItem none = GUIUtil.applyProp(new JMenuItem(), empty);
            none.setEnabled(false);
            menu.add(none);
            return;
        }
        List<String> keys = rows.stream().map(ProbeRow::key).toList();
        JCheckBoxMenuItem all = GUIUtil.applyProp(new JCheckBoxMenuItem("", tickedProbes.containsAll(keys)), NSAppUtil.ProbeMenu.ALL);
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
        JOptionPane.showMessageDialog(this, new JScrollPane(text), NSAppUtil.ScanPage.USAGE_DIALOG.getDisplayName(), JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * The Probe library (2026-10-26, on the maintainer's instruction: "the bundled probes can't
     * be read, and it doesn't explain how to create one"): a table of every probe a scan can run,
     * bundled and stored, with the selected one read-only in a detail pane; with nothing selected
     * the pane says what a probe is and the three ways to add one. Same shape as the history page.
     */
    private JPanel buildProbePanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setName(NSAppUtil.ProbeLibraryPage.PAGE.getName());
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeLibraryPage.TITLE);
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeLibraryPage.SUBTITLE);
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        JButton withAssistant = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/chat.svg", 16, UITokens.text())), NSAppUtil.ProbeLibraryPage.WRITE_WITH_ASSISTANT);
        withAssistant.addActionListener(_ -> onWriteProbeWithAssistant());
        head.add(withAssistant);
        JButton newProbe = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ProbeLibraryPage.NEW_PROBE));
        newProbe.addActionListener(_ -> newProbe());
        head.add(newProbe);
        out.add(head, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][][]push[]"));
        bar.setOpaque(false);
        GUIUtil.applyProp(librarySearch, NSAppUtil.ProbeLibraryPage.SEARCH);
        librarySearch.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(librarySearch, "growx");
        libraryFilter.select(NSAppUtil.ProbeLibraryFilter.ALL);
        libraryFilter.onChange(_ -> filterLibrary());
        bar.add(libraryFilter);
        libraryCount.setForeground(UITokens.muted());
        libraryCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(libraryCount);
        JButton groups = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/folder.svg", 16, UITokens.text())), NSAppUtil.ProbeGroupsPage.OPEN);
        groups.putClientProperty("JButton.buttonType", "toolBarButton");
        groups.addActionListener(_ -> showProbeGroups());
        bar.add(groups);
        JButton definition = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/book.svg", 16, UITokens.text())), NSAppUtil.ProbeLibraryPage.DEFINITION);
        definition.putClientProperty("JButton.buttonType", "toolBarButton");
        definition.addActionListener(_ -> showProbeDefinition());
        bar.add(definition);
        out.add(bar, "growx");

        Tables.style(GUIUtil.applyProp(libraryTable, NSAppUtil.ProbeLibraryPage.TABLE));
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
        JLabel t = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeLibraryPage.HOWTO_TITLE);
        t.setFont(UITokens.font(Font.BOLD, 2f));
        p.add(t, "gapbottom 4");
        WrapLabel what = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.ProbeLibraryPage.HOWTO_TEXT);
        what.setWrapWidth(300);
        what.setForeground(UITokens.muted());
        p.add(what, "gapbottom 8");

        // each way is a link; the constant's description is the note under it
        JButton copy = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeLibraryPage.HOWTO_COPY));
        copy.addActionListener(_ -> selectFirstBundledRow());
        p.add(copy, "growx 0");
        p.add(note(NSAppUtil.ProbeLibraryPage.HOWTO_COPY.getDescription()));

        JButton ask = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeLibraryPage.HOWTO_ASK));
        ask.addActionListener(_ -> onWriteProbeWithAssistant());
        p.add(ask, "growx 0, gaptop 8");
        p.add(note(NSAppUtil.ProbeLibraryPage.HOWTO_ASK.getDescription()));

        JButton fresh = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeLibraryPage.HOWTO_NEW));
        fresh.addActionListener(_ -> newProbe());
        p.add(fresh, "growx 0, gaptop 8");
        p.add(note(NSAppUtil.ProbeLibraryPage.HOWTO_NEW.getDescription()));
        return p;
    }

    private static WrapLabel note(String text) {
        WrapLabel l = new WrapLabel(text);
        l.setWrapWidth(290);
        l.setForeground(UITokens.muted());
        l.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        return l;
    }

    /** The detail pane for a selected probe: its name with what you can do with it, its facts, its JSON read-only. */
    private JPanel buildLibraryProbeCard() {
        JPanel p = new JPanel(new MigLayout("insets 16, wrap 1, gapy 8, fill", "[grow,fill]", "[][][][grow,fill]"));
        p.setOpaque(false);
        probeTitle.setFont(UITokens.font(Font.BOLD, 2f));
        // Title on the left, the actions (Copy / Edit / Delete) on the right of the same row: a human
        // looks for "what can I do with this" next to the name, not under a long JSON listing (2026-10-30).
        JPanel header = new JPanel(new MigLayout("insets 0, gapx 8", "[grow][][][]"));
        header.setOpaque(false);
        header.add(probeTitle, "growx");
        copyProbe.addActionListener(_ -> onCopyBundledProbe(selectedLibraryRow()));
        editProbe.addActionListener(_ -> {
            ProbeLibraryModel.Row row = selectedLibraryRow();
            if (row != null && row.stored()) onEditProbe(row.content());
        });
        deleteProbe.setForeground(UITokens.danger());
        deleteProbe.addActionListener(_ -> {
            ProbeLibraryModel.Row row = selectedLibraryRow();
            if (row == null || !row.stored()) return;
            int ok = JOptionPane.showConfirmDialog(this, "Delete the probe \"" + row.name() + "\"?", NSAppUtil.ProbeLibraryPage.DELETE_DIALOG.getDisplayName(),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveProbe(row.content());
        });
        for (JButton b : new JButton[]{copyProbe, editProbe, deleteProbe}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            header.add(b, "hidemode 3");
        }
        p.add(header);
        p.add(probeFacts);
        p.add(probeProblem, "hidemode 3");
        GUIUtil.applyProp(probeSource, NSAppUtil.ProbeLibraryPage.SOURCE);
        probeSource.setEditable(false);
        probeSource.setFont(UITokens.mono(-1f));
        probeSource.setMargin(new Insets(10, 12, 10, 12));
        JScrollPane sourceScroll = new JScrollPane(probeSource);
        sourceScroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        sourceScroll.setMinimumSize(new Dimension(0, 0));
        p.add(sourceScroll, "grow, push");
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
            WrapLabel description = probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_DESCRIPTION.getDisplayName(), d.getDescription());
            if (description != null) description.setWrapWidth(230);
            probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_SERVICE.getDisplayName(), d.getService());
            probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_TRANSPORT.getDisplayName(), d.getTransport());
            probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_PORTS.getDisplayName(), ProbeLibraryModel.ports(d));
            probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_PRIORITY.getDisplayName(), String.valueOf(d.getPriority()));
            probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_PORT_SCOPED.getDisplayName(), d.isPortScoped() ? "yes, declared ports only" : "no");
            if (d.getOverallTimeoutSec() != null) probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_WATCHDOG.getDisplayName(), d.getOverallTimeoutSec() + " s");
            int states = d.getStates() == null ? 0 : d.getStates().size();
            probeFacts.putMono(NSAppUtil.ProbeLibraryPage.FACT_STATES.getDisplayName(), states + ", start at " + d.getStart());
            probeProblem.clear();
        } else {
            probeProblem.error("This probe no longer loads: " + row.error());
        }
        probeFacts.put(NSAppUtil.ProbeLibraryPage.FACT_SOURCE.getDisplayName(),
                (row.stored() ? NSAppUtil.ProbeLibraryPage.SOURCE_MINE : NSAppUtil.ProbeLibraryPage.SOURCE_BUNDLED).getDisplayName());
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
        NSAppUtil.ProbeLibraryFilter chosen = libraryFilter.selectedSource();
        NSAppUtil.ProbeLibraryFilter f = chosen != null ? chosen : NSAppUtil.ProbeLibraryFilter.ALL;
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
        openProbeEditor(new ProbeContent(), NSAppUtil.ProbeEditor.TITLE_NEW.getDisplayName());
    }

    /** Opens the editor with a bundled probe's JSON as a new draft (2026-10-26). */
    private void onCopyBundledProbe(ProbeLibraryModel.Row row) {
        if (row == null || row.stored()) return;
        ProbeContent draft = new ProbeContent();
        draft.setContent(row.source());
        openProbeEditor(draft, NSAppUtil.ProbeEditor.TITLE_COPY.getDisplayName() + " " + row.name());
    }

    /**
     * Hands the assistant the probe definition and a request for a probe (2026-10-26): a small
     * dialog asks what to detect and where, then the Chat page opens with the request typed and
     * the definition attached, so only Send is left. With no chat open the assistant's own
     * message shows and the app goes to Chats, where one can be created.
     */
    private void onWriteProbeWithAssistant() {
        JTextField service = GUIUtil.applyProp(new JTextField(18), NSAppUtil.AskProbe.SERVICE_FIELD);
        JTextField port = GUIUtil.applyProp(new JTextField(6), NSAppUtil.AskProbe.PORT_FIELD);
        JPanel ask = new JPanel(new MigLayout("insets 0, wrap 2, gapy 6", "[][grow,fill]"));
        ask.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.AskProbe.SERVICE));
        ask.add(service);
        ask.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.AskProbe.PORT));
        ask.add(port, "growx 0");
        WrapLabel hint = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.AskProbe.HINT);
        hint.setWrapWidth(360);
        hint.setForeground(UITokens.muted());
        ask.add(hint, "span 2, gaptop 6");
        int ok = JOptionPane.showConfirmDialog(this, ask, NSAppUtil.AskProbe.DIALOG.getDisplayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        String prompt = ProbeLibraryModel.assistantPrompt(service.getText(), port.getText());
        try {
            sendToChat.send(ProbeDefinitionLoader.probeDefinition(), "Probe definition", prompt);
        } catch (AccessSecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), NSAppUtil.AskProbe.FAILED_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            ctx.nav().show(NSAppUtil.Screen.CHAT); // no chat open: the Chat page lands on the list, New chat is there
            return;
        }
        ctx.nav().show(NSAppUtil.Screen.CHAT);
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
        JPanel card = PanelBuilder.detail(NSAppUtil.ProbeDefinitionPage.PAGE.getDisplayName(), () -> cardStack.show("Probe"), content -> {
            JLabel sub = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeDefinitionPage.SUBTITLE);
            sub.setForeground(UITokens.muted());
            content.add(sub, "gapbottom 6");
            content.add(definitionView, "grow, push");
        });
        card.setName(NSAppUtil.ProbeDefinitionPage.PAGE.getName());
        return card;
    }

    // ---- Probe groups (2026-11-01) -------------------------------------------------------------

    /** The Groups button of the library bar: the groups page. */
    public void showProbeGroups() {
        cardStack.show("Probe_groups");
    }

    /**
     * The Probe groups page, the library's shape: a head (title, back link to the library, the
     * primary <i>New group</i>), a bar (search, count), and a split card — the table on
     * {@link ProbeGroupModel} left, right a how-to with nothing selected or the selected group
     * (name, Edit, confirmed Delete, its facts, its members with a bundled / mine / missing badge).
     */
    private JPanel buildProbeGroupsPanel() {
        JPanel out = new JPanel(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill", "[grow,fill]", "[][]0[grow,fill]"));
        out.setName(NSAppUtil.ProbeGroupsPage.PAGE.getName());
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupsPage.TITLE);
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupsPage.SUBTITLE);
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        JButton back = UITokens.link(GUIUtil.applyProp(new JButton(new IconUtil.BackIcon(16)), NSAppUtil.ProbeGroupsPage.BACK));
        back.addActionListener(_ -> cardStack.show("Probe"));
        head.add(back);
        JButton newGroup = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ProbeGroupsPage.NEW_GROUP));
        newGroup.addActionListener(_ -> openGroupEditor(null));
        head.add(newGroup);
        out.add(head, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push"));
        bar.setOpaque(false);
        GUIUtil.applyProp(groupSearch, NSAppUtil.ProbeGroupsPage.SEARCH);
        groupSearch.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(groupSearch, "growx");
        GUIUtil.applyProp(groupCount, NSAppUtil.ProbeGroupsPage.COUNT);
        groupCount.setForeground(UITokens.muted());
        groupCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(groupCount);
        out.add(bar, "growx");

        Tables.style(GUIUtil.applyProp(groupTable, NSAppUtil.ProbeGroupsPage.TABLE));
        Tables.width(groupTable, ProbeGroupModel.COL_NAME, 180);
        Tables.width(groupTable, ProbeGroupModel.COL_PROBES, 110);
        groupTable.getColumnModel().getColumn(ProbeGroupModel.COL_NAME).setCellRenderer(new MonoRenderer());
        groupTable.setRowSorter(groupSorter);
        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showGroupDetail(selectedGroupRow());
        });
        groupTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() != 2) return;
                ProbeGroupModel.Row row = selectedGroupRow();
                if (row != null && !row.preset()) openGroupEditor(row.group());
            }
        });
        groupSearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                filterGroups();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                filterGroups();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                filterGroups();
            }
        });

        JScrollPane tableScroll = new JScrollPane(groupTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        tableScroll.getViewport().setBackground(UITokens.surface());
        tableScroll.setMinimumSize(new Dimension(0, 0));

        groupDetail.add(buildGroupHowTo(), "howto");
        groupDetail.add(buildGroupCard(), "group");
        JComponent detail = groupDetail.view();
        detail.setBackground(UITokens.surfaceAlt());
        detail.setOpaque(true);
        detail.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, UITokens.border()));
        detail.setMinimumSize(new Dimension(0, 0));
        groupDetail.show("howto");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detail);
        split.setResizeWeight(0.58);
        split.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        split.setDividerSize(6);
        split.setMinimumSize(new Dimension(0, 0));
        out.add(split, "grow, push");
        return out;
    }

    /** The detail pane with nothing selected: what a group is, and the two ways to make one. */
    private JPanel buildGroupHowTo() {
        JPanel p = new JPanel(new MigLayout("insets 20, wrap 1, gapy 6", "[grow,fill]"));
        p.setOpaque(false);
        JLabel t = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupsPage.HOWTO_TITLE);
        t.setFont(UITokens.font(Font.BOLD, 2f));
        p.add(t, "gapbottom 4");
        WrapLabel what = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.ProbeGroupsPage.HOWTO_TEXT);
        what.setWrapWidth(300);
        what.setForeground(UITokens.muted());
        p.add(what, "gapbottom 8");

        JButton fresh = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeGroupsPage.HOWTO_NEW));
        fresh.addActionListener(_ -> openGroupEditor(null));
        p.add(fresh, "growx 0");
        p.add(note(NSAppUtil.ProbeGroupsPage.HOWTO_NEW.getDescription()));

        JButton fromScan = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeGroupsPage.HOWTO_FROM_SCAN));
        fromScan.addActionListener(_ -> ctx.nav().show(NSAppUtil.Screen.SCAN));
        p.add(fromScan, "growx 0, gaptop 8");
        p.add(note(NSAppUtil.ProbeGroupsPage.HOWTO_FROM_SCAN.getDescription()));
        return p;
    }

    /** The detail pane for a selected group: the name with Edit / Delete, its facts, its members. */
    private JPanel buildGroupCard() {
        JPanel p = new JPanel(new MigLayout("insets 16, wrap 1, gapy 8, fill", "[grow,fill]", "[][][][grow,fill]"));
        p.setOpaque(false);
        GUIUtil.applyProp(groupTitle, NSAppUtil.ProbeGroupsPage.GROUP_TITLE);
        groupTitle.setFont(UITokens.font(Font.BOLD, 2f));
        JPanel header = new JPanel(new MigLayout("insets 0, gapx 8", "[grow][][]"));
        header.setOpaque(false);
        header.add(groupTitle, "growx");
        JButton edit = GUIUtil.applyProp(new JButton(new IconUtil.EditIcon(16)), NSAppUtil.ProbeGroupsPage.EDIT);
        edit.addActionListener(_ -> {
            ProbeGroupModel.Row row = selectedGroupRow();
            if (row != null && !row.preset()) openGroupEditor(row.group());
        });
        JButton delete = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ProbeGroupsPage.DELETE);
        delete.setForeground(UITokens.danger());
        delete.addActionListener(_ -> {
            ProbeGroupModel.Row row = selectedGroupRow();
            if (row == null || row.preset()) return;
            int ok = JOptionPane.showConfirmDialog(this, "Delete the group \"" + row.name() + "\"? Its probes stay.",
                    NSAppUtil.ProbeGroupsPage.DELETE_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveGroup(row.group());
        });
        for (JButton b : new JButton[]{edit, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            header.add(b);
        }
        p.add(header);
        p.add(groupFacts);
        JLabel members = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupsPage.MEMBERS);
        members.setFont(UITokens.font(Font.BOLD, 0f));
        p.add(members, "gaptop 6");
        GUIUtil.applyProp(groupMembers, NSAppUtil.ProbeGroupsPage.MEMBER_LIST);
        groupMembers.setOpaque(false);
        JScrollPane scroll = new JScrollPane(groupMembers);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.setMinimumSize(new Dimension(0, 0));
        p.add(scroll, "grow, push");
        return p;
    }

    /** Fills the detail pane for {@code row}; null shows the how-to card. */
    private void showGroupDetail(ProbeGroupModel.Row row) {
        if (row == null) {
            groupDetail.show("howto");
            return;
        }
        groupTitle.setText(row.name());
        groupFacts.clear();
        WrapLabel description = groupFacts.put(NSAppUtil.ProbeGroupsPage.FACT_DESCRIPTION.getDisplayName(), row.description().isEmpty() ? "—" : row.description());
        if (description != null) description.setWrapWidth(230);
        groupFacts.put(NSAppUtil.ProbeGroupsPage.FACT_PROBES.getDisplayName(), row.count());
        if (!row.missing().isEmpty()) groupFacts.put(NSAppUtil.ProbeGroupsPage.FACT_MISSING.getDisplayName(), String.join(", ", row.missing()));
        groupFacts.put(NSAppUtil.ProbeGroupsPage.FACT_SOURCE.getDisplayName(), (row.preset() ? NSAppUtil.ProbeGroupsPage.SOURCE_PRESET : NSAppUtil.ProbeGroupsPage.SOURCE_MINE).getDisplayName());
        groupMembers.removeAll();
        for (String name : ProbeGroupModel.members(row.group())) {
            JPanel line = new JPanel(new MigLayout("insets 0, gapx 8", "[][]"));
            line.setOpaque(false);
            JLabel l = new JLabel(name);
            l.setFont(UITokens.mono(-1f));
            line.add(l);
            Set<String> keys = ProbeSelection.keysForNames(name, bundledProbes, probes);
            if (keys.isEmpty()) line.add(GUIUtil.applyProp(new BadgeLabel("", BadgeLabel.Tone.WARN), NSAppUtil.ProbeGroupsPage.BADGE_MISSING));
            else if (keys.iterator().next().startsWith("b:")) line.add(GUIUtil.applyProp(new BadgeLabel("", BadgeLabel.Tone.NEUTRAL), NSAppUtil.ProbeGroupsPage.BADGE_BUNDLED));
            else line.add(GUIUtil.applyProp(new BadgeLabel("", BadgeLabel.Tone.ACCENT), NSAppUtil.ProbeGroupsPage.BADGE_MINE));
            groupMembers.add(line);
        }
        groupMembers.revalidate();
        groupMembers.repaint();
        groupDetail.show("group");
    }

    private ProbeGroupModel.Row selectedGroupRow() {
        int row = groupTable.getSelectedRow();
        return row < 0 ? null : groupModel.at(groupTable.convertRowIndexToModel(row));
    }

    /** Rebuilds the groups table from the groups and the probes known now; keeps the selection by name. */
    private void refreshGroupRows() {
        ProbeGroupModel.Row before = selectedGroupRow();
        groupModel.setRows(ProbeGroupModel.rows(probeGroups, List.of(), bundledProbes, probes));
        filterGroups();
        if (before != null && selectGroupByName(before.name())) return;
        groupTable.clearSelection();
        showGroupDetail(null);
    }

    private boolean selectGroupByName(String name) {
        for (int i = 0; i < groupTable.getRowCount(); i++) {
            if (groupModel.at(groupTable.convertRowIndexToModel(i)).name().equals(name)) {
                groupTable.setRowSelectionInterval(i, i);
                groupTable.scrollRectToVisible(groupTable.getCellRect(i, 0, true));
                return true;
            }
        }
        return false;
    }

    private void filterGroups() {
        String q = groupSearch.getText();
        groupSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ProbeGroupModel, ? extends Integer> entry) {
                return ProbeGroupModel.matches(entry.getModel().at(entry.getIdentifier()).group(), q);
            }
        });
        int shown = groupTable.getRowCount(), all = groupModel.getRowCount();
        groupCount.setText(all == 0 ? "" : shown == all ? all + " groups" : shown + " of " + all + " groups");
    }

    /** Opens the editor on {@code group} (a stored row) or, with null, an empty draft. */
    private void openGroupEditor(ProbeGroup group) {
        editingGroup = group != null ? group : new ProbeGroup();
        GUIUtil.applyProp(groupEditTitle, group == null ? NSAppUtil.ProbeGroupEditor.TITLE_NEW : NSAppUtil.ProbeGroupEditor.TITLE_EDIT);
        groupEditName.setText(Objects.toString(editingGroup.getName(), ""));
        groupEditDescription.setText(Objects.toString(editingGroup.getDescription(), ""));
        groupEditSearch.setText("");
        groupEditTicks.clear();
        groupEditTicks.addAll(ProbeGroupModel.memberKeys(editingGroup, bundledProbes, probes));
        groupEditCheck.clear();
        List<String> missing = ProbeGroupModel.missing(editingGroup, bundledProbes, probes);
        if (!missing.isEmpty()) groupEditCheck.info(NSAppUtil.ProbeGroupEditor.CHECK.getDescription() + ": " + String.join(", ", missing));
        refreshGroupEditList();
        cardStack.show("Edit_probe_group");
        groupEditName.requestFocusInWindow();
    }

    /**
     * The group editor (card {@code Edit_probe_group}): Name, Description, a search box over a
     * checklist of every probe (Bundled and Mine, an All each, the same rows as the Add probe
     * popup), a live count, Save and Cancel. Save validates inline, updates a group of the same
     * name instead of adding a second, and returns to the groups page with the row selected.
     */
    private JPanel buildEditProbeGroup() {
        JPanel content = new JPanel(new MigLayout("wrap 1, insets 10, gapy 6, fill", "[grow,fill]", "[][][][][][grow,fill][]"));
        content.setName(NSAppUtil.ProbeGroupEditor.EDITOR.getName());
        JButton back = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.BackIcon(32), true), NSAppUtil.ProbeGroupEditor.BACK);
        back.addActionListener(_ -> cardStack.show("Probe_groups"));
        content.add(back, "growx 0");
        groupEditTitle.setFont(PanelBuilder.title("").getFont());
        content.add(groupEditTitle, "gaptop 6");

        JPanel fields = new JPanel(new MigLayout("insets 0, wrap 2, gapy 6", "[][grow,fill]"));
        fields.setOpaque(false);
        fields.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupEditor.NAME));
        GUIUtil.applyProp(groupEditName, NSAppUtil.ProbeGroupEditor.NAME_FIELD);
        fields.add(groupEditName, "wmax 420");
        fields.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeGroupEditor.DESCRIPTION));
        GUIUtil.applyProp(groupEditDescription, NSAppUtil.ProbeGroupEditor.DESCRIPTION_FIELD);
        fields.add(groupEditDescription, "wmax 420");
        content.add(fields, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push"));
        bar.setOpaque(false);
        GUIUtil.applyProp(groupEditSearch, NSAppUtil.ProbeGroupEditor.SEARCH);
        groupEditSearch.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        groupEditSearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                refreshGroupEditList();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                refreshGroupEditList();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                refreshGroupEditList();
            }
        });
        bar.add(groupEditSearch, "growx");
        GUIUtil.applyProp(groupEditCount, NSAppUtil.ProbeGroupEditor.COUNT);
        groupEditCount.setForeground(UITokens.muted());
        bar.add(groupEditCount);
        content.add(bar, "growx");
        content.add(GUIUtil.applyProp(groupEditCheck, NSAppUtil.ProbeGroupEditor.CHECK), "hidemode 3");

        GUIUtil.applyProp(groupEditList, NSAppUtil.ProbeGroupEditor.LIST);
        groupEditList.setBackground(UITokens.surface());
        groupEditList.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JScrollPane scroll = new JScrollPane(groupEditList);
        scroll.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        scroll.getViewport().setBackground(UITokens.surface());
        content.add(scroll, "grow, push");

        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8", "[][]push"));
        actions.setOpaque(false);
        JButton save = UITokens.primary(GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16, Color.WHITE)), NSAppUtil.ProbeGroupEditor.SAVE));
        save.addActionListener(_ -> saveGroupFromEditor(save));
        actions.add(save);
        JButton cancel = GUIUtil.applyProp(new JButton(new IconUtil.CancelIcon(16)), NSAppUtil.ProbeGroupEditor.CANCEL);
        cancel.addActionListener(_ -> cardStack.show("Probe_groups"));
        actions.add(cancel);
        content.add(actions, "growx");
        return content;
    }

    /** Rebuilds the checklist from the probes known now, the search box and the draft's ticks. */
    private void refreshGroupEditList() {
        groupEditList.removeAll();
        String q = groupEditSearch.getText().trim().toLowerCase(Locale.ROOT);
        List<ProbeRow> rows = probeRows();
        addGroupEditSection(NSAppUtil.ProbeGroupEditor.SECTION_BUNDLED, rows.stream().filter(r -> !r.stored()).toList(), q, NSAppUtil.ProbeGroupEditor.EMPTY_BUNDLED);
        addGroupEditSection(NSAppUtil.ProbeGroupEditor.SECTION_MINE, rows.stream().filter(ProbeRow::stored).toList(), q, NSAppUtil.ProbeGroupEditor.EMPTY_MINE);
        int n = groupEditTicks.size();
        groupEditCount.setText(n == 0 ? "no probe ticked" : n + " probe" + (n == 1 ? "" : "s") + " ticked");
        groupEditList.revalidate();
        groupEditList.repaint();
    }

    private void addGroupEditSection(NSAppUtil.ProbeGroupEditor section, List<ProbeRow> rows, String query, NSAppUtil.ProbeGroupEditor empty) {
        JLabel header = GUIUtil.applyProp(new JLabel(), section);
        header.setText(section.getDisplayName().toUpperCase());
        header.setFont(UITokens.font(Font.BOLD, -2f));
        header.setForeground(UITokens.muted());
        groupEditList.add(header, "gaptop 6");
        if (rows.isEmpty()) {
            JLabel none = GUIUtil.applyProp(new JLabel(), empty);
            none.setForeground(UITokens.muted());
            groupEditList.add(none, "gapleft 20");
            return;
        }
        List<String> keys = rows.stream().map(ProbeRow::key).toList();
        JCheckBox all = GUIUtil.applyProp(new JCheckBox("", groupEditTicks.containsAll(keys)), NSAppUtil.ProbeGroupEditor.ALL);
        all.setName(section.getName() + ".all");
        all.setOpaque(false);
        all.addActionListener(_ -> {
            if (all.isSelected()) groupEditTicks.addAll(keys);
            else keys.forEach(groupEditTicks::remove);
            refreshGroupEditList();
        });
        groupEditList.add(all);
        for (ProbeRow row : rows) {
            if (!query.isEmpty() && !row.label().toLowerCase(Locale.ROOT).contains(query)) continue;
            JCheckBox box = new JCheckBox(row.label(), groupEditTicks.contains(row.key()));
            box.setOpaque(false);
            if (row.tooltip() != null) box.setToolTipText(row.tooltip());
            box.addActionListener(_ -> {
                if (box.isSelected()) groupEditTicks.add(row.key());
                else groupEditTicks.remove(row.key());
                refreshGroupEditList();
            });
            groupEditList.add(box, "gapleft 20");
        }
    }

    /** Save: validate inline, dedupe by name, store off the EDT, back to the groups page with the row selected. */
    private void saveGroupFromEditor(JButton save) {
        if (editingGroup == null) return;
        Set<String> names = ProbeGroupModel.namesFromTicks(groupEditTicks, bundledProbes, probes);
        String problem = ProbeGroupModel.validate(groupEditName.getText(), names);
        if (problem != null) {
            groupEditCheck.error(problem);
            return;
        }
        ProbeGroup g = editingGroup;
        if (SUS.isEmpty(g.getGUID())) {
            ProbeGroup existing = ProbeGroupModel.existingByName(probeGroups, groupEditName.getText());
            if (existing != null) g = existing;
        }
        g.setName(groupEditName.getText().trim());
        g.setDescription(groupEditDescription.getText().trim());
        g.setProbes(names);
        ProbeGroup toSave = g;
        BackgroundTask.run(this, save, () -> ctx.session().saveProbeGroup(toSave), saved -> {
            editingGroup = null;
            BackgroundTask.run(this, null, () -> ctx.session().getAllProbeGroups(), loaded -> {
                probeGroups = loaded;
                refreshGroupRows();
                selectGroupByName(toSave.getName());
                cardStack.show("Probe_groups");
            });
        });
    }

    private void onRemoveGroup(ProbeGroup group) {
        BackgroundTask.runCatching(this, null, () -> ctx.session().deleteProbeGroup(group), this::reloadProbeGroups);
    }

    /** A "bundled" / "mine" badge in the Source column. */
    private static final class SourceRenderer implements javax.swing.table.TableCellRenderer {
        private final BadgeLabel bundled = GUIUtil.applyProp(new BadgeLabel("", BadgeLabel.Tone.NEUTRAL), NSAppUtil.ProbeLibraryPage.BADGE_BUNDLED);
        private final BadgeLabel mine = GUIUtil.applyProp(new BadgeLabel("", BadgeLabel.Tone.ACCENT), NSAppUtil.ProbeLibraryPage.BADGE_MINE);
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
        out.setName(NSAppUtil.ScanHistoryPage.PAGE.getName());
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));

        JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
        head.setOpaque(false);
        JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
        titles.setOpaque(false);
        JLabel title = GUIUtil.applyProp(new JLabel(), NSAppUtil.ScanHistoryPage.TITLE);
        title.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(title);
        JLabel sub = GUIUtil.applyProp(new JLabel(), NSAppUtil.ScanHistoryPage.SUBTITLE);
        sub.setForeground(UITokens.muted());
        titles.add(sub);
        head.add(titles, "wmin 0");
        JButton newScan = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ScanHistoryPage.NEW_SCAN));
        newScan.addActionListener(_ -> ctx.nav().show(NSAppUtil.Screen.SCAN));
        head.add(newScan);
        out.add(head, "growx");

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][][][][][][]"));
        bar.setOpaque(false);
        JTextField search = GUIUtil.applyProp(new JTextField(), NSAppUtil.ScanHistoryPage.SEARCH);
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        historyCount.setForeground(UITokens.muted());
        historyCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(historyCount);
        JButton view = GUIUtil.applyProp(new JButton(new IconUtil.VisibleIcon(16)), NSAppUtil.ScanHistoryPage.VIEW);
        JButton again = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/refresh.svg", 16, UITokens.text())), NSAppUtil.ScanHistoryPage.AGAIN);
        JButton copyCommand = GUIUtil.applyProp(new JButton(new IconUtil.TextBoxIcon(16)), NSAppUtil.ScanHistoryPage.COPY_COMMAND);
        JButton copyResult = GUIUtil.applyProp(new JButton(new IconUtil.CopyIcon(16)), NSAppUtil.ScanHistoryPage.COPY_RESULT);
        JButton send = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/chat.svg", 16, UITokens.text())), NSAppUtil.ScanHistoryPage.SEND);
        JButton delete = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ScanHistoryPage.DELETE);
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
        bar.add(historyDeleteAll);
        out.add(bar, "growx");

        Tables.style(GUIUtil.applyProp(historyTable, NSAppUtil.ScanHistoryPage.TABLE));
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
            delete.setText(selected > 1 ? NSAppUtil.ScanHistoryPage.DELETE.getDisplayName() + " " + selected : NSAppUtil.ScanHistoryPage.DELETE.getDisplayName());
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
            int ok = JOptionPane.showConfirmDialog(this, "Delete " + what + "?", NSAppUtil.ScanHistoryPage.DELETE_DIALOG.getDisplayName() + (rows.size() == 1 ? "" : "s"),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) onRemoveScanResults(rows);
        });
        historyDeleteAll.addActionListener(_ -> {
            int all = historyModel.getRowCount();
            if (all == 0) return;
            int ok = JOptionPane.showConfirmDialog(this,
                    "Delete all " + all + " scan" + (all == 1 ? "" : "s") + " in your history? This cannot be undone.",
                    NSAppUtil.ScanHistoryPage.DELETE_ALL_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
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
        historyCount.setText(all == 0 ? NSAppUtil.ScanHistoryPage.COUNT_EMPTY.getDisplayName() : shown == all ? all + " scans" : shown + " of " + all + " scans");
        historyDeleteAll.setEnabled(all > 0);
    }

    /** The history rows: projections, re-fetched by GUID before anything reads their content. */
    private static final class HistoryModel extends javax.swing.table.AbstractTableModel {
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
            return NSAppUtil.ScanHistoryColumn.values().length;
        }

        public String getColumnName(int c) {
            return NSAppUtil.ScanHistoryColumn.values()[c].getDisplayName();
        }

        public Object getValueAt(int r, int c) {
            ReportContent s = rows.get(r);
            return switch (NSAppUtil.ScanHistoryColumn.values()[c]) {
                case SCAN -> s.getName();
                case COMMAND -> commandOf(s);
                case WHEN -> s.getCreationTime() > 0 ? STAMP.format(Instant.ofEpochMilli(s.getCreationTime())) : "";
                case HOSTS_UP -> property(s, "hostsUp");
                case OPEN_PORTS -> property(s, "openPorts");
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
            JOptionPane.showMessageDialog(this, "This report did not record its command.", NSAppUtil.ScanHistoryPage.AGAIN_DIALOG.getDisplayName(),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Object saved = scan.getProperties() != null ? scan.getProperties().getValue("probes") : null;
        tickedProbes.clear();
        tickedProbes.addAll(ProbeSelection.keysForNames(saved != null ? saved.toString() : null, bundledProbes, probes));
        form.setCommand(command);
        form.setScanName(scan.getName());
        refreshProbeChips();
        ctx.nav().show(NSAppUtil.Screen.SCAN);
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
                        NSAppUtil.ScanHistoryPage.NOT_FOUND_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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
                        NSAppUtil.ScanHistoryPage.NOT_FOUND_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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
            refreshGroupRows(); // a group's resolved count follows the probes known now
            refreshProbeChips();
        });
    }

    /** Re-reads the subject's probe groups off the EDT and refreshes the groups table (and the popup's section next time it opens). */
    public void reloadProbeGroups() {
        BackgroundTask.run(this, null, () -> ctx.session().getAllProbeGroups(), loaded -> {
            probeGroups = loaded;
            refreshGroupRows();
        });
    }

    /** What one probe reload produced: the stored rows and the library's rows built from them. */
    private record ProbeLoad(List<ProbeContent> probes, List<ProbeLibraryModel.Row> rows) {}

    private void onViewScanResult(ReportContent row) {
        if (row == null) return;
        BackgroundTask.run(this, null, () -> ctx.session().getScanResult(row.getGUID()), full -> {
            if (full == null) {
                JOptionPane.showMessageDialog(this, "That scan result is no longer available.",
                        NSAppUtil.ScanHistoryPage.NOT_FOUND_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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
        out.setName(NSAppUtil.ViewScanPage.PAGE.getName());
        out.setBackground(UITokens.color("xlogistx.ground", null, 0xF4F4F7));
        JButton back = UITokens.link(GUIUtil.applyProp(new JButton(new IconUtil.BackIcon(16)), NSAppUtil.ViewScanPage.BACK));
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
        openProbeEditor(probeContent, (SUS.isEmpty(probeContent.getGUID()) ? NSAppUtil.ProbeEditor.TITLE_NEW : NSAppUtil.ProbeEditor.TITLE_EDIT).getDisplayName());
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
        editName.setText(name == null ? NSAppUtil.ProbeEditor.NAME_PENDING.getDisplayName() : NSAppUtil.ProbeEditor.NAME_PREFIX.getDisplayName() + " " + name);
    }

    /**
     * The probe editor (2026-10-26): mono text with no wrapping, a Check button that reports
     * inline, the name read from the JSON, and the two ways to get help one click away.
     */
    private JPanel buildEditProbe() {
        viewProbeTextArea = GUIUtil.applyProp(new JTextArea(), NSAppUtil.ProbeEditor.SOURCE);
        viewProbeTextArea.setEditable(true);
        viewProbeTextArea.setFont(UITokens.mono(-1f));
        viewProbeTextArea.setTabSize(2);
        viewProbeTextArea.setMargin(new Insets(10, 12, 10, 12));

        JPanel content = new JPanel(new MigLayout("wrap 1, insets 10, gapy 6, fill", "[grow,fill]", "[][][][][][grow,fill]"));
        content.setName(NSAppUtil.ProbeEditor.PAGE.getName());
        JButton back = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.BackIcon(32), true), NSAppUtil.ProbeEditor.BACK);
        back.addActionListener(_ -> cardStack.show("Probe"));
        content.add(back, "growx 0");
        editTitle.setFont(PanelBuilder.title("").getFont());
        content.add(editTitle, "gaptop 6");
        {
            JPanel help = new JPanel(new MigLayout("insets 0, gapx 4", "[][][][]"));
            help.setOpaque(false);
            JLabel one = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeEditor.HELP_ONE);
            one.setForeground(UITokens.muted());
            help.add(one);
            JButton definition = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeEditor.HELP_DEFINITION));
            definition.setMargin(new Insets(0, 2, 0, 2));
            definition.addActionListener(_ -> showProbeDefinition());
            help.add(definition);
            JLabel or = GUIUtil.applyProp(new JLabel(), NSAppUtil.ProbeEditor.HELP_OR);
            or.setForeground(UITokens.muted());
            help.add(or);
            JButton ask = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeEditor.HELP_ASK));
            ask.setMargin(new Insets(0, 2, 0, 2));
            ask.addActionListener(_ -> onWriteProbeWithAssistant());
            help.add(ask);
            content.add(help);
            WrapLabel shadow = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.ProbeEditor.SHADOW);
            shadow.setWrapWidth(640);
            shadow.setForeground(UITokens.muted());
            content.add(shadow, "gapbottom 4");

            JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]push[]"));
            bar.setOpaque(false);
            JButton save = UITokens.primary(GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16, Color.WHITE)), NSAppUtil.ProbeEditor.SAVE));
            JButton check = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/check.svg", 16, UITokens.text())), NSAppUtil.ProbeEditor.CHECK);
            check.addActionListener(_ -> checkDraft());
            save.addActionListener(_ -> {
                if (selectedProbe == null) return;
                ProbeContent p;
                try {
                    p = probeToSave(selectedProbe, "", viewProbeTextArea.getText());
                } catch (IllegalArgumentException ex) {
                    editCheck.error(ex.getMessage());
                    JOptionPane.showMessageDialog(this, ex.getMessage(), NSAppUtil.ProbeEditor.INVALID_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
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
            ctx.nav().show(NSAppUtil.Screen.PROBES);
            JOptionPane.showMessageDialog(this,
                    (updated ? "Updated probe \"" : "Saved probe \"") + p.getName() + "\".",
                    NSAppUtil.ProbeEditor.SAVED_DIALOG.getDisplayName(), JOptionPane.INFORMATION_MESSAGE);
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
            JOptionPane.showMessageDialog(this, e.getMessage(), NSAppUtil.ScanPage.SEND_TO_CHAT_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            return;
        }
        ctx.nav().show(NSAppUtil.Screen.CHAT);
    }
}
