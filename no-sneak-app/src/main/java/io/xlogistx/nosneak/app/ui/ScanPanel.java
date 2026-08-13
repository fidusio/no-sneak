package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.v2.data.ProbeContent;
import io.xlogistx.nosneak.v2.data.ReportContent;
import io.xlogistx.nosneak.v2.nmap.NMapConfig;
import io.xlogistx.nosneak.v2.nmap.NMapScanner;
import io.xlogistx.nosneak.v2.nmap.ScanReport;
import io.xlogistx.nosneak.v2.nmap.output.OutputFormat;
import org.zoxweb.shared.task.CallableConsumerTask;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static io.xlogistx.nosneak.v2.nmap.NMap.DEFAULT_PORTS;

public class ScanPanel extends JPanel {
    private final CardStack cardStack = new CardStack();
    private final AppContext ctx;

    private ListSection<ReportContent> resultList;
    private ListSection<ProbeContent> probeList;
    private final JTextField commandText = new JTextField(30);
    private final JTextArea resultText = new JTextArea();
    private ReportContent selectedScan;
    private ProbeContent selectedProbe;

    private JTextArea viewScanTextArea;
    private JTextArea viewProbeTextArea;

    public ScanPanel(AppContext ctx) {
        this.ctx = ctx;

        ctx.session().onAuthChange(e -> {
            resultList.refresh();
            probeList.refresh();
        });

        setLayout(new BorderLayout());
        cardStack.add(buildScanPanel(), "Scan");
        cardStack.add(buildProbePanel(), "Probe");
        cardStack.add(buildResultPanel(), "Result");
        cardStack.add(buildViewScanResult(), "View_scan");
        cardStack.add(buildEditProbe(), "Edit_probe");

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
        JButton help = new JButton(new IconUtil.VisibleIcon(16));
        help.setToolTipText("Usage");
        help.addActionListener(e -> showUsage());

        JButton run = new JButton("Run");
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(help);
        actions.add(run);

        top.add(new JLabel("Command"), BorderLayout.NORTH);
        top.add(commandText, BorderLayout.CENTER);
        top.add(actions, BorderLayout.EAST);
        top.setBorder(BorderFactory.createEmptyBorder(10, 12,10, 12));

        JSplitPane split = PanelBuilder.buildHorizontalSplitView(buildProbeSelector(), new JScrollPane(resultText), 320, 0);

        out.add(top, BorderLayout.NORTH);
        out.add(split, BorderLayout.CENTER);


        run.addActionListener(_ -> BackgroundTask.run(this, run, () -> scanNetwork(commandText.getText()), json -> {
            resultText.setText(json);
            resultText.setCaretPosition(0);
            ReportContent r = new ReportContent();
            r.setName("placeholder" + " " + Instant.now());
            r.setContent(json);
            r.getProperties().build("command", commandText.getText());
            ctx.session().saveScanResult(r);
            resultList.refresh();
        }));

        return out;
    }

    private JPanel buildProbeSelector() {
        return  new JPanel();
    }

    private JPopupMenu showUsage() {
        return new JPopupMenu();
    }

    private JPanel buildProbePanel() {
        probeList = ListSection.of(() -> ctx.session().getAllProbes())
                .title("Probe List")
                .label(ProbeContent::getName)
                .addButton("+ Add Probe", null)
                .onEdit(p -> () -> onEditProbe(p))
                .onRemove(p -> () -> onRemoveProbe(p))
                .emptyText("No probes yet")
                .scrollable()
                .search()
                .build();

        return probeList;
    }

    private JPanel buildResultPanel() {
        resultList = ListSection.of(() -> ctx.session().getAllScanResults())
                .title("Scan Results")
                .label(ReportContent::getName)
                .sublabel(scan -> SUS.trimOrNull(String.valueOf(scan.getCreationTime())))
                .action(new ListSection.RowAction<>(new IconUtil.VisibleIcon(16), "View", s -> () -> onViewScanResult(s)))
                .onRemove(s -> () -> onRemoveScanResult(s))
                .emptyText("No scans yet")
                .scrollable()
                .build();

        return resultList;
    }

    private void onViewScanResult(ReportContent selectedScan) {
        if (selectedScan == null) return;
        this.selectedScan = selectedScan;
        viewScanTextArea.setText(selectedScan.getContent());
        viewScanTextArea.setCaretPosition(0);
        cardStack.show("View_scan");
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
            JButton sendToChat = new JButton("Send to chat");
            content.add(copy, "gapbottom 6");
            content.add(sendToChat, "gapbottom 6");

            body.add(new JScrollPane(viewScanTextArea), BorderLayout.CENTER);

            content.add(body, "grow, push");
        });
    }

    private void onRemoveScanResult(ReportContent reportContent) {
        ctx.session().deleteScanResult(reportContent);
        resultList.refresh();
    }

    private void onEditProbe(ProbeContent probeContent) {
        if(probeContent == null) return;
        this.selectedProbe = probeContent;
        viewProbeTextArea.setText(probeContent.getContent());
        viewProbeTextArea.setCaretPosition(0);
        cardStack.show("Edit_probe");
    }

    private JPanel buildEditProbe() {
        viewProbeTextArea = new JTextArea();
        viewProbeTextArea.setEditable(true);
        viewProbeTextArea.setLineWrap(true);
        viewProbeTextArea.setWrapStyleWord(true);

        return PanelBuilder.detail("Edit Probe", () -> cardStack.show("Probe"), content -> {
    //stub
        });
    }

    private void onRemoveProbe(ProbeContent probeContent) {
        ctx.session().deleteProbe(probeContent);
        probeList.refresh();
    }

    public String scanNetwork(String command) {
        String content = "";
        try {
            NMapConfig cfg = new NMapConfig();
            cfg.target(command);
            CompletableFuture<ScanReport> future = new CompletableFuture<>();
            NMapScanner.scan(ctx.session().getNio(), cfg,
                    new CallableConsumerTask<ScanReport>().setConsumer(future::complete));
            ScanReport report = future.get(maxWaitMs(cfg), TimeUnit.MILLISECONDS);

            content = OutputFormat.formatter(OutputFormat.JSON).render(report);

        } catch (Exception e) {
            System.err.println("Error: " + e);
        }

        return content;
    }

    private static long maxWaitMs(NMapConfig cfg) {
        int hosts = Math.max(1, NMapScanner.expand(cfg.targets).size());
        int ports = (cfg.ports != null ? cfg.ports.length : DEFAULT_PORTS.length)
                + NMapScanner.DEFAULT_DISCOVERY_PORTS.length + 1;
        long units = (long) hosts * ports * (cfg.probeScan ? 2 : 1);
        long par = cfg.maxInFlight > 0 ? cfg.maxInFlight : 64;
        long waves = units / par + 1;
        long byPar = waves * (cfg.timeoutSec + 2L) * 1000L + 30000L;
        long byRate = cfg.maxPerSec > 0
                ? (units / cfg.maxPerSec) * 1000L + (cfg.timeoutSec + 2L) * 2000L : 0;
        return Math.max(byPar, byRate);
    }
}
