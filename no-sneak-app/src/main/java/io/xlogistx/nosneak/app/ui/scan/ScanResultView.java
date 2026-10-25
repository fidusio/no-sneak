package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.gui.BadgeLabel;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.KeyValuePanel;
import io.xlogistx.gui.Tables;
import io.xlogistx.gui.UITokens;
import io.xlogistx.gui.WrapLabel;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * A scan result as tables (board 2 of the redesign canvas, 2026-10-24): a header with the
 * scan's name, command, duration and the four counts, then <b>Hosts</b> (a table with a detail
 * pane for the selected host: its ports, the TLS posture of its worst-graded endpoint, and the
 * engine's verdict), <b>Services</b> (every open port flat) and <b>Raw JSON</b> (the report as the
 * engine rendered it, which is what Copy and Send carry). One instance shows a fresh run on the
 * scanner page, another a stored report opened from history.
 */
public class ScanResultView extends JPanel {

    private static final String EMPTY = "empty";
    private static final String CONTENT = "content";

    private final CardLayout cards = new CardLayout();
    private final JLabel title = new JLabel();
    private final JLabel meta = new JLabel();
    private final BadgeLabel state = new BadgeLabel("", BadgeLabel.Tone.NEUTRAL);
    private final JLabel counts = new JLabel();
    private final JButton copy = new JButton(new IconUtil.CopyIcon(16));
    private final JButton send = new JButton("Send to assistant", IconUtil.svgIcon("io/xlogistx/gui/icons/chat.svg", 16, UITokens.text()));
    /** Shown only once {@link #onRerun} gives it something to do (a stored report). */
    private final JButton rerun = new JButton("Scan again", IconUtil.svgIcon("io/xlogistx/gui/icons/refresh.svg", 16, UITokens.text()));
    private final HostsModel hostsModel = new HostsModel();
    private final ServicesModel servicesModel = new ServicesModel();
    private final JTable hosts = Tables.style(new JTable(hostsModel));
    private final JTable services = Tables.style(new JTable(servicesModel));
    private final JTextArea raw = new JTextArea();
    private final JPanel detail = new JPanel(new MigLayout("insets 16 20 20 20, wrap 1, gapy 14, fillx, hidemode 3", "[grow,fill]"));
    private final JLabel emptyLabel = new JLabel("Run a scan to see its hosts, services and raw report here.");

    private String json;
    private String name;
    private ReportView.Report report;

    /**
     * @param onCopy receives the raw JSON when Copy is pressed
     * @param onSend receives (json, name) when Send to assistant is pressed
     */
    public ScanResultView(Consumer<String> onCopy, BiConsumer<String, String> onSend) {
        super(null);
        setLayout(cards);
        setBackground(UITokens.surface());
        setBorder(BorderFactory.createLineBorder(UITokens.border()));

        emptyLabel.setForeground(UITokens.muted());
        emptyLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(emptyLabel, EMPTY);

        JPanel content = new JPanel(new BorderLayout());
        content.setOpaque(false);

        // header
        // the command text is the one thing that gives way when the window is narrow (wmin 0 +
        // JLabel's own ellipsis); everything else keeps its width
        JPanel head = new JPanel(new MigLayout("insets 14 20 8 20, gapx 12, fillx", "[][grow,fill][]push[][][][]"));
        head.setOpaque(false);
        title.setFont(UITokens.font(Font.BOLD, 3f));
        meta.setFont(UITokens.mono(-1f));
        meta.setForeground(UITokens.muted());
        counts.setFont(UITokens.font(Font.PLAIN, -0.5f));
        head.add(title);
        head.add(meta, "wmin 0, growx");
        head.add(state);
        head.add(counts, "gapright 8");
        copy.setToolTipText("Copy the raw report to the clipboard");
        copy.addActionListener(_ -> {
            if (json != null) onCopy.accept(json);
        });
        send.addActionListener(_ -> {
            if (json != null) onSend.accept(json, name);
        });
        rerun.setVisible(false);
        rerun.setToolTipText("Load this scan's command, probes and name into New scan");
        head.add(rerun);
        head.add(copy);
        head.add(send);
        content.add(head, BorderLayout.NORTH);

        // tabs
        JTabbedPane tabs = new JTabbedPane();
        tabs.putClientProperty("JTabbedPane.tabAreaInsets", new Insets(0, 12, 0, 12));
        tabs.putClientProperty("JTabbedPane.showContentSeparator", true);

        hosts.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showHost(selectedHost());
        });
        hosts.getColumnModel().getColumn(5).setCellRenderer(new PostureRenderer());
        Tables.width(hosts, 0, 220);
        Tables.width(hosts, 1, 70);
        Tables.width(hosts, 2, 60);
        Tables.width(hosts, 3, 220);
        Tables.width(hosts, 4, 180);
        Tables.width(hosts, 5, 150);
        JScrollPane hostsScroll = new JScrollPane(hosts);
        hostsScroll.setBorder(BorderFactory.createEmptyBorder());
        detail.setBackground(UITokens.surfaceAlt());
        JScrollPane detailScroll = new JScrollPane(detail, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        detailScroll.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, UITokens.border()));
        detailScroll.getVerticalScrollBar().setUnitIncrement(16);
        // a split pane's minimum is the sum of its halves'; without this the hosts table and the
        // detail pane push the whole card past the window's edge
        hostsScroll.setMinimumSize(new Dimension(0, 0));
        detailScroll.setMinimumSize(new Dimension(0, 0));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, hostsScroll, detailScroll);
        split.setResizeWeight(0.62);
        split.setBorder(BorderFactory.createEmptyBorder());
        split.setDividerSize(6);
        split.setMinimumSize(new Dimension(0, 0));
        tabs.addTab("Hosts", split);

        Tables.width(services, 0, 160);
        Tables.width(services, 1, 90);
        Tables.width(services, 2, 140);
        Tables.width(services, 3, 300);
        Tables.width(services, 4, 200);
        JScrollPane servicesScroll = new JScrollPane(services);
        servicesScroll.setBorder(BorderFactory.createEmptyBorder());
        tabs.addTab("Services", servicesScroll);

        raw.setEditable(false);
        raw.setFont(UITokens.mono(-1f));
        raw.setMargin(new Insets(12, 16, 12, 16));
        JScrollPane rawScroll = new JScrollPane(raw);
        rawScroll.setBorder(BorderFactory.createEmptyBorder());
        rawScroll.setMinimumSize(new Dimension(0, 0));
        servicesScroll.setMinimumSize(new Dimension(0, 0));
        tabs.addTab("Raw JSON", rawScroll);
        tabs.setMinimumSize(new Dimension(0, 0));

        content.add(tabs, BorderLayout.CENTER);
        add(content, CONTENT);
        cards.show(this, EMPTY);
    }

    // ---- API ----

    /**
     * Shows a report.
     *
     * @param name    the scan's name (the history row label, the attachment label)
     * @param json    the raw report, exactly as rendered; what Copy and Send carry
     * @param stopped when not null, the scan was stopped and this is why; nothing was saved
     * @param saved   whether the report is in the store (a fresh run is marked once its save lands)
     */
    public void setReport(String name, String json, String stopped, boolean saved) {
        this.name = name;
        this.json = json;
        ReportView.Report parsed = null;
        try {
            parsed = ReportView.parse(json);
        } catch (IllegalArgumentException ignore) {
            // the raw tab still shows it
        }
        this.report = parsed;
        title.setText(name != null && !name.isBlank() ? name : "Result");
        if (parsed != null) {
            String when = parsed.startTime() != null ? parsed.startTime().replace('T', ' ').replaceAll("(\\.\\d+)?Z$", "") : "";
            meta.setText((parsed.command() != null ? parsed.command() : "") + (when.isEmpty() ? "" : "  ·  " + when) + "  ·  " + parsed.durationLabel());
            counts.setText(parsed.upHosts().size() + " hosts up · " + parsed.openPortCount() + " open ports · "
                    + parsed.tlsEndpointCount() + " TLS endpoints · " + parsed.pqcReadyCount() + " PQC ready");
        } else {
            meta.setText("");
            counts.setText("");
        }
        if (stopped != null) {
            state.setText("stopped · not saved");
            state.setTone(BadgeLabel.Tone.WARN);
            state.setToolTipText(stopped);
        } else {
            markSaved(saved);
        }
        send.setEnabled(stopped == null);
        hostsModel.setHosts(parsed != null ? parsed.hosts() : List.of());
        servicesModel.setHosts(parsed != null ? parsed.hosts() : List.of());
        raw.setText(json != null ? json : "");
        raw.setCaretPosition(0);
        if (hostsModel.getRowCount() > 0) hosts.setRowSelectionInterval(0, 0);
        else showHost(null);
        cards.show(this, CONTENT);
    }

    /** Flips the state badge once the report's save has landed (or not). */
    public void markSaved(boolean saved) {
        state.setText(saved ? "saved to history" : "not saved");
        state.setTone(saved ? BadgeLabel.Tone.OK : BadgeLabel.Tone.NEUTRAL);
        state.setToolTipText(null);
    }

    /** Back to the empty state; nothing of the previous report remains. */
    public void clear() {
        json = null;
        name = null;
        report = null;
        hostsModel.setHosts(List.of());
        servicesModel.setHosts(List.of());
        raw.setText("");
        showHost(null);
        cards.show(this, EMPTY);
    }

    public boolean hasReport() {
        return json != null;
    }

    /**
     * Gives the header a <b>Scan again</b> button that runs {@code action} (2026-10-25, asked for
     * by the maintainer while viewing a stored report: the saved command, probes and name go back
     * into the New scan form so the same scan can be run again). Null removes the button.
     */
    public void onRerun(Runnable action) {
        for (java.awt.event.ActionListener l : rerun.getActionListeners()) rerun.removeActionListener(l);
        rerun.setVisible(action != null);
        if (action != null) rerun.addActionListener(_ -> action.run());
    }

    public String getJson() {
        return json;
    }

    // ---- detail pane ----

    private ReportView.Host selectedHost() {
        int row = hosts.getSelectedRow();
        if (row < 0) return null;
        return hostsModel.at(hosts.convertRowIndexToModel(row));
    }

    private void showHost(ReportView.Host h) {
        detail.removeAll();
        if (h != null) {
            JLabel addr = new JLabel(h.address());
            addr.setFont(UITokens.mono(3f));
            addr.setFont(addr.getFont().deriveFont(Font.BOLD));
            detail.add(addr);
            String sub = (h.hostname() != null ? h.hostname() + " · " : "") + h.openPorts().size() + " open ports"
                    + (h.mac() != null ? " · " + h.mac() : "") + (h.latencyMs() >= 0 ? " · " + h.latencyMs() + " ms" : "");
            JLabel subLabel = new JLabel(sub);
            subLabel.setForeground(UITokens.muted());
            detail.add(subLabel, "gaptop -8");

            // ports
            detail.add(section("Ports"));
            PortsModel pm = new PortsModel(h.openPorts());
            JTable ports = Tables.style(new JTable(pm));
            ports.setRowHeight(28);
            ports.setAutoCreateRowSorter(false);
            Tables.width(ports, 0, 80);
            Tables.width(ports, 1, 100);
            Tables.width(ports, 2, 200);
            JPanel portsBox = new JPanel(new BorderLayout());
            portsBox.setOpaque(false);
            portsBox.add(ports.getTableHeader(), BorderLayout.NORTH);
            portsBox.add(ports, BorderLayout.CENTER);
            detail.add(portsBox, "growx");

            // TLS posture
            ReportView.Port tls = h.worstTlsPort();
            if (tls != null) {
                detail.add(section("TLS posture · " + tls.portLabel()));
                KeyValuePanel kv = new KeyValuePanel(110);
                kv.putMono("Protocol", tls.tlsVersion() != null ? tls.tlsVersion() : tls.tls());
                kv.putMono("Key exchange", tls.kexGroup() != null ? tls.kexGroup() : tls.kexAlgorithm());
                kv.putMono("Cipher", tls.cipherSuite());
                kv.put("Certificate", cert(tls));
                kv.put("Chain", chain(tls));
                if (!tls.supportedGroups().isEmpty()) kv.putMono("Groups offered", String.join(", ", tls.supportedGroups()));
                if (!tls.supportedProtocols().isEmpty()) kv.putMono("Versions", String.join(", ", tls.supportedProtocols()));
                detail.add(kv, "growx");

                ReportView.Posture posture = h.posture();
                JPanel verdict = new JPanel(new MigLayout("insets 10 12 10 12, gapx 10", "[]0[grow,fill]"));
                verdict.setBackground(UITokens.surface());
                verdict.add(new BadgeLabel(posture.label(), tone(posture.tone())), "aligny top");
                WrapLabel text = new WrapLabel(verdict(tls));
                text.setFont(UITokens.font(Font.PLAIN, -0.5f));
                verdict.add(text, "growx, wmin 0");
                detail.add(verdict, "growx");
            } else {
                JLabel none = new JLabel("No TLS endpoint answered on this host, so there is no posture to grade.");
                none.setForeground(UITokens.muted());
                detail.add(none);
            }
        }
        detail.revalidate();
        detail.repaint();
    }

    private static String cert(ReportView.Port p) {
        StringBuilder sb = new StringBuilder();
        if (p.certSubject() != null) sb.append(p.certSubject());
        if (p.certIssuer() != null) sb.append(sb.isEmpty() ? "" : " · ").append("issued by ").append(p.certIssuer());
        if (p.certNotAfter() != null) sb.append(sb.isEmpty() ? "" : " · ").append("expires ").append(p.certNotAfter().replaceAll("T.*$", ""));
        if (p.certValidity() != null) sb.append(sb.isEmpty() ? "" : " · ").append(p.certValidity().toLowerCase());
        return sb.toString();
    }

    private static String chain(ReportView.Port p) {
        StringBuilder sb = new StringBuilder();
        if (p.certChainTrust() != null) sb.append(p.certChainTrust().replace('_', ' ').toLowerCase());
        if (p.chainMessage() != null) sb.append(sb.isEmpty() ? "" : " · ").append(p.chainMessage());
        return sb.toString();
    }

    /** The engine's verdict in words: PQC status, trust, then its advisories. */
    static String verdict(ReportView.Port p) {
        StringBuilder sb = new StringBuilder();
        String pqc = p.pqc() != null ? p.pqc().toUpperCase() : "";
        if (pqc.startsWith("PQC")) sb.append("Negotiates a hybrid post-quantum key exchange.");
        else if (pqc.equals("CLASSICAL")) sb.append("TLS 1.3 with a classical key exchange: the server could offer a hybrid group, it does not.");
        else if (pqc.equals("NOT_READY")) sb.append("TLS 1.2 or older: no post-quantum key exchange is possible on this version.");
        if (p.trust() != null && !"TRUSTED".equals(p.trust()) && !"UNKNOWN".equals(p.trust())) {
            sb.append(sb.isEmpty() ? "" : " ").append("Certificate: ").append(p.trust().replace('_', ' ').toLowerCase()).append('.');
        }
        for (String a : p.advisories()) sb.append(sb.isEmpty() ? "" : " ").append(a).append(a.endsWith(".") ? "" : ".");
        return sb.isEmpty() ? "No further notes." : sb.toString();
    }

    private static JLabel section(String text) {
        JLabel l = new JLabel(text);
        l.setFont(UITokens.font(Font.BOLD, -1f));
        return l;
    }

    static BadgeLabel.Tone tone(ReportView.Tone t) {
        return switch (t) {
            case OK -> BadgeLabel.Tone.OK;
            case WARN -> BadgeLabel.Tone.WARN;
            case DANGER -> BadgeLabel.Tone.DANGER;
            case NEUTRAL -> BadgeLabel.Tone.NEUTRAL;
        };
    }

    // ---- models ----

    private static final class HostsModel extends AbstractTableModel {
        private static final String[] COLS = {"Host", "Status", "Open", "Services", "TLS", "PQC readiness"};
        private List<ReportView.Host> rows = List.of();

        void setHosts(List<ReportView.Host> hosts) {
            rows = hosts;
            fireTableDataChanged();
        }

        ReportView.Host at(int row) {
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
            ReportView.Host h = rows.get(r);
            return switch (c) {
                case 0 -> h.hostname() != null ? h.address() + "  " + h.hostname() : h.address();
                case 1 -> h.up() ? "up" : "down";
                case 2 -> h.openPorts().size();
                case 3 -> h.serviceList();
                case 4 -> {
                    ReportView.Port t = h.worstTlsPort();
                    yield t != null ? t.tlsSummary() : "";
                }
                default -> h.posture();
            };
        }

        public Class<?> getColumnClass(int c) {
            return c == 2 ? Integer.class : c == 5 ? ReportView.Posture.class : String.class;
        }
    }

    private static final class ServicesModel extends AbstractTableModel {
        private static final String[] COLS = {"Host", "Port", "Service", "Version · probe", "TLS"};
        private record Row(ReportView.Host host, ReportView.Port port) {
        }

        private List<Row> rows = List.of();

        void setHosts(List<ReportView.Host> hosts) {
            List<Row> out = new java.util.ArrayList<>();
            for (ReportView.Host h : hosts) for (ReportView.Port p : h.openPorts()) out.add(new Row(h, p));
            rows = out;
            fireTableDataChanged();
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
            Row row = rows.get(r);
            return switch (c) {
                case 0 -> row.host.address();
                case 1 -> row.port.portLabel();
                case 2 -> row.port.service() != null ? row.port.service() : "";
                case 3 -> row.port.detail();
                default -> row.port.tlsSummary();
            };
        }
    }

    private static final class PortsModel extends AbstractTableModel {
        private static final String[] COLS = {"Port", "Service", "Version · probe"};
        private final List<ReportView.Port> rows;

        PortsModel(List<ReportView.Port> rows) {
            this.rows = rows;
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
            ReportView.Port p = rows.get(r);
            return switch (c) {
                case 0 -> p.portLabel();
                case 1 -> p.service() != null ? p.service() : "";
                default -> p.detail();
            };
        }
    }

    /** The posture column: the label in its tone's colour, bold. */
    private static final class PostureRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof ReportView.Posture p) {
                setText(p.label());
                setFont(UITokens.font(Font.BOLD, -0.5f));
                if (!isSelected) {
                    setForeground(switch (p.tone()) {
                        case OK -> UITokens.ok();
                        case WARN -> UITokens.warn();
                        case DANGER -> UITokens.danger();
                        case NEUTRAL -> UITokens.neutral();
                    });
                }
            }
            return this;
        }
    }
}
