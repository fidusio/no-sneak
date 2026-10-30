package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.ai.model.AICapture;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

/**
 * The Capture page (re-laid out 2026-10-26 in the house list look, after Chat History): a
 * {@link PagePanel} head with the two actions (Define area, the primary Capture (N)), and two
 * columns — the session's capture areas on the left ({@link CaptureAreaModel}, the name edited
 * in place) and the stored captures on the right ({@link CaptureTableModel}, thumbnails, newest
 * first), each a toolbar over a card. Opening a capture replaces the page with a preview page
 * (Back, Send to chat).
 */
public class CapturePanel extends JPanel {

    private record LoadedCaptures(List<AICapture> rows, Map<String, ImageIcon> icons) {
    }

    private static final int THUMB_WIDTH = 72;
    private static final int THUMB_HEIGHT = 54;

    private final AssistantContext ctx;
    private final CardStack pageCards = new CardStack();
    private final JPanel previewHost = new JPanel(new BorderLayout());

    private final CaptureAreaModel areaModel = new CaptureAreaModel();
    private final JTable areaTable = new JTable(areaModel);
    private final JLabel areaNote = new JLabel();

    private final CaptureTableModel captureModel = new CaptureTableModel();
    private final JTable captureTable = new JTable(captureModel);
    private final TableRowSorter<CaptureTableModel> captureSorter = new TableRowSorter<>(captureModel);
    private final JLabel captureNote = new JLabel();

    private JButton defineAreaButton;
    /** Component name of the <i>Hide window</i> box beside Capture (N). */
    public static final String HIDE_WINDOW = "hide-window";

    private JButton captureButton;
    private JCheckBox hideWindowBox;
    private JButton sendButton;
    private JButton deleteAllButton;

    private Consumer<AICapture> onSendToChat;

    public CapturePanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        pageCards.add(buildPage(), "page");
        pageCards.add(previewHost, "preview");
        pageCards.show("page");
        add(pageCards.view(), BorderLayout.CENTER);
        refreshAreas();
        updateCaptureNote();
    }

    public void setOnSendToChat(Consumer<AICapture> onSendToChat) {
        this.onSendToChat = onSendToChat;
        sendButton.setVisible(onSendToChat != null);
    }

    private JPanel buildPage() {
        PagePanel page = new PagePanel(AssistantPanel.Page.CAPTURE.getDisplayName(),
                "Draw areas on the screen and shoot them all at once. Areas last the session; captures are kept under your account.");

        defineAreaButton = new JButton("Define area", new IconUtil.AreaIcon(16));
        defineAreaButton.setToolTipText("Drag out a region of the screen as a reusable capture area");
        defineAreaButton.addActionListener(_ -> onDefineArea());
        captureButton = UITokens.primary(new JButton("Capture (0)", IconUtil.svgIcon("io/xlogistx/gui/icons/camera.svg", 14, Color.WHITE)));
        captureButton.setToolTipText("Capture an image of every area");
        captureButton.setEnabled(false);
        captureButton.addActionListener(_ -> onCapture());
        hideWindowBox = new JCheckBox("Hide window", ctx.isHideWindowOnCapture());
        hideWindowBox.setOpaque(false);
        hideWindowBox.setName(HIDE_WINDOW);
        hideWindowBox.setToolTipText("Hide this window while an area is drawn or shot; untick to draw over and capture the application itself");
        hideWindowBox.addActionListener(_ -> ctx.setHideWindowOnCapture(hideWindowBox.isSelected()));
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(defineAreaButton);
        actions.add(captureButton);
        actions.add(hideWindowBox);
        page.action(actions);

        // preferred widths are zeroed so the two columns split the page 38/62 whatever their toolbars want
        JPanel columns = new JPanel(new MigLayout("insets 0, gapx 20, fill", "[grow 38,fill][grow 62,fill]", "[grow,fill]"));
        columns.setOpaque(false);
        columns.add(buildAreasColumn(), "w 0:0:, hmin 0, growy");
        columns.add(buildCapturesColumn(), "w 0:0:, hmin 0, growy");
        page.add(columns, "grow, push");
        return page;
    }

    /** The session's capture areas: Rename / Redraw / Remove on the selected row, the name edited in place. */
    private JPanel buildAreasColumn() {
        JButton rename = toolButton("Rename", new IconUtil.EditIcon(16));
        JButton redraw = toolButton("Redraw", new IconUtil.AreaIcon(16));
        redraw.setToolTipText("Drag the region again, keeping the name");
        JButton remove = toolButton("Remove", new IconUtil.DeleteIcon(16));
        remove.setForeground(UITokens.danger());

        Tables.style(areaTable);
        Tables.width(areaTable, CaptureAreaModel.COL_NAME, 150);
        Tables.width(areaTable, CaptureAreaModel.COL_DISPLAY, 120);
        Tables.width(areaTable, CaptureAreaModel.COL_REGION, 170);
        areaTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        areaTable.getSelectionModel().addListSelectionListener(_ -> {
            boolean one = areaTable.getSelectedRowCount() == 1;
            rename.setEnabled(one);
            redraw.setEnabled(one);
            remove.setEnabled(one);
        });
        rename.addActionListener(_ -> editAreaName(selectedArea()));
        redraw.addActionListener(_ -> onRedrawArea(selectedArea()));
        remove.addActionListener(_ -> onRemoveArea(selectedArea()));

        return column("Areas", areaNote, new JButton[]{rename, redraw, remove}, areaTable);
    }

    /** The stored captures: thumbnails, newest first; Open / Send to chat / Rename / Delete on the row, Delete all. */
    private JPanel buildCapturesColumn() {
        JButton open = toolButton("Open", new IconUtil.VisibleIcon(16));
        sendButton = toolButton("Send to chat", new IconUtil.NextIcon(16));
        sendButton.setVisible(false);
        JButton rename = toolButton("Rename", new IconUtil.EditIcon(16));
        JButton delete = toolButton("Delete", new IconUtil.DeleteIcon(16));
        delete.setForeground(UITokens.danger());
        deleteAllButton = toolButton("Delete all", new IconUtil.DeleteIcon(16));
        deleteAllButton.setToolTipText("Delete every saved capture");
        deleteAllButton.setForeground(UITokens.danger());

        Tables.style(captureTable);
        captureTable.setRowHeight(THUMB_HEIGHT + 8);
        TableColumn thumb = captureTable.getColumnModel().getColumn(CaptureTableModel.COL_THUMB);
        thumb.setMinWidth(THUMB_WIDTH + 12);
        thumb.setMaxWidth(THUMB_WIDTH + 12);
        thumb.setCellRenderer(new ThumbnailRenderer());
        Tables.width(captureTable, CaptureTableModel.COL_NAME, 200);
        Tables.width(captureTable, CaptureTableModel.COL_AREA, 100);
        Tables.width(captureTable, CaptureTableModel.COL_SIZE, 80);
        Tables.width(captureTable, CaptureTableModel.COL_BYTES, 70);
        Tables.width(captureTable, CaptureTableModel.COL_TAKEN, 130);
        captureTable.getColumnModel().getColumn(CaptureTableModel.COL_TAKEN).setMinWidth(120); // the stamp never truncates; the name gives way
        captureTable.getColumnModel().getColumn(CaptureTableModel.COL_BYTES).setCellRenderer(new MutedRenderer(true));
        captureTable.getColumnModel().getColumn(CaptureTableModel.COL_TAKEN).setCellRenderer(new MutedRenderer(false));
        captureTable.setRowSorter(captureSorter);
        captureSorter.setSortable(CaptureTableModel.COL_THUMB, false);
        captureSorter.setSortKeys(List.of(new RowSorter.SortKey(CaptureTableModel.COL_TAKEN, SortOrder.DESCENDING)));
        captureTable.getSelectionModel().addListSelectionListener(_ -> {
            boolean one = captureTable.getSelectedRowCount() == 1;
            open.setEnabled(one);
            sendButton.setEnabled(one);
            rename.setEnabled(one);
            delete.setEnabled(one);
        });
        captureTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) onViewCapture(selectedCapture());
            }
        });
        open.addActionListener(_ -> onViewCapture(selectedCapture()));
        sendButton.addActionListener(_ -> onSendToChat(selectedCapture()));
        rename.addActionListener(_ -> onRenameCapture(selectedCapture()));
        delete.addActionListener(_ -> onRemoveCapture(selectedCapture()));
        deleteAllButton.addActionListener(_ -> onDeleteAllCaptures());

        return column("Captures", captureNote, new JButton[]{open, sendButton, rename, delete, deleteAllButton}, captureTable);
    }

    private static JButton toolButton(String text, Icon icon) {
        JButton b = new JButton(text, icon);
        b.putClientProperty("JButton.buttonType", "toolBarButton");
        b.setEnabled(false);
        return b;
    }

    /** One column of the page: a toolbar (title, muted note, the buttons at the right) over a white card holding the table. */
    private static JPanel column(String title, JLabel note, JButton[] buttons, JTable table) {
        StringBuilder cols = new StringBuilder("[][grow]push");
        for (int i = 0; i < buttons.length; i++) cols.append("[]");
        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", cols.toString()));
        bar.setOpaque(false);
        JLabel t = new JLabel(title);
        t.setFont(UITokens.font(Font.BOLD, 1f));
        bar.add(t);
        note.setForeground(UITokens.muted());
        note.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(note, "wmin 0");
        for (JButton b : buttons) bar.add(b);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(UITokens.surface());
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(UITokens.surface());
        card.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        card.add(scroll, BorderLayout.CENTER);

        JPanel col = new JPanel(new MigLayout("insets 0, wrap 1, gapy 10, fill", "[grow,fill]", "[][grow,fill]"));
        col.setOpaque(false);
        col.add(bar, "growx, wmin 0");
        col.add(card, "grow, push, wmin 0, hmin 0");
        return col;
    }

    /** The thumbnail column: the row's scaled jpeg, or the camera glyph when the capture has none. */
    private static final class ThumbnailRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setText("");
            setIcon(value instanceof Icon i ? i : new IconUtil.CameraIcon(24));
            setHorizontalAlignment(SwingConstants.CENTER);
            return this;
        }
    }

    /** Bytes ({@code 412 KB}) or a {@code yyyy-MM-dd HH:mm} stamp, muted like the scan history's. */
    private static final class MutedRenderer extends DefaultTableCellRenderer {
        private final boolean bytes;

        MutedRenderer(boolean bytes) {
            this.bytes = bytes;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (bytes) setText(value instanceof Integer n ? CaptureSupport.bytes(n) : "");
            else setText(value instanceof Long l ? timestamp(l) : "");
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
    }

    private CaptureArea selectedArea() {
        int row = areaTable.getSelectedRow();
        return row < 0 ? null : areaModel.rowAt(areaTable.convertRowIndexToModel(row));
    }

    private AICapture selectedCapture() {
        int row = captureTable.getSelectedRow();
        return row < 0 ? null : captureModel.rowAt(captureTable.convertRowIndexToModel(row));
    }

    public void refreshAreas() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshAreas);
            return;
        }
        if (areaTable.isEditing()) areaTable.getCellEditor().stopCellEditing();
        CaptureArea keep = selectedArea();
        areaModel.setRows(ctx.getCaptureAreaSet().getCaptureAreas());
        selectArea(keep);
        int count = areaModel.getRowCount();
        areaNote.setText(count == 0 ? "No areas yet" : count + (count == 1 ? " area" : " areas"));
        captureButton.setText("Capture (" + count + ")");
        captureButton.setEnabled(count > 0);
    }

    private void selectArea(CaptureArea area) {
        int model = area == null ? -1 : areaModel.indexOf(area);
        if (model < 0) return;
        int view = areaTable.convertRowIndexToView(model);
        areaTable.setRowSelectionInterval(view, view);
    }

    /** Starts the in-place editor on the area's name with the text selected (Define area lands here). */
    private void editAreaName(CaptureArea area) {
        if (area == null) return;
        selectArea(area);
        int view = areaTable.getSelectedRow();
        if (view < 0 || !areaTable.editCellAt(view, CaptureAreaModel.COL_NAME)) return;
        if (areaTable.getEditorComponent() instanceof JTextField field) {
            field.selectAll();
            field.requestFocusInWindow();
        }
    }

    /**
     * Reloads the capture rows off the EDT. The store read is projected, so these carry a thumbnail
     * but no full image.
     */
    public void refreshCaptures() {
        BackgroundTask.run(this, null, () -> {
            List<AICapture> loaded = ctx.getAllCaptures();
            Map<String, ImageIcon> icons = new HashMap<>();
            if (loaded == null) loaded = List.of();
            for (AICapture capture : loaded) {
                if (capture.getGUID() == null) continue;
                try {
                    BufferedImage thumb = CaptureSupport.toImage(capture.getThumbnail());
                    if (thumb != null)
                        icons.put(capture.getGUID(),
                                CaptureSupport.scaledIcon(thumb, THUMB_WIDTH, THUMB_HEIGHT));
                } catch (Exception ignore) {
                }
            }
            return new LoadedCaptures(loaded, icons);
        }, loaded -> {
            AICapture keep = selectedCapture();
            captureModel.setRows(loaded.rows(), loaded.icons());
            int model = keep == null ? -1 : captureModel.indexOf(keep.getGUID());
            if (model >= 0) {
                int view = captureTable.convertRowIndexToView(model);
                captureTable.setRowSelectionInterval(view, view);
            }
            updateCaptureNote();
        });
    }

    private void updateCaptureNote() {
        int count = captureModel.getRowCount();
        captureNote.setText(count == 0 ? "No captures yet" : count + (count == 1 ? " capture" : " captures"));
        deleteAllButton.setEnabled(count > 0);
    }

    private void onDefineArea() {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, defineAreaButton, () -> CaptureSupport.select(ctx, window), selection -> {
            if (selection == null) return;
            CaptureArea area = new CaptureArea(
                    "Area " + (ctx.getCaptureAreaSet().getCaptureAreas().length + 1),
                    selection.display(), selection.bounds());
            ctx.getCaptureAreaSet().addCaptureAreas(area);
            showCaptures();
            refreshAreas();
            editAreaName(area);
        });
    }

    private void onRedrawArea(CaptureArea area) {
        if (area == null) return;
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, null, () -> CaptureSupport.select(ctx, window), selection -> {
            if (selection == null) return;
            area.setCaptureArea(selection.bounds());
            area.setDescription(selection.display());
            refreshAreas();
        });
    }

    private void onRemoveArea(CaptureArea area) {
        if (area == null) return;
        ctx.getCaptureAreaSet().removeCaptureAreas(area);
        refreshAreas();
    }

    private void onCapture() {
        CaptureArea[] areas = ctx.getCaptureAreaSet().getCaptureAreas();
        if (areas.length == 0) return;

        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, captureButton,
                () -> CaptureSupport.shootAndSave(ctx, window, areas), snaps -> {
            if (snaps.length < areas.length)
                JOptionPane.showMessageDialog(this,
                        (areas.length - snaps.length) + " of " + areas.length
                                + " areas could not be captured",
                        "Capture", JOptionPane.WARNING_MESSAGE);
            showCaptures();
            refreshCaptures();
        });
    }

    private void onViewCapture(AICapture capture) {
        if (capture == null || capture.getGUID() == null) return;
        BackgroundTask.run(this, null, () -> CaptureSupport.toImage(full(capture).getImage()), image -> {
            if (image == null) {
                JOptionPane.showMessageDialog(this, "That capture has no stored image.",
                        "Capture", JOptionPane.WARNING_MESSAGE);
                return;
            }
            showPreview(capture, image);
        });
    }

    /** The preview page: the capture's name and facts in the head, Back and Send to chat as its actions, the image in the card. */
    private void showPreview(AICapture capture, BufferedImage image) {
        PagePanel page = new PagePanel(CaptureTableModel.title(capture), previewFacts(capture));
        JButton back = new JButton("Back", new IconUtil.BackIcon(16));
        back.addActionListener(_ -> showCaptures());
        JButton send = UITokens.primary(new JButton("Send to chat", IconUtil.svgIcon("io/xlogistx/gui/icons/next.svg", 14, Color.WHITE)));
        send.setVisible(onSendToChat != null);
        send.addActionListener(_ -> onSendToChat(capture));
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(back);
        actions.add(send);
        page.action(actions);

        JLabel picture = new JLabel(new ImageIcon(image));
        picture.setHorizontalAlignment(SwingConstants.LEFT);
        picture.setVerticalAlignment(SwingConstants.TOP);
        picture.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        JScrollPane scroll = new JScrollPane(picture);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(UITokens.surface());
        page.card(scroll);

        previewHost.removeAll();
        previewHost.add(page, BorderLayout.CENTER);
        previewHost.revalidate();
        previewHost.repaint();
        pageCards.show("preview");
    }

    /** {@code Area 1 · 640x360 · 412 KB · taken 2026-10-26 14:02} for the preview head. */
    static String previewFacts(AICapture capture) {
        StringBuilder sb = new StringBuilder();
        if (capture.getFromArea() != null && !capture.getFromArea().isBlank())
            sb.append(capture.getFromArea()).append("  ·  ");
        sb.append(CaptureTableModel.size(capture));
        sb.append("  ·  ").append(CaptureSupport.bytes(capture.getNumBytes()));
        sb.append("  ·  taken ").append(timestamp(capture.getCreationTime()));
        return sb.toString();
    }

    private void onSendToChat(AICapture capture) {
        if (capture == null || capture.getGUID() == null) return;
        if (onSendToChat != null) onSendToChat.accept(capture);
    }

    /**
     * Renames through a fresh full read. The rows come from a projected query with no image column,
     * and an update writes every column, so saving the row instance would null the stored png.
     */
    private void onRenameCapture(AICapture capture) {
        if (capture == null || capture.getGUID() == null) return;
        String name = JOptionPane.showInputDialog(this, "Capture name", CaptureTableModel.title(capture));
        if (name == null || name.trim().isEmpty()) return;

        String trimmed = name.trim();
        BackgroundTask.run(this, null, () -> {
            AICapture stored = full(capture);
            stored.setName(trimmed);
            return ctx.saveCapture(stored);
        }, _ -> refreshCaptures());
    }

    private void onRemoveCapture(AICapture capture) {
        if (capture == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(CaptureTableModel.title(capture), "capture"),
                "Delete capture", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, null, () -> ctx.deleteCapture(capture), this::refreshCaptures);
    }

    private void onDeleteAllCaptures() {
        List<AICapture> doomed = captureModel.rows();
        if (doomed.isEmpty()) return;
        int count = doomed.size();
        int res = JOptionPane.showConfirmDialog(this,
                "Delete all " + count + " capture" + (count == 1 ? "" : "s")
                        + "? This permanently removes them.",
                "Delete all captures", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, deleteAllButton, () -> {
            for (AICapture capture : doomed) ctx.deleteCapture(capture);
        }, () -> {
            showCaptures();
            refreshCaptures();
        });
    }

    private AICapture full(AICapture projected) {
        AICapture stored = ctx.getCapture(projected.getGUID());
        return (stored != null) ? stored : projected;
    }

    /** Closes a preview: the page with both columns comes back. */
    private void showCaptures() {
        previewHost.removeAll();
        pageCards.show("page");
    }

    public void reset() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::reset);
            return;
        }
        captureModel.setRows(null, null);
        updateCaptureNote();
        refreshAreas();
        showCaptures();
    }
}
