package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.AICapture;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;

public class CapturePanel extends JPanel {

    private record LoadedCaptures(List<AICapture> rows, Map<String, ImageIcon> icons) {
    }

    private static final int THUMB_WIDTH = 72;
    private static final int THUMB_HEIGHT = 54;

    private final AssistantContext ctx;
    private final List<AICapture> captures = new ArrayList<>();
    private final Map<String, ImageIcon> thumbnails = new HashMap<>();
    private final CardStack captureCards = new CardStack();

    private JButton defineAreaButton;
    private JButton captureButton;
    private JButton deleteAllButton;
    private JToggleButton areasTab;
    private JToggleButton capturesTab;
    private JPanel areasContent;
    private JPanel capturesContent;
    private JLabel previewTitle;
    private JLabel previewImage;

    private CaptureArea editingArea;
    private AICapture previewed;

    private Consumer<AICapture> onSendToChat;

    public CapturePanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildToolbar(), BorderLayout.NORTH);
        add(buildCaptureCards(), BorderLayout.CENTER);
        refreshAreas();
    }

    public void setOnSendToChat(Consumer<AICapture> onSendToChat) {
        this.onSendToChat = onSendToChat;
    }

    private JPanel buildToolbar() {
        defineAreaButton = new JButton("Define area", new IconUtil.AreaIcon(16));
        defineAreaButton.setToolTipText("Drag out a region of the screen as a reusable capture area");
        defineAreaButton.addActionListener(_ -> onDefineArea());

        captureButton = new JButton("Capture (0)", new IconUtil.CameraIcon(16));
        captureButton.setToolTipText("Capture an image of every area");
        captureButton.setEnabled(false);
        captureButton.addActionListener(_ -> onCapture());

        deleteAllButton = new JButton("Delete all", new IconUtil.DeleteIcon(16));
        deleteAllButton.setToolTipText("Delete every saved capture");
        deleteAllButton.setVisible(false);
        deleteAllButton.setEnabled(false);
        deleteAllButton.addActionListener(_ -> onDeleteAllCaptures());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(deleteAllButton);
        buttons.add(defineAreaButton);
        buttons.add(captureButton);

        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.add(PanelBuilder.title("Capture"), BorderLayout.WEST);
        titleRow.add(buttons, BorderLayout.EAST);

        areasTab = new JToggleButton("Capture area selection", true);
        areasTab.setFocusable(false);
        areasTab.addActionListener(_ -> {
            showAreas();
            refreshAreas();
        });

        capturesTab = new JToggleButton("Captures");
        capturesTab.setFocusable(false);
        capturesTab.addActionListener(_ -> {
            showCaptures();
            refreshCaptures();
        });

        ButtonGroup tabs = new ButtonGroup();
        tabs.add(areasTab);
        tabs.add(capturesTab);

        JPanel tabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        tabRow.add(areasTab);
        tabRow.add(capturesTab);

        JPanel toolbar = new JPanel(new BorderLayout(0, 8));
        toolbar.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        toolbar.add(titleRow, BorderLayout.NORTH);
        toolbar.add(tabRow, BorderLayout.SOUTH);
        return toolbar;
    }

    private JComponent buildCaptureCards() {
        areasContent = listContent();
        capturesContent = listContent();
        captureCards.add(scrollList(areasContent), "areas");
        captureCards.add(scrollList(capturesContent), "captures");
        captureCards.add(buildPreviewPanel(), "preview");
        captureCards.show("areas");
        return captureCards.view();
    }

    private JPanel buildPreviewPanel() {
        JButton back = GUIUtil.iconButton(new IconUtil.BackIcon(24), true);
        back.setToolTipText("Back");
        back.addActionListener(_ -> showCaptures());

        previewTitle = PanelBuilder.title("");
        previewTitle.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        header.add(back, BorderLayout.WEST);
        header.add(previewTitle, BorderLayout.CENTER);

        previewImage = new JLabel();
        previewImage.setHorizontalAlignment(SwingConstants.LEFT);
        previewImage.setVerticalAlignment(SwingConstants.TOP);
        previewImage.setBorder(BorderFactory.createEmptyBorder(0, 14, 14, 14));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(header, BorderLayout.NORTH);
        panel.add(new JScrollPane(previewImage), BorderLayout.CENTER);
        return panel;
    }

    public void refreshAreas() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshAreas);
            return;
        }

        areasContent.removeAll();
        CaptureArea[] areas = ctx.getCaptureAreaSet().getCaptureAreas();
        if (areas.length == 0) {
            areasContent.add(emptyLabel("No capture areas yet, use Define area to add one"));
        } else {
            boolean first = true;
            for (CaptureArea area : areas) {
                if (!first) areasContent.add(separator());
                first = false;
                areasContent.add(areaRow(area));
            }
        }
        areasContent.revalidate();
        areasContent.repaint();
        updateCaptureButton();
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
            captures.clear();
            captures.addAll(loaded.rows());
            thumbnails.clear();
            thumbnails.putAll(loaded.icons());
            rebuildCaptureRows();
        });
    }

    private void rebuildCaptureRows() {
        capturesContent.removeAll();
        if (captures.isEmpty()) {
            capturesContent.add(emptyLabel("No captures yet"));
        } else {
            boolean first = true;
            for (AICapture capture : captures) {
                if (!first) capturesContent.add(separator());
                first = false;
                capturesContent.add(captureRow(capture));
            }
        }
        capturesContent.revalidate();
        capturesContent.repaint();
        deleteAllButton.setEnabled(!captures.isEmpty());
    }

    private JPanel areaRow(CaptureArea area) {
        JComponent name;
        if (area == editingArea) {
            JTextField field = new JTextField(area.getName());
            field.selectAll();
            field.addActionListener(_ -> commitAreaName(area, field.getText()));
            field.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    commitAreaName(area, field.getText());
                }
            });
            field.getInputMap().put(KeyStroke.getKeyStroke("ESCAPE"), "cancelRename");
            field.getActionMap().put("cancelRename", new AbstractAction() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    editingArea = null;
                    refreshAreas();
                }
            });
            SwingUtilities.invokeLater(field::requestFocusInWindow);
            name = field;
        } else {
            name = new JLabel(areaLabel(area));
        }
        name.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel sub = mutedLabel(CaptureSupport.areaSublabel(area));

        JPanel text = new JPanel();
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setOpaque(false);
        text.add(name);
        text.add(sub);

        JButton rename = GUIUtil.iconButton(new IconUtil.EditIcon(16));
        rename.setToolTipText("Rename");
        rename.addActionListener(_ -> {
            editingArea = area;
            refreshAreas();
        });

        JButton redraw = GUIUtil.iconButton(new IconUtil.AreaIcon(16));
        redraw.setToolTipText("Redraw this area");
        redraw.addActionListener(_ -> onRedrawArea(area));

        JButton remove = GUIUtil.iconButton(new IconUtil.DeleteIcon(16));
        remove.setToolTipText("Remove");
        remove.addActionListener(_ -> {
            ctx.getCaptureAreaSet().removeCaptureAreas(area);
            refreshAreas();
        });

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        right.setOpaque(false);
        right.add(rename);
        right.add(redraw);
        right.add(remove);

        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.add(text, BorderLayout.CENTER);
        row.add(right, BorderLayout.EAST);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    private JPanel captureRow(AICapture capture) {
        JLabel thumb = new JLabel();
        thumb.setPreferredSize(new Dimension(THUMB_WIDTH, THUMB_HEIGHT));
        thumb.setHorizontalAlignment(SwingConstants.CENTER);
        thumb.setVerticalAlignment(SwingConstants.CENTER);
        ImageIcon icon = (capture.getGUID() != null) ? thumbnails.get(capture.getGUID()) : null;
        thumb.setIcon(icon != null ? icon : new IconUtil.CameraIcon(24));

        JLabel name = new JLabel(captureLabel(capture));
        name.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel sub = mutedLabel(captureSublabel(capture));

        JPanel text = new JPanel();
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setOpaque(false);
        text.add(name);
        text.add(sub);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        right.setOpaque(false);
        if (onSendToChat != null) {
            JButton send = GUIUtil.iconButton(new IconUtil.NextIcon(16));
            send.setToolTipText("Send to chat");
            send.addActionListener(_ -> onSendToChat(capture));
            right.add(send);
        }

        JButton open = GUIUtil.iconButton(new IconUtil.VisibleIcon(16));
        open.setToolTipText("Open");
        open.addActionListener(_ -> onViewCapture(capture));
        right.add(open);

        JButton rename = GUIUtil.iconButton(new IconUtil.EditIcon(16));
        rename.setToolTipText("Rename");
        rename.addActionListener(_ -> onRenameCapture(capture));
        right.add(rename);

        JButton delete = GUIUtil.iconButton(new IconUtil.DeleteIcon(16));
        delete.setToolTipText("Delete");
        delete.addActionListener(_ -> onRemoveCapture(capture));
        right.add(delete);

        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.add(thumb, BorderLayout.WEST);
        row.add(text, BorderLayout.CENTER);
        row.add(right, BorderLayout.EAST);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    private void onDefineArea() {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, defineAreaButton, () -> CaptureSupport.select(window), selection -> {
            if (selection == null) return;
            CaptureArea area = new CaptureArea(
                    "Area " + (ctx.getCaptureAreaSet().getCaptureAreas().length + 1),
                    selection.display(), selection.bounds());
            ctx.getCaptureAreaSet().addCaptureAreas(area);
            editingArea = area;
            showAreas();
            refreshAreas();
        });
    }

    private void onRedrawArea(CaptureArea area) {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, null, () -> CaptureSupport.select(window), selection -> {
            if (selection == null) return;
            area.setCaptureArea(selection.bounds());
            area.setDescription(selection.display());
            refreshAreas();
        });
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

    private void commitAreaName(CaptureArea area, String text) {
        if (editingArea != area) return;
        editingArea = null;
        String trimmed = (text == null) ? "" : text.trim();
        if (!trimmed.isEmpty()) area.setName(trimmed);
        refreshAreas();
    }

    private void updateCaptureButton() {
        int count = ctx.getCaptureAreaSet().getCaptureAreas().length;
        captureButton.setText("Capture (" + count + ")");
        captureButton.setEnabled(count > 0);
    }

    private void onViewCapture(AICapture capture) {
        if (capture == null || capture.getGUID() == null) return;
        BackgroundTask.run(this, null, () -> CaptureSupport.toImage(full(capture).getImage()), image -> {
            if (image == null) {
                JOptionPane.showMessageDialog(this, "That capture has no stored image.",
                        "Capture", JOptionPane.WARNING_MESSAGE);
                return;
            }
            previewed = capture;
            previewTitle.setText(captureLabel(capture) + "   " + captureSublabel(capture));
            previewImage.setIcon(new ImageIcon(image));
            previewImage.revalidate();
            previewImage.repaint();
            captureCards.show("preview");
        });
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
        String name = JOptionPane.showInputDialog(this, "Capture name", captureLabel(capture));
        if (name == null || name.trim().isEmpty()) return;

        String trimmed = name.trim();
        BackgroundTask.run(this, null, () -> {
            AICapture stored = full(capture);
            stored.setName(trimmed);
            return ctx.saveCapture(stored);
        }, _ -> {
            capture.setName(trimmed);
            rebuildCaptureRows();
            if (previewed == capture)
                previewTitle.setText(trimmed + "   " + captureSublabel(capture));
        });
    }

    private void onRemoveCapture(AICapture capture) {
        if (capture == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(captureLabel(capture), "capture"),
                "Delete capture", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, null, () -> ctx.deleteCapture(capture), () -> {
            if (previewed == capture) showCaptures();
            refreshCaptures();
        });
    }

    private void onDeleteAllCaptures() {
        if (captures.isEmpty()) return;
        int count = captures.size();
        int res = JOptionPane.showConfirmDialog(this,
                "Delete all " + count + " capture" + (count == 1 ? "" : "s")
                        + "? This permanently removes them.",
                "Delete all captures", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        List<AICapture> doomed = new ArrayList<>(captures);
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

    private void showAreas() {
        areasTab.setSelected(true);
        previewed = null;
        previewImage.setIcon(null);
        deleteAllButton.setVisible(false);
        captureCards.show("areas");
    }

    private void showCaptures() {
        capturesTab.setSelected(true);
        previewed = null;
        previewImage.setIcon(null);
        deleteAllButton.setVisible(true);
        captureCards.show("captures");
    }

    private static String areaLabel(CaptureArea area) {
        String name = area.getName();
        return (name == null || name.isBlank()) ? "Untitled area" : name;
    }

    private static String captureLabel(AICapture capture) {
        String name = capture.getName();
        return (name == null || name.isBlank()) ? "Untitled capture" : name;
    }

    private static String captureSublabel(AICapture capture) {
        StringBuilder sb = new StringBuilder();
        if (capture.getFromArea() != null && !capture.getFromArea().isBlank())
            sb.append(capture.getFromArea()).append("  ·  ");
        sb.append(capture.getWidth()).append('x').append(capture.getHeight());
        sb.append("  ·  ").append(CaptureSupport.bytes(capture.getNumBytes()));
        sb.append("  ·  ").append(CaptureSupport.shortTime(capture.getCreationTime()));
        return sb.toString();
    }

    private static JPanel listContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        return content;
    }

    private static JScrollPane scrollList(JPanel content) {
        JScrollPane scroll = new JScrollPane(new ScrollAnchor(content),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private static final class ScrollAnchor extends JPanel implements Scrollable {
        ScrollAnchor(Component content) {
            super(new BorderLayout());
            setOpaque(false);
            add(content, BorderLayout.NORTH);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) {
            return Math.max(32, visible.height - 16);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    private static JLabel mutedLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(label.getFont().getSize2D() - 2f));
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private static JLabel emptyLabel(String text) {
        JLabel label = new JLabel(text);
        label.setEnabled(false);
        label.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private static JSeparator separator() {
        JSeparator sep = new JSeparator();
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, sep.getPreferredSize().height));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        return sep;
    }

    public void reset() {
        captures.clear();
        thumbnails.clear();
        editingArea = null;
        refreshAreas();
        rebuildCaptureRows();
        showAreas();
    }
}
