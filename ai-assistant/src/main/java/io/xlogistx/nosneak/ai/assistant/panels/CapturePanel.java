package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.CaptureArea;
import io.xlogistx.nosneak.ai.model.AICapture;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

public class CapturePanel extends JPanel {

    private final AssistantContext ctx;
    private final List<AICapture> captures = new ArrayList<>();
    private final CardStack captureCards = new CardStack();

    private ListSection<AICapture> captureList;
    private JPanel areaStrip;
    private JButton newAreaButton;
    private JButton captureOnceButton;
    private JLabel previewTitle;
    private JLabel previewImage;

    private AICapture previewed;
    private int captureCount;
    private int areaCount;

    private BiConsumer<BufferedImage, String> onSendToChat;

    public CapturePanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildCaptureCards());
    }

    public void setOnSendToChat(BiConsumer<BufferedImage, String> onSendToChat) {
        this.onSendToChat = onSendToChat;
    }

    public JComponent buildCaptureCards() {
        captureCards.add(buildScreenCapturePanel(), "list");
        captureCards.add(buildPreviewPanel(), "preview");
        captureCards.show("list");
        return captureCards.view();
    }

    public JPanel buildScreenCapturePanel() {
        newAreaButton = new JButton("New area", new IconUtil.AreaIcon(16));
        newAreaButton.setToolTipText("Drag out a region you can re-shoot for the rest of this session");
        newAreaButton.addActionListener(_ -> onNewArea());

        captureOnceButton = new JButton("Capture once", new IconUtil.CameraIcon(16));
        captureOnceButton.setToolTipText("Drag out a region and capture it without saving the area");
        captureOnceButton.addActionListener(_ -> onCaptureOnce());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(newAreaButton);
        buttons.add(captureOnceButton);

        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.add(PanelBuilder.title("Capture"), BorderLayout.WEST);
        titleRow.add(buttons, BorderLayout.EAST);

        areaStrip = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        header.add(titleRow, BorderLayout.NORTH);
        header.add(areaStrip, BorderLayout.SOUTH);

        captureList = ListSection.of(() -> captures)
                .title("")
                .label(CapturePanel::captureLabel)
                .sublabel(CapturePanel::captureSublabel)
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Send to chat",
                        c -> (onSendToChat == null) ? null : () -> onSendToChat(c)))
                .action(new ListSection.RowAction<>(new IconUtil.VisibleIcon(16), "View capture",
                        c -> () -> onViewCapture(c)))
                .onEdit(c -> () -> onRenameCapture(c))
                .onRemove(c -> () -> onRemoveCapture(c))
                .emptyText("No captures yet")
                .search("search")
                .build();

        refreshAreas();

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(header, BorderLayout.NORTH);
        panel.add(captureList, BorderLayout.CENTER);
        return panel;
    }

    public JPanel buildPreviewPanel() {
        JButton back = GUIUtil.iconButton(new IconUtil.BackIcon(24), true);
        back.setToolTipText("Back");
        back.addActionListener(_ -> showList());

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

    /**
     * Rebuilds the area chips. Areas are session state on the context, so this is cheap and runs on
     * the EDT.
     */
    public void refreshAreas() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshAreas);
            return;
        }

        areaStrip.removeAll();
        List<CaptureArea> areas = ctx.getCaptureAreas();
        if (areas.isEmpty()) {
            JLabel none = new JLabel("No capture areas yet, add one to re-shoot the same region");
            none.setEnabled(false);
            areaStrip.add(none);
        } else {
            for (CaptureArea area : areas) areaStrip.add(areaChip(area));
        }
        areaStrip.revalidate();
        areaStrip.repaint();
    }

    /**
     * Reloads the capture rows off the EDT. The store read is projected, so these carry a thumbnail
     * but no full image.
     */
    public void refreshCaptures() {
        BackgroundTask.run(this, null, ctx::getAllCaptures, loaded -> {
            captures.clear();
            if (loaded != null) captures.addAll(loaded);
            captureList.refresh();
        });
    }

    private JPanel areaChip(CaptureArea area) {
        JButton shoot = new JButton(area.getName(), new IconUtil.CameraIcon(14));
        shoot.putClientProperty("JButton.buttonType", "borderless");
        shoot.setToolTipText("Capture " + CaptureSupport.region(area.getBounds()));
        shoot.setFocusable(false);
        shoot.addActionListener(_ -> onShootArea(area));

        JButton drop = GUIUtil.iconButton(new IconUtil.CancelIcon(12), true);
        drop.setToolTipText("Remove this area");
        drop.setFocusable(false);
        drop.addActionListener(_ -> {
            ctx.removeCaptureArea(area);
            refreshAreas();
        });

        JPanel chip = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        chip.setBorder(BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")));
        chip.add(shoot);
        chip.add(drop);
        return chip;
    }

    private void onNewArea() {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, newAreaButton, () -> CaptureSupport.select(window), bounds -> {
            if (bounds == null) {
                nothingSelected();
                return;
            }
            String name = JOptionPane.showInputDialog(this, "Area name", "Area " + (areaCount + 1));
            if (name == null || name.trim().isEmpty()) return;

            areaCount++;
            CaptureArea area = new CaptureArea();
            area.setName(name.trim());
            area.setBounds(bounds);
            ctx.addCaptureArea(area);
            refreshAreas();
        });
    }

    private void onShootArea(CaptureArea area) {
        area.setLastUsed(System.currentTimeMillis());
        capture(area.getBounds(), area.getName(), area.getName() + " " + timestamp(System.currentTimeMillis()));
    }

    private void onCaptureOnce() {
        capture(null, null, "Capture " + (captureCount + 1));
    }

    private void capture(Rectangle bounds, String areaName, String name) {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, captureOnceButton, () -> {
            BufferedImage shot = CaptureSupport.shoot(window, bounds);
            if (shot == null) return null;
            return ctx.saveCapture(CaptureSupport.toCapture(shot, name, areaName));
        }, saved -> {
            if (saved == null) {
                nothingSelected();
                return;
            }
            if (areaName == null) captureCount++;
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
        BackgroundTask.run(this, null, () -> CaptureSupport.toImage(full(capture).getImage()), image -> {
            if (image == null) {
                JOptionPane.showMessageDialog(this, "That capture has no stored image.",
                        "Capture", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (onSendToChat != null) onSendToChat.accept(image, captureLabel(capture));
        });
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
            captureList.refresh();
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
            if (previewed == capture) showList();
            refreshCaptures();
        });
    }

    private AICapture full(AICapture projected) {
        AICapture stored = ctx.getCapture(projected.getGUID());
        return (stored != null) ? stored : projected;
    }

    private void nothingSelected() {
        JOptionPane.showMessageDialog(this, "Nothing was selected. Drag out an area to capture it.",
                "Capture", JOptionPane.INFORMATION_MESSAGE);
    }

    private static String captureLabel(AICapture capture) {
        String name = capture.getName();
        return (name == null || name.isBlank()) ? "Untitled capture" : name;
    }

    private static String captureSublabel(AICapture capture) {
        StringBuilder sb = new StringBuilder();
        sb.append(capture.getWidth()).append('x').append(capture.getHeight());
        if (capture.getFromArea() != null && !capture.getFromArea().isBlank())
            sb.append("  ·  from ").append(capture.getFromArea());
        sb.append("  ·  ").append(timestamp(capture.getCreationTime()));
        return sb.toString();
    }

    private void showList() {
        previewed = null;
        previewImage.setIcon(null);
        captureCards.show("list");
    }

    public void reset() {
        captures.clear();
        captureCount = 0;
        areaCount = 0;
        refreshAreas();
        showList();
        captureList.refresh();
    }
}