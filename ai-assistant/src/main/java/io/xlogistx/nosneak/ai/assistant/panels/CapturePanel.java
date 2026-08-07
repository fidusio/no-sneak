package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

public class CapturePanel extends JPanel {

    private static final int SETTLE_MILLIS = 150;

    private final AssistantContext ctx;
    private final List<ScreenCapture> captures = new ArrayList<>();
    private final CardStack captureCards = new CardStack();

    private ListSection<ScreenCapture> captureList;
    private JButton selectAreaButton;
    private JButton clearAreaButton;
    private JButton captureButton;
    private JLabel areaLabel;
    private JLabel previewTitle;
    private JLabel previewImage;

    private Rectangle pendingArea;
    private ScreenCapture previewed;
    private int captureCount;

    private Consumer<ScreenCapture> onSendToChat;

    public CapturePanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildCaptureCards());
    }

    /**
     * Set by the host to hand a capture to the chat composer. The row action only renders when a
     * handler is present.
     */
    public void setOnSendToChat(Consumer<ScreenCapture> onSendToChat) {
        this.onSendToChat = onSendToChat;
    }

    public List<ScreenCapture> getCaptures() {
        return captures;
    }

    public JComponent buildCaptureCards() {
        captureCards.add(buildScreenCapturePanel(), "list");
        captureCards.add(buildPreviewPanel(), "preview");
        captureCards.show("list");
        return captureCards.view();
    }

    public JPanel buildScreenCapturePanel() {
        selectAreaButton = new JButton("Select Area", new IconUtil.AreaIcon(16));
        selectAreaButton.addActionListener(_ -> onSelectArea());

        clearAreaButton = new JButton("Clear Area");
        clearAreaButton.addActionListener(_ -> onClearArea());

        captureButton = new JButton("Capture", new IconUtil.CameraIcon(16));
        captureButton.addActionListener(_ -> onCapture());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(selectAreaButton);
        buttons.add(clearAreaButton);
        buttons.add(captureButton);

        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.add(PanelBuilder.title("Capture"), BorderLayout.WEST);
        titleRow.add(buttons, BorderLayout.EAST);

        areaLabel = new JLabel();
        areaLabel.setEnabled(false);

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        header.add(titleRow, BorderLayout.NORTH);
        header.add(areaLabel, BorderLayout.SOUTH);

        captureList = ListSection.of(() -> captures)
                .title("")
                .label(ScreenCapture::getName)
                .sublabel(CapturePanel::captureSublabel)
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Send to chat",
                        c -> (onSendToChat == null) ? null : () -> onSendToChat.accept(c)))
                .action(new ListSection.RowAction<>(new IconUtil.VisibleIcon(16), "View Capture",
                        c -> () -> onViewCapture(c)))
                .action(new ListSection.RowAction<>(new IconUtil.AreaIcon(16), "Edit Capture Location",
                        c -> () -> onEditCaptureLocation(c)))
                .onEdit(c -> () -> onEditCaptureDetails(c))
                .onRemove(c -> () -> onRemoveCapture(c))
                .emptyText("No Captures yet")
                .search("search")
                .build();

        updateAreaLabel();

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
        panel.add(previewImage, BorderLayout.CENTER);
        return panel;
    }

    private void onSelectArea() {
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, selectAreaButton, () -> selectArea(window), area -> {
            if (area == null) {
                nothingSelected();
                return;
            }
            pendingArea = area;
            updateAreaLabel();
        });
    }

    private void onClearArea() {
        pendingArea = null;
        updateAreaLabel();
    }

    private void onCapture() {
        Window window = SwingUtilities.getWindowAncestor(this);
        Rectangle area = pendingArea;
        BackgroundTask.run(this, captureButton, () -> shoot(window, area), shot -> {
            if (shot == null) {
                nothingSelected();
                return;
            }
            shot.setName("Capture " + (++captureCount));
            captures.add(shot);
            captureList.refresh();
        });
    }

    private void onViewCapture(ScreenCapture capture) {
        if (capture == null || capture.getImage() == null) return;
        previewed = capture;
        previewTitle.setText(capture.getName() + "   " + captureSublabel(capture));
        previewImage.setIcon(new ImageIcon(capture.getImage()));
        previewImage.revalidate();
        previewImage.repaint();
        captureCards.show("preview");
    }

    private void onEditCaptureLocation(ScreenCapture capture) {
        if (capture == null) return;
        Window window = SwingUtilities.getWindowAncestor(this);
        BackgroundTask.run(this, captureButton, () -> shoot(window, null), shot -> {
            if (shot == null) {
                nothingSelected();
                return;
            }
            capture.setArea(shot.getArea());
            capture.setImage(shot.getImage());
            capture.setTimestamp(shot.getTimestamp());
            captureList.refresh();
            if (previewed == capture) onViewCapture(capture);
        });
    }

    private void onEditCaptureDetails(ScreenCapture capture) {
        if (capture == null) return;
        String name = JOptionPane.showInputDialog(this, "Capture name", capture.getName());
        if (name == null || name.trim().isEmpty()) return;
        capture.setName(name.trim());
        captureList.refresh();
        if (previewed == capture) previewTitle.setText(capture.getName() + "   " + captureSublabel(capture));
    }

    private void onRemoveCapture(ScreenCapture capture) {
        if (capture == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(capture.getName(), "capture"),
                "Delete capture", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        captures.remove(capture);
        if (previewed == capture) showList();
        captureList.refresh();
    }

    /**
     * Runs off the EDT: hides the window so it stays out of the shot, takes the selection (or
     * reuses the pending one), and restores the window whatever happens.
     */
    private ScreenCapture shoot(Window window, Rectangle preset) throws Exception {
        hideWindow(window);
        try {
            Rectangle area = (preset != null) ? preset : select();
            if (!usable(area)) return null;
            ScreenCapture capture = new ScreenCapture(area, GUIUtil.captureSelectedArea(area));
            capture.setTimestamp(System.currentTimeMillis());
            return capture;
        } finally {
            restoreWindow(window);
        }
    }

    private Rectangle selectArea(Window window) throws Exception {
        hideWindow(window);
        try {
            Rectangle area = select();
            return usable(area) ? area : null;
        } finally {
            restoreWindow(window);
        }
    }

    private static Rectangle select() throws Exception {
        Rectangle area = GUIUtil.captureSelectedArea();
        settle();
        return area;
    }

    private static boolean usable(Rectangle area) {
        return area != null && area.width > 0 && area.height > 0;
    }

    private static void hideWindow(Window window) throws Exception {
        if (window == null) return;
        SwingUtilities.invokeAndWait(() -> window.setVisible(false));
        settle();
    }

    private static void restoreWindow(Window window) {
        if (window == null) return;
        SwingUtilities.invokeLater(() -> {
            window.setVisible(true);
            window.toFront();
        });
    }

    /**
     * The selection overlay is disposed on an invokeLater, so flush the EDT queue and give the
     * compositor a beat before Robot fires, or the shot catches the overlay tint.
     */
    private static void settle() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
        });
        Thread.sleep(SETTLE_MILLIS);
    }

    private void nothingSelected() {
        JOptionPane.showMessageDialog(this, "Nothing was selected. Drag out an area to capture it.",
                "Capture", JOptionPane.INFORMATION_MESSAGE);
    }

    private void updateAreaLabel() {
        boolean set = (pendingArea != null);
        areaLabel.setText(set ? "Capture area " + region(pendingArea)
                : "No area selected, Capture asks for one");
        clearAreaButton.setEnabled(set);
    }

    private static String captureSublabel(ScreenCapture capture) {
        return region(capture.getArea()) + "  ·  " + timestamp(capture.getTimestamp());
    }

    private static String region(Rectangle area) {
        if (area == null) return "no area";
        return area.width + "x" + area.height + " at " + area.x + "," + area.y;
    }

    private void showList() {
        previewed = null;
        previewImage.setIcon(null);
        captureCards.show("list");
    }

    public void reset() {
        captures.clear();
        captureCount = 0;
        pendingArea = null;
        updateAreaLabel();
        showList();
        captureList.refresh();
    }
}
