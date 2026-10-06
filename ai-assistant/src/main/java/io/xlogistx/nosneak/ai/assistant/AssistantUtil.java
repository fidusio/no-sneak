package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.PDFViewerPanel;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.*;
import java.awt.*;

public class AssistantUtil {

    public static JComponent chatBubble(NVGenericMap response, boolean user, Integer latency,
                                        Integer inTokens, Integer outTokens) {
        return chatBubble(AssistantMDDecoder.SINGLETON.decode(response), user, latency, inTokens, outTokens);
    }

    public static JComponent chatBubble(String markdown, boolean user, Integer latency,
                                        Integer inTokens, Integer outTokens) {
        return chatBubble(markdown, user, latency, inTokens, outTokens, null);
    }

    /**
     * @param latency   milliseconds, or null / 0 to omit
     * @param inTokens  prompt tokens the provider reported, or null / 0 to omit
     * @param outTokens completion tokens the provider reported, or null / 0 to omit
     *                  (2026-09-23: the detail line shows in and out separately, no total)
     */
    public static JComponent chatBubble(String markdown, boolean user, Integer latency,
                                        Integer inTokens, Integer outTokens, Runnable onSaveAsSkill) {

        MDViewerPanel mdViewerPanel = new MDViewerPanel();
        mdViewerPanel.setMarkdown(markdown);

        JEditorPane pane = mdViewerPanel.getEditorPane();
        pane.setOpaque(false);
        pane.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        Color accent = UIManager.getColor("Component.accentColor");
        Color bg = user
                ? (accent != null ? accent : new Color(0x2D7FF9))
                : UIManager.getColor("Button.background");
        if (bg == null) bg = new Color(0xE6E6E6);

        if (user) pane.setForeground(Color.WHITE);

        Bubble bubble = new Bubble(bg);
        bubble.add(pane, BorderLayout.CENTER);
        String detail = user ? null : detailLine(latency, inTokens, outTokens);
        if (detail != null || (!user && onSaveAsSkill != null)) {
            JPanel south = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            south.setOpaque(false);
            south.setBorder(BorderFactory.createEmptyBorder(0, 12, 6, 12));
            if (detail != null) {
                JLabel label = new JLabel(detail);
                label.setFont(label.getFont().deriveFont(label.getFont().getSize2D() - 2f));
                label.setForeground(UIManager.getColor("Label.disabledForeground"));
                south.add(label);
            }
            if (onSaveAsSkill != null) {
                JButton saveAsSkill = new JButton("Save as skill");
                saveAsSkill.putClientProperty("JButton.buttonType", "borderless");
                saveAsSkill.setFont(saveAsSkill.getFont().deriveFont(saveAsSkill.getFont().getSize2D() - 2f));
                saveAsSkill.setForeground(UIManager.getColor("Label.disabledForeground"));
                saveAsSkill.setFocusable(false);
                saveAsSkill.setToolTipText("Open the skill editor seeded with this response");
                saveAsSkill.addActionListener(_ -> onSaveAsSkill.run());
                south.add(saveAsSkill);
            }
            if (markdown != null) {
                JButton copyMarkdown = new JButton(new IconUtil.CopyIcon(16));
                copyMarkdown.putClientProperty("JButton.buttonType", "borderless");
                copyMarkdown.setFont(copyMarkdown.getFont().deriveFont(copyMarkdown.getFont().getSize2D() - 2f));
                copyMarkdown.setForeground(UIManager.getColor("Label.disabledForeground"));
                copyMarkdown.setFocusable(false);
                copyMarkdown.setToolTipText("Copy the response text");
                copyMarkdown.addActionListener(_ -> copyResponse(pane));
                south.add(copyMarkdown);

                JButton convertMDToPDF = new JButton(new IconUtil.FileIcon(16));
                convertMDToPDF.putClientProperty("JButton.buttonType", "borderless");
                convertMDToPDF.setFont(convertMDToPDF.getFont().deriveFont(convertMDToPDF.getFont().getSize2D() - 2f));
                convertMDToPDF.setForeground(UIManager.getColor("Label.disabledForeground"));
                convertMDToPDF.setFocusable(false);
                convertMDToPDF.setToolTipText("Show this response as a PDF");
                convertMDToPDF.addActionListener(_ -> showAsPDF(convertMDToPDF, markdown));
                south.add(convertMDToPDF);
            }
            bubble.add(south, BorderLayout.SOUTH);
        }

        return bubble;
    }

    /**
     * The bubble's PDF button (2026-09-23): renders the response's markdown to PDF with the
     * toolkit's {@link MDToPDF} off the EDT, then opens it in a {@link PDFViewerPanel} inside a
     * modeless dialog. The conversion is the slow part (fonts embedded, PDFBox layout), so the
     * button is disabled while it runs and {@code BackgroundTask} reports a failure in its own
     * dialog. Everything else — Save, Print, Insert, Delete pages — is the viewer's own toolbar
     * (page editing lives in the toolkit, not here), so the dialog only asks the viewer's
     * {@code confirmDiscard()} before closing on unsaved edits.
     */
    static void showAsPDF(JComponent owner, String markdown) {
        String md = markdown == null ? "" : markdown;
        BackgroundTask.run(owner, owner, () -> MDToPDF.mdToPDF(md).toByteArray(), pdf -> {
            Window parent = SwingUtilities.getWindowAncestor(owner);
            JDialog dialog = new JDialog(parent, "Response as PDF", Dialog.ModalityType.MODELESS);
            PDFViewerPanel viewer = new PDFViewerPanel(true);
            dialog.setContentPane(viewer);
            dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent e) {
                    if (viewer.confirmDiscard()) dialog.dispose();
                }

                @Override
                public void windowClosed(java.awt.event.WindowEvent e) {
                    viewer.close();
                }
            });
            dialog.setSize(900, 940);
            dialog.setLocationRelativeTo(parent);
            dialog.setVisible(true);
            viewer.setPDF(pdf);
        });
    }

    private static void copyResponse(JEditorPane pane) {
        boolean selected = pane.getSelectionStart() != pane.getSelectionEnd();
        if (!selected) pane.selectAll();
        pane.copy();
        if (!selected) pane.select(0, 0);
    }

    /**
     * {@code 120 ms · 57 in / 203 out tokens}; a missing or zero part is left out, all missing → null.
     */
    static String detailLine(Integer latency, Integer inTokens, Integer outTokens) {
        StringBuilder sb = new StringBuilder();
        if (latency != null && latency > 0) sb.append(latency).append(" ms");
        boolean in = inTokens != null && inTokens > 0;
        boolean out = outTokens != null && outTokens > 0;
        if (in || out) {
            if (!sb.isEmpty()) sb.append(" · ");
            if (in) sb.append(inTokens).append(" in");
            if (in && out) sb.append(" / ");
            if (out) sb.append(outTokens).append(" out");
            sb.append(" tokens");
        }
        return sb.isEmpty() ? null : sb.toString();
    }


    private static class Bubble extends JPanel {
        Bubble(Color bg) {
            setOpaque(false);
            setBackground(bg);
            setLayout(new BorderLayout());
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 18, 18);
            g2.dispose();
            super.paintComponent(g);
        }
    }
}
