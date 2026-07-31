package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.MDViewerPanel;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.*;
import java.awt.*;

public class AssistantUtil {

    public static JComponent chatBubble(NVGenericMap response, boolean user, Integer latency, Integer tokens) {
        return chatBubble(AssistantMDDecoder.SINGLETON.decode(response), user, latency, tokens);
    }

    public static JComponent chatBubble(String markdown, boolean user, Integer latency, Integer tokens) {

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
        String detail = user ? null : detailLine(latency, tokens);
        if (detail != null) {
            JLabel label = new JLabel(detail);
            label.setFont(label.getFont().deriveFont(label.getFont().getSize2D() - 2f));
            label.setForeground(UIManager.getColor("Label.disabledForeground"));
            label.setBorder(BorderFactory.createEmptyBorder(0, 12, 6, 12));
            bubble.add(label, BorderLayout.SOUTH);
        }

        return bubble;
    }

    private static String detailLine(Integer latency, Integer tokens) {
        StringBuilder sb = new StringBuilder();
        if (latency != null && latency > 0) sb.append(latency).append(" ms");
        if (tokens != null && tokens > 0) {
            if (!sb.isEmpty()) sb.append(" · ");
            sb.append(tokens).append(" tokens");
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
