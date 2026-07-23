package io.xlogistx.nosneak.ai.assistant;

import javax.swing.*;
import java.awt.*;

public class AssistantUtil {
    public static JComponent chatBubble(String text, boolean user) {
        Color accent = UIManager.getColor("Component.accentColor");
        Color bg = user
                ? (accent != null ? accent : new Color(0x2D7FF9))
                : UIManager.getColor("Button.background");
        if (bg == null) bg = new Color(0xE6E6E6);

        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        if (user) area.setForeground(Color.WHITE);

        Bubble bubble = new Bubble(bg);
        bubble.add(area, BorderLayout.CENTER);
        return bubble;
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
