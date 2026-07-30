package io.xlogistx.nosneak.ai.assistant;

import javax.swing.*;
import java.awt.*;

import org.commonmark.node.AbstractVisitor;
import org.commonmark.node.FencedCodeBlock;
import org.commonmark.node.IndentedCodeBlock;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

public class AssistantUtil {
    public static JComponent chatBubble(String text, boolean user) {
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        Node doc = parser.parse(unwrapMarkdownFence(text));
        doc.accept(new AbstractVisitor() {
            @Override
            public void visit(FencedCodeBlock b) {
                b.setLiteral(hardWrap(b.getLiteral(), 60));
            }

            @Override
            public void visit(IndentedCodeBlock b) {
                b.setLiteral(hardWrap(b.getLiteral(), 60));
            }
        });
        String html = renderer.render(doc);


        Color accent = UIManager.getColor("Component.accentColor");
        Color bg = user
                ? (accent != null ? accent : new Color(0x2D7FF9))
                : UIManager.getColor("Button.background");
        if (bg == null) bg = new Color(0xE6E6E6);

        JEditorPane pane = new JEditorPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setText("<html><body>" + html + "</body></html>");
        pane.setOpaque(false);
        pane.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        if (user) pane.setForeground(Color.WHITE);

        Bubble bubble = new Bubble(bg);
        bubble.add(pane, BorderLayout.CENTER);
        return bubble;
    }

    private static String hardWrap(String s, int cols) {
        StringBuilder out = new StringBuilder();
        for (String line : s.split("\n", -1)) {
            while (line.length() > cols) {
                out.append(line, 0, cols).append('\n');
                line = line.substring(cols);
            }
            out.append(line).append('\n');
        }
        return out.toString();
    }

    private static String unwrapMarkdownFence(String text) {
        //System.out.println(text);
        String t = text;
        if (text.contains("```md")) {
            t = t.replace("```md", "");
            return t;
        }
        if (text.contains("```markdown")) {
            t = t.replace("```markdown", "");
            return t;
        }
        if (text.contains("````")) {
            t = t.replace("````", "");
            return t;
        }
        return text;
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
