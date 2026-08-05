package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.app.Main;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class AppInfoPanel extends JPanel {

    private static final String DESCRIPTION_RESOURCE = "/app-description.md";
    private static final String TAGLINE = "Network exposure and post-quantum readiness tooling";

    private final AppContext ctx;
    private JDialog description;

    public AppInfoPanel(AppContext context) {
        this.ctx = context;
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(24, 24, 24, 24));
        add(buildCard());
    }

    private JComponent buildCard() {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(24, 32, 24, 32)));

        card.add(left(PanelBuilder.title(Main.VERSION.getName())));
        card.add(Box.createVerticalStrut(4));
        card.add(left(muted(new JLabel(TAGLINE))));
        card.add(Box.createVerticalStrut(16));
        card.add(left(new JSeparator()));
        card.add(Box.createVerticalStrut(16));

        card.add(left(detail("Version", Main.VERSION.version())));
        card.add(Box.createVerticalStrut(6));
        card.add(left(detail("Java", System.getProperty("java.version"))));
        card.add(Box.createVerticalStrut(6));
        card.add(left(detail("Platform", System.getProperty("os.name") + " " + System.getProperty("os.arch"))));
        card.add(Box.createVerticalStrut(20));

        JButton open = new JButton("App description");
        open.addActionListener(e -> showDescription());
        card.add(left(open));
        return card;
    }

    private JComponent detail(String label, String value) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.setOpaque(false);

        JLabel name = new JLabel(label);
        name.setPreferredSize(new Dimension(80, name.getPreferredSize().height));
        row.add(muted(name));

        JLabel field = new JLabel(value != null ? value : "");
        field.setFont(new Font(Font.MONOSPACED, Font.PLAIN, field.getFont().getSize()));
        row.add(field);
        return row;
    }

    private JLabel muted(JLabel label) {
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        return label;
    }

    private JComponent left(JComponent component) {
        component.setAlignmentX(LEFT_ALIGNMENT);
        component.setMaximumSize(new Dimension(Integer.MAX_VALUE, component.getPreferredSize().height));
        return component;
    }

    private void showDescription() {
        if (description == null) {
            MDViewerPanel viewer = new MDViewerPanel();
            viewer.setMarkdown(loadDescription());

            description = new JDialog(SwingUtilities.getWindowAncestor(this),
                    Main.VERSION.getName() + " — description", Dialog.ModalityType.MODELESS);
            description.setContentPane(viewer);
            description.setSize(680, 560);
            description.setLocationRelativeTo(this);
        }
        description.setVisible(true);
        description.toFront();
    }

    private String loadDescription() {
        try (InputStream in = AppInfoPanel.class.getResourceAsStream(DESCRIPTION_RESOURCE)) {
            if (in != null) return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ignore) {
        }
        return "# " + Main.VERSION.getName() + "\n\n" + TAGLINE;
    }
}