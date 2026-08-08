package io.xlogistx.nosneak.app.ui;


import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.app.Main;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;


import static java.awt.Component.LEFT_ALIGNMENT;

public class MenuBarFactory {

    private static final String DESCRIPTION_RESOURCE = "/app-description.md";
    private static final String TAGLINE = "Network exposure and post-quantum readiness tooling";

    private final AppContext ctx;
    private JMenuBar menuBar;
    private JDialog about;
    private JDialog description;

    public MenuBarFactory(AppContext ctx) {
        this.ctx = ctx;
    }

    public JMenuBar buildMenu() {
        menuBar = new JMenuBar();

        // JMenuBar -> JMenu -> JMenuItem

        // create menu bar items
        JMenu file = new JMenu("File");
        JMenu tools = new JMenu("Tools");
        JMenu help = new JMenu("Help");
        JMenu mode = new JMenu("Mode");

        JMenuItem logout = new JMenuItem("Logout");
        logout.setMaximumSize(logout.getPreferredSize());
        logout.addActionListener(_ -> {
            int ok = JOptionPane.showConfirmDialog(menuBar, "Log out of NoSneak?", "Logout",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) ctx.session().logout();
        });

        JCheckBoxMenuItem modeToggle = new JCheckBoxMenuItem("Technical Mode");

        JMenuItem scanner = new JMenuItem("Network scanner");
        scanner.addActionListener(_ -> ctx.nav().show(Navigator.Screen.SCAN));

/*
      JMenuItem pqc = new JMenuItem("PQC file sharing");
      pqc.addActionListener(e -> ctx.nav().show(Navigator.Screen.MAIN));
*/

        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(_ -> ctx.nav().show(Navigator.Screen.SUBJECT));

        JMenuItem manager = new JMenuItem("ACL Tool");
        manager.addActionListener(_ -> ctx.nav().show(Navigator.Screen.MANAGER));

        JMenuItem aiChat = new JMenuItem("AI Assistant");
        aiChat.addActionListener(_ -> ctx.nav().show(Navigator.Screen.ASSISTANT));

        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(_ -> showAbout());

        JMenuItem appHelp = new JMenuItem("Help");
        appHelp.addActionListener(_ -> showDescription());

        // FILE
        file.add(settings);

        // TOOLS
        tools.add(scanner);
        tools.add(manager);
        tools.add(aiChat);
//        tools.add(pqc);

        // HELP
        help.add(aboutItem);
        help.add(appHelp);


        mode.add(modeToggle);

        // add menu bar items to menu bar
        menuBar.add(file);
        menuBar.add(tools);
        menuBar.add(help);
        menuBar.add(Box.createHorizontalGlue());
        menuBar.add(logout);
        menuBar.add(mode);

        return menuBar;
    }

    private void showAbout() {
        if (about == null) about = dialog("About " + Main.VERSION.getName(), buildCard(), null);
        show(about);
    }

    private void showDescription() {
        if (description == null) {
            MDViewerPanel viewer = new MDViewerPanel();
            viewer.setMarkdown(loadDescription());
            description = dialog(Main.VERSION.getName() + " — description", viewer, new Dimension(680, 560));
        }
        show(description);
    }

    /**
     * A modeless dialog owned by the frame the menu bar is installed in, so it stays with the app
     * window instead of floating as its own top-level.
     *
     * @param size explicit size, or null to pack to the content's preferred size
     */
    private JDialog dialog(String title, JComponent content, Dimension size) {
        Window owner = menuBar != null ? SwingUtilities.getWindowAncestor(menuBar) : null;

        JDialog d = new JDialog(owner, title, Dialog.ModalityType.MODELESS);
        d.setContentPane(content);
        if (size != null) d.setSize(size);
        else d.pack();
        d.setLocationRelativeTo(owner);
        return d;
    }

    private void show(JDialog d) {
        d.setVisible(true);
        d.toFront();
    }

    private String loadDescription() {
        try (InputStream in = MenuBarFactory.class.getResourceAsStream(DESCRIPTION_RESOURCE)) {
            if (in != null) return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ignore) {
        }
        return "# " + Main.VERSION.getName() + "\n\n" + TAGLINE;
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
}
