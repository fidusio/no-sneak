package io.xlogistx.nosneak.app.ui;


import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;


import static java.awt.Component.LEFT_ALIGNMENT;

/**
 * The menu bar of the signed-in window (2026-10-24: File / View / Help). Navigation moved to the
 * sidebar; the View menu mirrors it for keyboard discoverability and nothing else. The "Mode"
 * menu with its never-wired "Technical Mode" checkbox is gone.
 */
public class MenuBarFactory {

    private static final String DESCRIPTION_RESOURCE = "/app-description.md";
    public static final String TAGLINE = "Network exposure and post-quantum readiness tooling";

    private final AppContext ctx;
    private JMenuBar menuBar;
    private JDialog about;
    private JDialog description;

    public MenuBarFactory(AppContext ctx) {
        this.ctx = ctx;
    }

    public JMenuBar buildMenu() {
        menuBar = new JMenuBar();

        JMenu file = new JMenu("File");
        JMenu view = new JMenu("View");
        JMenu help = new JMenu("Help");

        JMenuItem logout = new JMenuItem("Sign out");
        logout.addActionListener(_ -> {
            int ok = JOptionPane.showConfirmDialog(menuBar, "Sign out of NoSneak?", "Sign out",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) ctx.session().logout();
        });
        file.add(logout);

        view.add(page("New scan", Navigator.Screen.SCAN_NEW));
        view.add(page("Scan history", Navigator.Screen.SCAN_HISTORY));
        view.add(page("Probe library", Navigator.Screen.PROBES));
        view.addSeparator();
        view.add(page("Assistant chat", Navigator.Screen.CHAT));
        view.add(page("Chats", Navigator.Screen.CHATS));
        view.add(page("Capture", Navigator.Screen.CAPTURE));
        view.add(page("Skills", Navigator.Screen.SKILLS));
        view.add(page("Providers", Navigator.Screen.PROVIDERS));
        view.addSeparator();
        view.add(page("Profile", Navigator.Screen.PROFILE));
        view.add(page("API keys", Navigator.Screen.API_KEYS));
        view.add(page("Backup", Navigator.Screen.BACKUP));
        view.addSeparator();
        view.add(page("Access control", Navigator.Screen.ACL));

        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(_ -> showAbout());
        JMenuItem appHelp = new JMenuItem("Help");
        appHelp.addActionListener(_ -> showDescription());
        help.add(appHelp);
        help.add(aboutItem);

        menuBar.add(file);
        menuBar.add(view);
        menuBar.add(help);

        return menuBar;
    }

    private JMenuItem page(String label, Navigator.Screen screen) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(_ -> ctx.nav().show(screen));
        return item;
    }

    public void showAbout() {
        if (about == null) about = dialog("About " + NoSneakMain.VERSION.getName(), buildCard(), null);
        show(about);
    }

    public void showDescription() {
        if (description == null) {
            MDViewerPanel viewer = new MDViewerPanel();
            viewer.setMarkdown(loadDescription());
            description = dialog(NoSneakMain.VERSION.getName() + " — description", viewer, new Dimension(680, 560));
        }
        show(description);
    }

    /**
     * A modeless dialog owned by the application window, so it stays with it instead of
     * floating as its own top-level. The owner is found from the menu bar when it is installed,
     * else from the focused window.
     *
     * @param size explicit size, or null to pack to the content's preferred size
     */
    private JDialog dialog(String title, JComponent content, Dimension size) {
        Window owner = menuBar != null ? SwingUtilities.getWindowAncestor(menuBar) : null;
        if (owner == null) owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();

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
        return "# " + NoSneakMain.VERSION.getName() + "\n\n" + TAGLINE;
    }

    private JComponent buildCard() {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(24, 32, 24, 32)));

        card.add(left(PanelBuilder.title(NoSneakMain.VERSION.getName())));
        card.add(Box.createVerticalStrut(4));
        card.add(left(muted(new JLabel(TAGLINE))));
        card.add(Box.createVerticalStrut(16));
        card.add(left(new JSeparator()));
        card.add(Box.createVerticalStrut(16));

        card.add(left(detail("Version", NoSneakMain.VERSION.version())));
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
