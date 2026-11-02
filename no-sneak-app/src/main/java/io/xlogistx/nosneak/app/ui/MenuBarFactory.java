package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.NSAppUtil;

import io.xlogistx.gui.ComponentRef;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.KeyValuePanel;
import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.UITokens;
import io.xlogistx.gui.WrapLabel;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;

import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The menu bar of the signed-in window (2026-10-24: File / View / Help). Navigation moved to the
 * sidebar; the View menu mirrors it for keyboard discoverability and nothing else. The "Mode"
 * menu with its never-wired "Technical Mode" checkbox is gone.
 * <p>
 * Help is the bundled {@code app-description.md} (one entry per sidebar page) in an
 * {@link MDViewerPanel}; About is a card in the house look (2026-10-27): the name, the tagline,
 * the one-paragraph {@link #SUMMARY} of what the tool does and will not do, the version / Java /
 * platform / store facts, and a link to Help. Keep both in step when a page is added or merged.
 */
public class MenuBarFactory {

    private static final String DESCRIPTION_RESOURCE = "/app-description.md";
    public static final String TAGLINE = "Network exposure and post-quantum readiness, with an AI assistant";
    /** The About card's paragraph: the same promise as the Help's "What it will and won't do". */
    public static final String SUMMARY = "It looks, and it reports: host liveness, open ports, service banners, "
            + "the MAC and vendor of each host, TLS handshakes and certificates, graded for post-quantum readiness. "
            + "The assistant, on a provider you configure with your own API key, makes sense of the results. "
            + "It does not exploit what it finds, guess passwords or flood a target; traffic leaves under this "
            + "machine's own address. Point it at endpoints you own, administer, or have permission to test.";
    /** What the open vault holds: the About card's Store row and the header chip's tooltip. */
    public static final String STORE_NOTE = "The vault holds the encrypted H2 store, opened with your own credentials; "
            + "every scan report, chat, capture and skill in it is kept under your account.";

    private final AppContext ctx;
    private JMenuBar menuBar;
    private JDialog about;
    private JDialog description;

    public MenuBarFactory(AppContext ctx) {
        this.ctx = ctx;
    }

    public JMenuBar buildMenu() {
        menuBar = new JMenuBar();
        menuBar.setName(NSAppUtil.MenuBar.BAR.getName());

        JMenu file = GUIUtil.applyProp(new JMenu(), NSAppUtil.MenuBar.FILE);
        JMenu view = GUIUtil.applyProp(new JMenu(), NSAppUtil.MenuBar.VIEW);
        JMenu help = GUIUtil.applyProp(new JMenu(), NSAppUtil.MenuBar.HELP);

        JMenuItem logout = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.MenuBar.SIGN_OUT);
        logout.addActionListener(_ -> {
            int ok = JOptionPane.showConfirmDialog(menuBar, "Sign out of NoSneak?", NSAppUtil.MenuBar.SIGN_OUT_DIALOG.getDisplayName(),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) ctx.session().logout();
        });
        file.add(logout);

        view.add(page(NSAppUtil.Screen.SCAN));
        view.add(page(NSAppUtil.Screen.SCAN_HISTORY));
        view.add(page(NSAppUtil.Screen.PROBES));
        view.addSeparator();
        view.add(page(NSAppUtil.MenuBar.VIEW_CHAT.getDisplayName(), NSAppUtil.Screen.CHAT));
        view.add(page(NSAppUtil.Screen.CAPTURE));
        view.add(page(NSAppUtil.Screen.SKILLS));
        view.add(page(NSAppUtil.Screen.PROVIDERS));
        view.addSeparator();
        view.add(page(NSAppUtil.Screen.PROFILE));
        view.add(page(NSAppUtil.Screen.API_KEYS));
        view.add(page(NSAppUtil.Screen.SETTINGS));
        view.addSeparator();
        view.add(page(NSAppUtil.Screen.ACL));

        JMenuItem aboutItem = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.MenuBar.ABOUT);
        aboutItem.addActionListener(_ -> showAbout());
        JMenuItem appHelp = GUIUtil.applyProp(new JMenuItem(), NSAppUtil.MenuBar.HELP_ITEM);
        appHelp.addActionListener(_ -> showDescription());
        help.add(appHelp);
        help.add(aboutItem);

        menuBar.add(file);
        menuBar.add(view);
        menuBar.add(help);

        return menuBar;
    }


    /** The View menu's items, each a ref over its screen (2026-10-27); for hosts that read the menu. */
    private final List<ComponentRef<NSAppUtil.Screen>> viewItems = new ArrayList<>();

    /** A View item worded as the sidebar words the screen. */
    private JMenuItem page(NSAppUtil.Screen screen) {
        return page(screen, null);
    }

    /**
     * A View item for a screen, worded by {@code label} when given ({@code MenuBar.VIEW_CHAT} for the Chat
     * page): the ref's display name is the text, its description the tooltip, its source the
     * screen the item shows.
     */
    private JMenuItem page(String label, NSAppUtil.Screen screen) {
        return page(screen, label);
    }

    private JMenuItem page(NSAppUtil.Screen screen, String label) {
        JMenuItem item = new JMenuItem();
        ComponentRef<NSAppUtil.Screen> ref = GUIUtil.applyProp(new ComponentRef<>(item, screen, label));
        item.addActionListener(_ -> ctx.nav().show(ref.getSource()));
        viewItems.add(ref);
        return item;
    }

    /** The View menu's items as refs: text, tooltip and the screen each one shows. */
    public List<ComponentRef<NSAppUtil.Screen>> viewItems() {
        return Collections.unmodifiableList(viewItems);
    }

    public void showAbout() {
        if (about == null) about = dialog(NSAppUtil.MenuBar.ABOUT_DIALOG.getDisplayName() + " " + NoSneakMain.VERSION.getName(), buildAbout(), null);
        show(about);
    }

    public void showDescription() {
        if (description == null) {
            MDViewerPanel viewer = new MDViewerPanel();
            viewer.setMarkdown(loadDescription());
            description = dialog(NoSneakMain.VERSION.getName() + " — " + NSAppUtil.MenuBar.HELP_DIALOG.getDisplayName(), viewer, new Dimension(680, 560));
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

    /** The About card: name, tagline, summary, facts, a Help link. 460 px wide, packed to height. */
    private JComponent buildAbout() {
        JPanel card = new JPanel(new MigLayout("insets 24 32 24 32, wrap 1, gapy 0, fillx", "[460!]"));
        card.setName(NSAppUtil.MenuBar.ABOUT_CARD.getName());
        card.setBackground(UITokens.surface());

        JLabel name = GUIUtil.applyProp(new JLabel(NoSneakMain.VERSION.getName()), NSAppUtil.MenuBar.ABOUT_NAME);
        name.setFont(UITokens.font(Font.BOLD, 8f));
        card.add(name, "growx");

        JLabel tagline = GUIUtil.applyProp(new JLabel(TAGLINE), NSAppUtil.MenuBar.ABOUT_TAGLINE);
        tagline.setForeground(UITokens.muted());
        card.add(tagline, "growx, gaptop 2");

        WrapLabel summary = GUIUtil.applyProp(new WrapLabel(SUMMARY), NSAppUtil.MenuBar.ABOUT_SUMMARY);
        summary.setWrapWidth(460);
        card.add(summary, "growx, wmin 0, gaptop 14");

        card.add(new JSeparator(), "growx, gaptop 16, gapbottom 14");

        KeyValuePanel facts = new KeyValuePanel(80);
        facts.setName(NSAppUtil.MenuBar.ABOUT_FACTS.getName());
        facts.putMono(NSAppUtil.MenuBar.FACT_VERSION.getDisplayName(), NoSneakMain.VERSION.version());
        facts.putMono(NSAppUtil.MenuBar.FACT_JAVA.getDisplayName(), System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");
        facts.putMono(NSAppUtil.MenuBar.FACT_PLATFORM.getDisplayName(), System.getProperty("os.name") + " " + System.getProperty("os.version")
                + " " + System.getProperty("os.arch"));
        File store = AppPrefs.storeLocation();
        facts.putMono(NSAppUtil.MenuBar.FACT_VAULT.getDisplayName(), store != null ? store.getAbsolutePath() : NSAppUtil.MenuBar.VAULT_NOT_OPEN.getDisplayName());
        facts.put(NSAppUtil.MenuBar.FACT_STORE.getDisplayName(), STORE_NOTE);
        card.add(facts, "growx, wmin 0");

        WrapLabel tips = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.MenuBar.ABOUT_TIPS);
        tips.setFont(UITokens.font(Font.PLAIN, -1f));
        tips.setForeground(UITokens.muted());
        tips.setWrapWidth(460);
        card.add(tips, "growx, wmin 0, gaptop 14");

        JButton help = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.MenuBar.ABOUT_HELP_LINK));
        help.addActionListener(_ -> showDescription());
        card.add(help, "gaptop 4, left");
        return card;
    }
}
