package io.xlogistx.nosneak.app.ui;


import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.HeaderBar;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.SideNavPanel;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.ui.assistant.AssistantStorage;
import io.xlogistx.nosneak.app.ui.assistant.SessionAICredentialSource;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.nosneak.app.ui.utility.Navigator.Screen;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * The signed-in application (2026-10-24, Phase 2 of the UI redesign): a {@link HeaderBar}
 * (brand, the open store, the subject, Sign out), one {@link SideNavPanel} for every page,
 * a {@code CardLayout} host with one card per screen panel, and a footer. The sidebar replaces
 * both the old menu-bar navigation and each screen's own toggle column: the panels keep their
 * internal {@code CardStack}s and expose {@code show(section)}, and {@link Navigator} routes a
 * {@link Screen} to a card plus a section. Every panel is constructed here, when the store
 * opens and before anyone signs in — the navigator controls visibility only, never construction.
 * Signing in happens outside this shell: {@code NoSneakMain.AppFrame} shows the
 * {@link UnlockPanel} until the session authenticates, then swaps this shell in, and swaps it
 * back out on logout.
 * <p>
 * This is also where the scanner and the assistant are joined, and <b>the order is load-bearing</b>:
 * the assistant is built first so {@code ScanPanel} can take its {@code sendToChat} hook, then the
 * assistant is handed {@code scanPanel::saveProbeFromEditor} for the reverse direction. Both
 * directions are plain callbacks, which is what keeps the module dependency one-way
 * ({@code no-sneak-app → ai-assistant}) even though data flows both ways.
 */
public class AppShell extends JPanel {

    private static final String SECTION_ADMIN = "admin";

    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private final AppContext ctx;
    private final Navigator navigator;
    private final HeaderBar header;
    private final SideNavPanel nav = new SideNavPanel();
    private final MenuBarFactory menus;

    // import assistant panel from ai-assistant gui
    private final AssistantPanel assistantPanel;
    private final ScanPanel scanPanel;
    private final SubjectPanel subjectPanel;
    private final SubjectSecManagerPanel managerPanel;

    public AppShell(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        assistantPanel = new AssistantPanel(new AssistantContext(new SessionAICredentialSource(ctx.session()), new AssistantStorage(ctx.session())));
        subjectPanel = new SubjectPanel(ctx);
        scanPanel = new ScanPanel(ctx, assistantPanel::sendToChat);
        assistantPanel.addSaveTarget("probe", scanPanel::saveProbeFromEditor);
        managerPanel = new SubjectSecManagerPanel(ctx);

        // the navigator adds each panel to the content host as a card the first time a screen
        // names it (2026-10-27); a route is a ComponentRef over that panel keyed by the Screen
        navigator = new Navigator(cards, content);
        navigator.register(Screen.SCAN, scanPanel, () -> scanPanel.show(ScanPanel.SECTION_SCAN));
        navigator.register(Screen.SCAN_HISTORY, scanPanel, () -> scanPanel.show(ScanPanel.SECTION_HISTORY));
        navigator.register(Screen.PROBES, scanPanel, () -> scanPanel.show(ScanPanel.SECTION_PROBES));
        navigator.register(Screen.CHAT, assistantPanel, () -> assistantPanel.showPage(AssistantPanel.Page.CHAT));
        navigator.register(Screen.CAPTURE, assistantPanel, () -> assistantPanel.showPage(AssistantPanel.Page.CAPTURE));
        navigator.register(Screen.SKILLS, assistantPanel, () -> assistantPanel.showPage(AssistantPanel.Page.SKILLS));
        navigator.register(Screen.PROVIDERS, assistantPanel, () -> assistantPanel.showPage(AssistantPanel.Page.PROVIDERS));
        navigator.register(Screen.PROFILE, subjectPanel, () -> subjectPanel.show(SubjectPanel.SECTION_PROFILE));
        navigator.register(Screen.API_KEYS, subjectPanel, () -> subjectPanel.show(SubjectPanel.SECTION_CREDENTIALS));
        navigator.register(Screen.SETTINGS, subjectPanel, () -> subjectPanel.show(SubjectPanel.SECTION_SETTINGS));
        navigator.register(Screen.ACL, managerPanel, null);
        ctx.setNavigator(navigator);

        // the assistant moves itself (a chat opened from history, a report sent from the scanner):
        // the card is already the assistant's or about to be, so only the sidebar needs telling
        assistantPanel.setOnPageShown(page -> {
            Screen s = screenFor(page);
            if (s != null && navigator.isShowing(assistantPanel)) navigator.sync(s);
        });
        navigator.onShow(nav::select); // by the Screen itself: the item's ref carries it

        menus = new MenuBarFactory(ctx);
        header = buildHeader();
        buildSidebar();

        add(header, BorderLayout.NORTH);
        add(nav, BorderLayout.WEST);
        add(content, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) {
                String principal = ctx.session().getPrincipalID();
                boolean admin = isSuperAdmin();
                header.setSubject(principal, admin ? "super-admin" : null);
                nav.setSectionVisible(SECTION_ADMIN, admin);
                assistantPanel.reloadProviders();
                assistantPanel.refreshHistory();
                assistantPanel.refreshSkills();
                navigator.show(Screen.SCAN);
            } else {
                // the frame swaps this shell out for the unlock screen; the next subject must
                // not see anything of the previous one when it is swapped back in
                header.clearSubject();
                assistantPanel.refreshHistory();
                assistantPanel.refreshSkills();
                assistantPanel.clearProviders();
                assistantPanel.resetPanel();
                navigator.show(Screen.SCAN);
            }
        });

        navigator.show(Screen.SCAN);
    }

    /** The menu bar that goes with this shell (File / View / Help); the frame installs it while signed in. */
    public JMenuBar menuBar() {
        return menus.buildMenu();
    }

    /** The scanner pages; for hosts that feed it a report (renders, tests). */
    public ScanPanel scanPanel() {
        return scanPanel;
    }

    private boolean isSuperAdmin() {
        try {
            String guid = ctx.session().getSubjectGUID();
            return guid != null && ctx.session().getDomainSecurityManager().isSuperAdminSubject(guid);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The sidebar screen of an assistant page, null for the job queue (not offered); package-private for {@code ScreenLabelsTest}. */
    static Screen screenFor(AssistantPanel.Page page) {
        return switch (page) {
            case CHAT -> Screen.CHAT;
            case CAPTURE -> Screen.CAPTURE;
            case SKILLS -> Screen.SKILLS;
            case PROVIDERS -> Screen.PROVIDERS;
            case QUEUE -> null;
        };
    }

    private HeaderBar buildHeader() {
        HeaderBar h = new HeaderBar(IconUtil.svgIcon("io/xlogistx/gui/icons/shield.svg", 20, UITokens.accent()), "NoSneak");
        // The chip names the vault directory; the tooltip says what is inside it, in the About
        // card's words (2026-10-27), since the chip itself has room for one line.
        File store = AppPrefs.storeLocation();
        h.setStatus(IconUtil.svgIcon("io/xlogistx/gui/icons/lock.svg", 14, UITokens.muted()),
                (store != null ? store.getAbsolutePath() : "store") + " · vault open",
                MenuBarFactory.STORE_NOTE + " Settings > Backup saves a copy.");
        JButton signOut = new JButton("Sign out", IconUtil.svgIcon("io/xlogistx/gui/icons/logout.svg", 16, UITokens.text()));
        signOut.putClientProperty("JButton.buttonType", "toolBarButton");
        signOut.addActionListener(_ -> {
            int ok = JOptionPane.showConfirmDialog(this, "Sign out of NoSneak?", "Sign out",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) ctx.session().logout();
        });
        h.addAction(signOut);
        return h;
    }

    private void buildSidebar() {
        nav.section("scan", "Scan");
        item(Screen.SCAN, "scan");
        item(Screen.SCAN_HISTORY, "clock");
        item(Screen.PROBES, "flask");

        nav.section("assistant", "Assistant");
        item(Screen.CHAT, "chat");
        item(Screen.CAPTURE, "capture");
        item(Screen.SKILLS, "book");
        item(Screen.PROVIDERS, "plug");

        nav.section("account", "Account");
        item(Screen.PROFILE, "user");
        item(Screen.API_KEYS, "key");
        item(Screen.SETTINGS, "settings");

        nav.section(SECTION_ADMIN, "Admin");
        item(Screen.ACL, "shield");
        nav.setSectionVisible(SECTION_ADMIN, false);

        nav.onSelect(key -> navigator.show(Screen.valueOf(key)));

        // Help opens the page-by-page description; the version line is the About entry (2026-10-27),
        // so the Java / platform / store facts live in the About card instead of the sidebar.
        nav.footerAction(icon("help"), "Help", menus::showDescription);
        JButton version = UITokens.link(new JButton(NoSneakMain.VERSION.getName() + " " + NoSneakMain.VERSION.version()));
        version.setFont(UITokens.mono(-2f));
        version.setForeground(UITokens.muted());
        version.setHorizontalAlignment(SwingConstants.LEFT);
        version.setBorder(BorderFactory.createEmptyBorder(6, 12, 2, 12));
        version.setToolTipText("About " + NoSneakMain.VERSION.getName() + ": version, Java, platform, store");
        version.addActionListener(_ -> menus.showAbout());
        nav.footer(version);
    }

    /**
     * A sidebar item for a screen (2026-10-27): a {@code ComponentRef} over the constant, so its
     * name is the key, its display name the text and its description the tooltip.
     */
    private void item(Screen screen, String iconName) {
        nav.item(screen, icon(iconName));
    }

    private static Icon icon(String name) {
        return IconUtil.svgIcon("io/xlogistx/gui/icons/" + name + ".svg", 16, UITokens.text());
    }

    /**
     * The status bar (2026-10-27): who is signed in on the left, the MAC vendor list's state on
     * the right in the Settings page's own words ({@link SubjectPanel#syncStatusText}) — the one
     * piece of session state the header and the pages do not already show. It reads "loading…"
     * from sign-in until {@link Session#onMacVendorsChange} says the table is filled (the login
     * screen loads it before the shell appears, so the subject rarely sees that), and follows
     * every sync from Settings. The old static "Ready" said nothing.
     */
    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITokens.border()),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        footer.setBackground(UITokens.surface());

        JLabel session = new JLabel("Signed out");
        JLabel vendors = new JLabel(" ");
        session.setForeground(UITokens.muted());
        vendors.setForeground(UITokens.muted());
        session.setFont(UITokens.font(Font.PLAIN, -1f));
        vendors.setFont(UITokens.font(Font.PLAIN, -1f));
        vendors.setToolTipText("The Wireshark manufacturer list that names each host's vendor in scan reports. Settings > Sync refreshes it.");

        Runnable refreshVendors = () -> {
            if (!ctx.session().isAuthenticated()) {
                vendors.setText(" ");
                return;
            }
            if (!ctx.session().macVendorsLoaded()) {
                vendors.setText("MAC vendors: loading…");
                return;
            }
            BackgroundTask.run(this, null, () -> ctx.session().macVendorStatus(),
                    status -> vendors.setText("MAC vendors: " + SubjectPanel.syncStatusText(status)));
        };
        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) {
                session.setText("Signed in as " + ctx.session().getPrincipalID());
            } else {
                session.setText("Signed out");
            }
            refreshVendors.run();
        });
        ctx.session().onMacVendorsChange(_ -> SwingUtilities.invokeLater(refreshVendors));

        footer.add(session, BorderLayout.WEST);
        footer.add(vendors, BorderLayout.EAST);

        return footer;
    }
}
