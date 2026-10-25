package io.xlogistx.nosneak.app.ui;


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

    private static final String CARD_SCAN = "scan";
    private static final String CARD_ASSISTANT = "assistant";
    private static final String CARD_ACCOUNT = "account";
    private static final String CARD_ADMIN = "admin";
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

        content.add(scanPanel, CARD_SCAN);
        content.add(assistantPanel, CARD_ASSISTANT);
        content.add(subjectPanel, CARD_ACCOUNT);
        content.add(managerPanel, CARD_ADMIN);

        navigator = new Navigator(cards, content);
        navigator.register(Screen.SCAN_NEW, CARD_SCAN, () -> scanPanel.show(ScanPanel.SECTION_SCAN));
        navigator.register(Screen.SCAN_HISTORY, CARD_SCAN, () -> scanPanel.show(ScanPanel.SECTION_HISTORY));
        navigator.register(Screen.PROBES, CARD_SCAN, () -> scanPanel.show(ScanPanel.SECTION_PROBES));
        navigator.register(Screen.CHAT, CARD_ASSISTANT, () -> assistantPanel.showPage(AssistantPanel.Page.CHAT));
        navigator.register(Screen.CHATS, CARD_ASSISTANT, () -> assistantPanel.showPage(AssistantPanel.Page.HISTORY));
        navigator.register(Screen.CAPTURE, CARD_ASSISTANT, () -> assistantPanel.showPage(AssistantPanel.Page.CAPTURE));
        navigator.register(Screen.SKILLS, CARD_ASSISTANT, () -> assistantPanel.showPage(AssistantPanel.Page.SKILLS));
        navigator.register(Screen.PROVIDERS, CARD_ASSISTANT, () -> assistantPanel.showPage(AssistantPanel.Page.PROVIDERS));
        navigator.register(Screen.PROFILE, CARD_ACCOUNT, () -> subjectPanel.show(SubjectPanel.SECTION_PROFILE));
        navigator.register(Screen.API_KEYS, CARD_ACCOUNT, () -> subjectPanel.show(SubjectPanel.SECTION_CREDENTIALS));
        navigator.register(Screen.BACKUP, CARD_ACCOUNT, () -> subjectPanel.show(SubjectPanel.SECTION_BACKUP));
        navigator.register(Screen.ACL, CARD_ADMIN, null);
        ctx.setNavigator(navigator);

        // the assistant moves itself (a chat opened from history, a report sent from the scanner):
        // the card is already the assistant's or about to be, so only the sidebar needs telling
        assistantPanel.setOnPageShown(page -> {
            Screen s = screenFor(page);
            if (s != null && isShowing(CARD_ASSISTANT)) navigator.sync(s);
        });
        navigator.onShow(s -> nav.select(s.name()));

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
                navigator.show(Screen.SCAN_NEW);
            } else {
                // the frame swaps this shell out for the unlock screen; the next subject must
                // not see anything of the previous one when it is swapped back in
                header.clearSubject();
                assistantPanel.refreshHistory();
                assistantPanel.refreshSkills();
                assistantPanel.clearProviders();
                assistantPanel.resetPanel();
                navigator.show(Screen.SCAN_NEW);
            }
        });

        navigator.show(Screen.SCAN_NEW);
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

    private boolean isShowing(String card) {
        for (Component c : content.getComponents()) {
            if (c.isVisible()) {
                if (c == assistantPanel) return CARD_ASSISTANT.equals(card);
                if (c == scanPanel) return CARD_SCAN.equals(card);
                if (c == subjectPanel) return CARD_ACCOUNT.equals(card);
                if (c == managerPanel) return CARD_ADMIN.equals(card);
            }
        }
        return false;
    }

    private static Screen screenFor(AssistantPanel.Page page) {
        return switch (page) {
            case CHAT -> Screen.CHAT;
            case HISTORY -> Screen.CHATS;
            case CAPTURE -> Screen.CAPTURE;
            case SKILLS -> Screen.SKILLS;
            case PROVIDERS -> Screen.PROVIDERS;
            case QUEUE -> null;
        };
    }

    private HeaderBar buildHeader() {
        HeaderBar h = new HeaderBar(IconUtil.svgIcon("io/xlogistx/gui/icons/shield.svg", 20, UITokens.accent()), "NoSneak");
        File store = AppPrefs.storeLocation();
        h.setStatus(IconUtil.svgIcon("io/xlogistx/gui/icons/lock.svg", 14, UITokens.muted()),
                (store != null ? store.getAbsolutePath() : "store") + " · vault open");
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
        nav.item(Screen.SCAN_NEW.name(), icon("scan"), "New scan");
        nav.item(Screen.SCAN_HISTORY.name(), icon("clock"), "History");
        nav.item(Screen.PROBES.name(), icon("flask"), "Probe library");

        nav.section("assistant", "Assistant");
        nav.item(Screen.CHAT.name(), icon("chat"), "Chat");
        nav.item(Screen.CHATS.name(), icon("list"), "Chats");
        nav.item(Screen.CAPTURE.name(), icon("capture"), "Capture");
        nav.item(Screen.SKILLS.name(), icon("book"), "Skills");
        nav.item(Screen.PROVIDERS.name(), icon("plug"), "Providers");

        nav.section("account", "Account");
        nav.item(Screen.PROFILE.name(), icon("user"), "Profile");
        nav.item(Screen.API_KEYS.name(), icon("key"), "API keys");
        nav.item(Screen.BACKUP.name(), icon("archive"), "Backup");

        nav.section(SECTION_ADMIN, "Admin");
        nav.item(Screen.ACL.name(), icon("shield"), "Access control");
        nav.setSectionVisible(SECTION_ADMIN, false);

        nav.onSelect(key -> navigator.show(Screen.valueOf(key)));

        nav.footerAction(icon("help"), "Help and about", menus::showDescription);
        JLabel version = new JLabel(NoSneakMain.VERSION.getName() + " " + NoSneakMain.VERSION.version()
                + " · Java " + System.getProperty("java.version"));
        version.setFont(UITokens.mono(-2f));
        version.setForeground(UITokens.muted());
        version.setBorder(BorderFactory.createEmptyBorder(6, 12, 0, 12));
        nav.footer(version);
    }

    private static Icon icon(String name) {
        return IconUtil.svgIcon("io/xlogistx/gui/icons/" + name + ".svg", 16, UITokens.text());
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITokens.border()),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        footer.setBackground(UITokens.surface());

        JLabel session = new JLabel("signed out");
        JLabel status = new JLabel("Ready");
        session.setForeground(UITokens.muted());
        status.setForeground(UITokens.muted());
        session.setFont(UITokens.font(Font.PLAIN, -1f));
        status.setFont(UITokens.font(Font.PLAIN, -1f));

        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) {
                session.setText("subject: " + ctx.session().getPrincipalID());
            } else {
                session.setText("signed out");
            }
        });

        footer.add(session, BorderLayout.WEST);
        footer.add(status, BorderLayout.EAST);

        return footer;
    }
}
