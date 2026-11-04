package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import com.openhtmltopdf.util.XRLog;
import io.xlogistx.datastore.h2p.H2PDataStore;
import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.UIFontSize;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.ui.AppShell;
import io.xlogistx.nosneak.app.ui.UnlockPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.app.AppVersion;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;

public class NoSneakMain {


    public final static AppVersion VERSION = new AppVersion("NOSNEAK::1.1.6");
    /** The H2 database name inside the installation directory; see {@link NoSneakStore}. */
    public static final String dbName = NoSneakStore.DB_NAME;

    /**
     * Launch parameters: {@code ds.location=<dir>} and {@code ds.store-password=<vault password>}
     * open an existing installation directly ({@link NoSneakStore#open}: vault + {@code shiro.ini}
     * in that directory) and the window starts on the sign-in step; without both, the window
     * starts on the open-store step of the {@link UnlockPanel} (which on a first run creates the
     * vault, the database, the operator account and the INI through {@code H2PSetup}).
     * With the store opened that way, {@code subject=<username>} and {@code password=<password>}
     * (2026-10-25; {@code username=} is accepted for {@code subject=}) also sign that subject in,
     * exactly as typing them on the sign-in step would: a refused login leaves the window on the
     * sign-in step with the reason inline and the username kept.
     * Passing the vault password or a subject's password on the command line exposes them
     * (process list, shell history, run configurations): a development convenience, the unlock
     * screen is the normal path.
     *
     * @param args {@code name=value} launch parameters: {@code ds.location}, {@code ds.store-password},
     *             {@code subject} (or {@code username}), {@code password}; none for the unlock screen
     */
    public static void main(String... args) {

        XRLog.setLoggingEnabled(false);
        // Must run before any LoggerFactory.getLogger() call anywhere in the JVM
        System.setProperty("org.slf4j.simpleLogger.log.com.zaxxer.hikari", "warn");
        H2PDataStore.log.setEnabled(false);
        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String location = params.stringValue("ds.location", true);
        String storePassword = params.stringValue("ds.store-password", true);
        String subject = params.stringValue("subject", true);
        if (SUS.isEmpty(subject)) subject = params.stringValue("username", true);
        String subjectPassword = params.stringValue("password", true);

        ShiroDSDomainSecurityManager dsm = null;
        if (!SUS.isEmpty(location) && storePassword != null) {
            try {
                dsm = NoSneakStore.open(location, storePassword.toCharArray());
                AppPrefs.storeLocation(location);
            } catch (Exception e) {
                System.err.println("Could not open the no-sneak store at " + location + ": " + e.getMessage());
                System.exit(2);
                return;
            }
        }
        final ShiroDSDomainSecurityManager domainSecurityManager = dsm;
        final String openedLocation = location;
        final String launchSubject = dsm != null && !SUS.isEmpty(subject) && subjectPassword != null ? subject : null;
        final char[] launchPassword = launchSubject != null ? subjectPassword.toCharArray() : null;
        if (dsm == null && (!SUS.isEmpty(subject) || subjectPassword != null)) {
            System.err.println("subject= / password= need ds.location= and ds.store-password=; ignored.");
        }

        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        installLookAndFeel(AppPrefs.theme());

        SwingUtilities.invokeLater(() -> {
            // the stored text size, applied before any window exists so the unlock screen opens at it;
            // every later change (the Settings page's control) is remembered through the listener
            UIFontSize.apply(AppPrefs.uiFontSize());
            UIFontSize.addListener(AppPrefs::uiFontSize);
            launchApp(domainSecurityManager, openedLocation, launchSubject, launchPassword);
        });
    }

    /** The size of the default font the app ships with, in points; {@code UIFontSize} scales from it. */
    public static final int DEFAULT_FONT_SIZE = 13;

    /**
     * Installs a theme (2026-11-02): FlatLaf's {@code setup} for it, then the Roboto default font
     * at {@link #DEFAULT_FONT_SIZE} — always that size, so {@code UIFontSize.getBase()} reads 13
     * and <i>Reset</i> on the Settings page returns to the look the app ships with; the stored
     * text size is applied after it, and stays in force across a switch (the scaled fonts live
     * in the user layer of {@code UIManager}, which a new look and feel does not clear). Used at
     * start and by {@link AppFrame#applyTheme}; the custom defaults source is registered once, in {@code main}.
     */
    public static void installLookAndFeel(NSAppUtil.Theme theme) {
        theme.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, DEFAULT_FONT_SIZE));
    }

    /**
     * The one application window. It starts on the {@link UnlockPanel}; when that panel's first
     * step opens the store, {@link #storeOpened} builds the {@link AppContext}, the menu bar and
     * the {@link AppShell} around the manager and binds the sign-in step to the session. The
     * session's {@code authenticated} event then swaps the content pane: the shell while a subject
     * is signed in, the unlock panel (at its sign-in step) otherwise. The store is opened once per
     * process and closed on window close only, not on logout.
     */
    public static class AppFrame extends JFrame {

        private UnlockPanel unlock;
        private ShiroDSDomainSecurityManager domainSecurityManager;
        private AppContext ctx;
        private AppShell shell;
        private JMenuBar menuBar;

        public AppFrame() {
            setTitle(NSAppUtil.MainWindow.WINDOW.getDisplayName());
            setName(NSAppUtil.MainWindow.WINDOW.getName());
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            //setSize(800, 600);
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            int width = (int) (screenSize.width * 0.6);
            int height = (int) (screenSize.height * 0.7);
            setSize(width, height);
            setLocationRelativeTo(null);
            setIconImages(IconUtil.windowIcons(IconUtil.ShieldIcon::new, Color.WHITE, UITokens.accent()));

            unlock = new UnlockPanel(NoSneakStore::openOrCreate, this::storeOpened);
            setContentPane(unlock);

            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    if (ctx != null) {
                        ctx.session().closeNio();
                        ctx.session().logout(); // ends the Shiro subject before the store goes
                    }
                    if (domainSecurityManager != null) {
                        domainSecurityManager.getDataStore().close();
                    }
                }
            });
        }

        /**
         * The store is open: build the application around it. Called on the EDT by the unlock
         * panel after a successful Open / Create, or by {@link #launchApp} for a store opened from
         * launch parameters. A second call is ignored: the store is fixed for the process.
         *
         * @param dsm the manager over the opened store, attached to its INI realm
         */
        public void storeOpened(ShiroDSDomainSecurityManager dsm) {
            if (ctx != null) return;
            domainSecurityManager = dsm;
            ctx = new AppContext(dsm);
            ctx.setThemeSwitcher(this::applyTheme);
            shell = new AppShell(ctx);
            menuBar = shell.menuBar();
            unlock.bindSession(ctx.session());
            ctx.session().onAuthChange(authListener);
        }

        private boolean macVendorWarningShown;

        /**
         * The frame's own ear on the session: login → load the MAC vendors, then show the shell;
         * logout → the unlock screen. A field so {@link #applyTheme} can register it again after
         * dropping the old shell's listeners.
         */
        private final java.beans.PropertyChangeListener authListener = e -> {
            if ((boolean) e.getNewValue()) loadMacVendorsThenShow();
            else showSignedIn(false);
        };

        /**
         * After a login (2026-10-25): fill the MAC vendor table from the store, downloading the
         * Wireshark list once when the store has none ({@link Session#loadMacVendors}), then show
         * the application. A download failure is shown once and the app starts without vendor
         * names; the next login tries again.
         */
        private void loadMacVendorsThenShow() {
            if (ctx.session().macVendorsLoaded()) {
                showSignedIn(true);
                return;
            }
            unlock.signInfo("Loading MAC vendors…");
            BackgroundTask.run(this, null, () -> {
                try {
                    ctx.session().loadMacVendors();
                    return null;
                } catch (IOException e) {
                    return e.getMessage() != null ? e.getMessage() : e.toString();
                }
            }, failure -> {
                if (failure != null && !macVendorWarningShown) {
                    macVendorWarningShown = true;
                    JOptionPane.showMessageDialog(this,
                            "The MAC vendor list could not be downloaded: " + failure
                                    + "\nScan reports will not name vendors until the next sign-in with a connection.",
                            "MAC vendors", JOptionPane.WARNING_MESSAGE);
                }
                showSignedIn(true);
            });
        }

        private void showSignedIn(boolean signedIn) {
            if (signedIn) {
                setJMenuBar(menuBar);
                setContentPane(shell);
            } else {
                setJMenuBar(null);
                unlock.resetForSignIn();
                setContentPane(unlock);
            }
            revalidate();
            repaint();
        }

        /**
         * A theme chosen on the Settings page (2026-11-02, {@code PLAN-appearance.md}): install
         * it, refresh the look and feel, and rebuild the pages on the same context and session —
         * the move {@link #showSignedIn} makes on login, because every panel keeps the token
         * colours it read when it was built. The old shell and unlock panel are dropped (the
         * fresh unlock panel is bound to the session and marked open, so a later sign-out lands
         * on its sign-in step as before); the store, the session and the MAC vendor table are
         * untouched. Settings is shown again. The Settings page refuses the switch while a scan
         * runs, so nothing in flight is lost here. The panels load the subject's rows on the
         * session's authenticated event, which the new shell never saw: the session drops the
         * old shell's listeners ({@code removeListeners}; this frame's own goes back on), the new
         * shell registers, and {@code replayAuthenticated} fires the event once more — the same
         * path as a login, which also shows the shell through {@link #loadMacVendorsThenShow}.
         */
        public void applyTheme(NSAppUtil.Theme theme) {
            installLookAndFeel(theme);
            FlatLaf.updateUI();
            Session session = ctx.session();
            session.removeListeners();
            session.onAuthChange(authListener);
            shell = new AppShell(ctx);
            menuBar = shell.menuBar();
            unlock = new UnlockPanel(NoSneakStore::openOrCreate, this::storeOpened);
            unlock.bindSession(session);
            java.io.File location = AppPrefs.storeLocation();
            unlock.markStoreOpened(location != null ? location.getPath() : null);
            session.replayAuthenticated();
            ctx.nav().show(NSAppUtil.Screen.SETTINGS);
        }

        public UnlockPanel getUnlockPanel() {
            return unlock;
        }
    }

    /**
     * A self-managed manager over a store that is already open with its controller and key maker
     * but was not set up by {@code H2PSetup} (see {@link NoSneakStore#secure}): built and
     * {@link NoSneakStore#bootstrap bootstrapped}. An installation on disk goes through
     * {@link NoSneakStore#open} instead, which attaches the manager to the INI realm.
     * {@code ShiroDSDomainSecurityManager} replaced {@code DomainSecurityManagerDefault} (user,
     * 2026-10-05); it registers {@code CIPassword} and {@code SubjectAPIKey} itself.
     *
     * @param dataStore the open store, configured with the Shiro controller and the key maker
     * @return the bootstrapped manager over it
     */
    public static ShiroDSDomainSecurityManager createDomainSecManager(APIDataStore<?, ?> dataStore) {
        OPSecUtil.singleton();
        return NoSneakStore.bootstrap(new ShiroDSDomainSecurityManager(dataStore));
    }

    /**
     * Shows the application window. With a manager (opened from launch parameters) the unlock
     * panel's first step is already done and the window opens on sign-in; without one it opens on
     * the open-store step.
     *
     * @param domainSecurityManager the manager of an installation opened from launch parameters, or null
     * @param location              that installation's directory, shown on the collapsed first step; null without a manager
     */
    public static void launchApp(ShiroDSDomainSecurityManager domainSecurityManager, String location) {
        launchApp(domainSecurityManager, location, null, null);
    }

    /**
     * As {@link #launchApp(ShiroDSDomainSecurityManager, String)}, and with a subject and password
     * (both non-null, store open) the sign-in step is run for them once the window is up
     * ({@link UnlockPanel#signIn}): success lands in the shell, a refusal stays on the sign-in step
     * with the reason inline. The password array is wiped by the panel.
     *
     * @param domainSecurityManager the manager of an installation opened from launch parameters, or null
     * @param location              that installation's directory; null without a manager
     * @param subject               the username to sign in once the window is up, or null
     * @param password              that subject's password, wiped by the panel; null with no subject
     */
    public static void launchApp(ShiroDSDomainSecurityManager domainSecurityManager, String location,
                                 String subject, char[] password) {
        AppFrame frame = new AppFrame();
        if (domainSecurityManager != null) {
            frame.storeOpened(domainSecurityManager);
            frame.getUnlockPanel().markStoreOpened(location);
        }
        frame.setVisible(true);
        if (domainSecurityManager != null && subject != null && password != null) {
            frame.getUnlockPanel().signIn(subject, password);
        }
    }
}
