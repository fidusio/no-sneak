package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import com.openhtmltopdf.util.XRLog;
import io.xlogistx.datastore.h2p.H2PDataStore;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.ui.AppShell;
import io.xlogistx.nosneak.app.ui.UnlockPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
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

public class NoSneakMain {


    public final static AppVersion VERSION = new AppVersion("NOSNEAK::1.0.0");
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
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> launchApp(domainSecurityManager, openedLocation, launchSubject, launchPassword));
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

        private final UnlockPanel unlock;
        private ShiroDSDomainSecurityManager domainSecurityManager;
        private AppContext ctx;
        private AppShell shell;
        private JMenuBar menuBar;

        public AppFrame() {
            setTitle("NoSneak");
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
         */
        public void storeOpened(ShiroDSDomainSecurityManager dsm) {
            if (ctx != null) return;
            domainSecurityManager = dsm;
            ctx = new AppContext(dsm);
            shell = new AppShell(ctx);
            menuBar = shell.menuBar();
            unlock.bindSession(ctx.session());
            ctx.session().onAuthChange(e -> showSignedIn((boolean) e.getNewValue()));
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
     */
    public static ShiroDSDomainSecurityManager createDomainSecManager(APIDataStore<?, ?> dataStore) {
        OPSecUtil.singleton();
        return NoSneakStore.bootstrap(new ShiroDSDomainSecurityManager(dataStore));
    }

    /**
     * Shows the application window. With a manager (opened from launch parameters) the unlock
     * panel's first step is already done and the window opens on sign-in; without one it opens on
     * the open-store step.
     */
    public static void launchApp(ShiroDSDomainSecurityManager domainSecurityManager, String location) {
        launchApp(domainSecurityManager, location, null, null);
    }

    /**
     * As {@link #launchApp(ShiroDSDomainSecurityManager, String)}, and with a subject and password
     * (both non-null, store open) the sign-in step is run for them once the window is up
     * ({@link UnlockPanel#signIn}): success lands in the shell, a refusal stays on the sign-in step
     * with the reason inline. The password array is wiped by the panel.
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
