package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.nosneak.app.ui.AppShell;
import io.xlogistx.nosneak.app.ui.DataStoreSetupPanel;
import io.xlogistx.nosneak.app.ui.MenuBarFactory;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.app.AppVersionDAO;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.function.Consumer;

public class Main {

    public final static AppVersionDAO VERSION = new AppVersionDAO("NOSNEAK::1.0.0");
    /** The H2 database name inside the installation directory; see {@link NoSneakStore}. */
    public static final String dbName = NoSneakStore.DB_NAME;

    /**
     * Launch parameters: {@code ds.location=<dir>} and {@code ds.store-password=<vault password>}
     * open an existing installation directly ({@link NoSneakStore#open}); without both, the
     * setup screen asks for them (and creates the vault and the database on a first run).
     * Passing the vault password on the command line exposes it (process list, shell history,
     * run configurations): a development convenience, the setup screen is the normal path.
     */
    public static void main(String... args) {

        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String location = params.stringValue("ds.location", true);
        String storePassword = params.stringValue("ds.store-password", true);

        ShiroDSDomainSecurityManager dsm = null;
        if (!SUS.isEmpty(location) && storePassword != null) {
            try {
                dsm = NoSneakStore.open(location, storePassword.toCharArray());
            } catch (Exception e) {
                System.err.println("Could not open the no-sneak store at " + location + ": " + e.getMessage());
                System.exit(2);
                return;
            }
        }
        final ShiroDSDomainSecurityManager domainSecurityManager = dsm;

        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> {
            if (domainSecurityManager != null) {
                launchApp(domainSecurityManager);
            } else {
                showSetup(Main::launchApp);
            }
        });
    }

    public static class AppFrame extends JFrame {

        public AppFrame(ShiroDSDomainSecurityManager domainSecurityManager) {
            setTitle("NoSneak");
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            //setSize(800, 600);
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            int width = (int) (screenSize.width * 0.6);
            int height = (int) (screenSize.height * 0.7);
            setSize(width, height);
            setLocationRelativeTo(null);

            AppContext ctx = new AppContext(domainSecurityManager);

            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    ctx.session().closeNio();
                    ctx.session().logout(); // ends the Shiro subject before the store goes
                    domainSecurityManager.getDataStore().close();
                }
            });

            JMenuBar menuBar = new MenuBarFactory(ctx).buildMenu();
            menuBar.setVisible(false);
            setJMenuBar(menuBar);

            ctx.session().onAuthChange(e -> menuBar.setVisible((boolean) e.getNewValue()));

            setContentPane(new AppShell(ctx));
        }
    }

    /**
     * The manager over a store that is already open with its controller and key maker (see
     * {@link NoSneakStore#openStore}): built and {@link NoSneakStore#bootstrap bootstrapped}.
     * {@code ShiroDSDomainSecurityManager} replaced {@code DomainSecurityManagerDefault} (user,
     * 2026-10-05); it registers {@code CIPassword} and {@code SubjectAPIKey} itself.
     */
    public static ShiroDSDomainSecurityManager createDomainSecManager(APIDataStore<?, ?> dataStore) {
        OPSecUtil.singleton();
        return NoSneakStore.bootstrap(new ShiroDSDomainSecurityManager(dataStore));
    }

    public static void launchApp(ShiroDSDomainSecurityManager domainSecurityManager) {
        new AppFrame(domainSecurityManager).setVisible(true);
    }

    public static void showSetup(Consumer<ShiroDSDomainSecurityManager> onComplete) {
        JFrame f = new JFrame("NoSneak - Setup");
        f.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        f.setSize(560, 520);
        f.setLocationRelativeTo(null);
        f.setContentPane(new DataStoreSetupPanel(
                (location, vaultPassword, user, password, encPassword) ->
                        NoSneakStore.vaultExists(location)
                                ? NoSneakStore.open(location, vaultPassword)
                                : NoSneakStore.create(location, vaultPassword, user, password, encPassword),
                dsm -> {
                    f.dispose();
                    onComplete.accept(dsm);
                }));
        f.setVisible(true);
    }
}
