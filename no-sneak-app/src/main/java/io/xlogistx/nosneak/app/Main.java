package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.datastore.h2p.H2PDSCreator;
import io.xlogistx.datastore.h2p.H2PUtil;
import io.xlogistx.nosneak.app.mock.AppShell;
import io.xlogistx.nosneak.app.mock.DataStoreSetupPanel;
import io.xlogistx.nosneak.app.mock.MenuBarFactory;
import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.ParamUtil;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

public class Main {

    public static final String dbName = "no-sneak";

    static void main(String... args) {

        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String dsUser = params.stringValue("ds.user", true);
        String dsPassword = params.stringValue("ds.password", true);
        String dsEncPassword = params.stringValue("ds.enc-password", true);
        String dsLocation = params.stringValue("ds.location", true);

        DomainSecurityManager dsm = null;
        if (dsUser != null && dsPassword != null && dsEncPassword != null && dsLocation != null) {
            APIDataStore<?, ?> dataStore = createDataStore(dsUser, dsPassword, dsEncPassword, dsLocation);
            dataStore.connect();
            dsm = createDomainSecManager(dataStore);
        }
        final DomainSecurityManager domainSecurityManager = dsm;

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

        public AppFrame(DomainSecurityManager domainSecurityManager) {
            setTitle("NoSneak");
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            setSize(800, 600);
            setLocationRelativeTo(null);

            AppContext ctx = new AppContext(domainSecurityManager);

            JMenuBar menuBar = new MenuBarFactory().buildMenu(ctx);
            menuBar.setVisible(false);
            setJMenuBar(menuBar);

            ctx.session().onAuthChange(e -> menuBar.setVisible((boolean) e.getNewValue()));

            setContentPane(new AppShell(ctx));
        }
    }

    public static DomainSecurityManager createDomainSecManager(APIDataStore<?, ?> dataStore) {
        OPSecUtil.singleton();

        return new DomainSecurityManagerDefault()
                .setDataStore(dataStore)
                .addCredentialType(CIPassword.class)
                .addCredentialType(SubjectAPIKey.class);
    }

    public static void launchApp(DomainSecurityManager domainSecurityManager) {
        new AppFrame(domainSecurityManager).setVisible(true);
    }

    public static APIDataStore<?, ?> createDataStore(String username, String password, String encPassword, String path) {
        String jdbcURL = H2PUtil.defaultH2JdbcURL(path, dbName);

        return new H2PDSCreator().createAPI(null, H2PDSCreator.toAPIConfigInfo(jdbcURL, username, password, encPassword));
    }

    public static void showSetup(Consumer<DomainSecurityManager> onComplete) {
        JFrame f = new JFrame("NoSneak - Setup");
        f.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        f.setSize(520, 460);
        f.setLocationRelativeTo(null);
        f.setContentPane(new DataStoreSetupPanel(
                (location, user, password, encPassword) -> {
                    APIDataStore<?, ?> dataStore = createDataStore(user, password, encPassword, location);
                    dataStore.connect();
                    return createDomainSecManager(dataStore);
                },
                dsm -> {
                    f.dispose();
                    onComplete.accept(dsm);
                }));
        f.setVisible(true);
    }
}
