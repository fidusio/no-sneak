package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.datastore.XlogistxMongoDSCreator;
import io.xlogistx.datastore.XlogistxMongoDataStore;
import io.xlogistx.nosneak.app.mock.AppShell;
import io.xlogistx.nosneak.app.mock.MenuBarFactory;
import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectAPIKey;

import javax.swing.*;
import java.awt.*;

public class Main {
    static void main(String... args) {
        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> new AppFrame().setVisible(true));
    }

    public static class AppFrame extends JFrame {
        public static final String DB_URL = "mongodb://localhost:27017/xlog_datastore_test?replicaSet=rs0";

        public AppFrame() {
            setTitle("NoSneak");
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            setSize(800, 600);
            setLocationRelativeTo(null);


            AppContext ctx = new AppContext(createDomainSecManager());

            JMenuBar menuBar = new MenuBarFactory().buildMenu(ctx);
            menuBar.setVisible(false);
            setJMenuBar(menuBar);

            ctx.session().onAuthChange(e -> menuBar.setVisible((boolean) e.getNewValue()));

            setContentPane(new AppShell(ctx));
        }

        private static DomainSecurityManager createDomainSecManager() {
            XlogistxMongoDSCreator creator = new XlogistxMongoDSCreator();
            APIConfigInfo configInfo = creator.toAPIConfigInfo(DB_URL);

            XlogistxMongoDataStore mongoDataStore = new XlogistxMongoDataStore();
            mongoDataStore.setAPIConfigInfo(configInfo);
            OPSecUtil.singleton();

            return new DomainSecurityManagerDefault()
                    .setDataStore(mongoDataStore)
                    .addCredentialType(CIPassword.class)
                    .addCredentialType(SubjectAPIKey.class);
        }
    }
}
