package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.scan.model.ProbeDefinitionLoader;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.io.File;
import java.lang.reflect.Field;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The symptom of the first live theme switch (2026-11-02, the maintainer: "when I change the theme
 * the probe library and history disappear"): a panel built while a subject is already signed in
 * has never heard the authenticated event, on which it loads the subject's rows, so it shows
 * nothing. {@code Session.replayAuthenticated} fires the event again and the panel fills, exactly
 * as on a login. Through a real store, the {@code SessionProbeSeedTest} pattern.
 */
class ThemeSwitchReloadTest {

    private static final String OPERATOR = "operator.local", OPERATOR_PWD = "Operat0r-pass!";
    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        System.setProperty("java.awt.headless", "true");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(),
                new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null));
    }

    @AfterAll
    static void closeStore() {
        if (dsm != null) dsm.getDataStore().close();
    }

    @Test
    void aPanelBuiltAfterTheLoginFillsOnTheReplay() throws Exception {
        AppContext ctx = new AppContext(dsm);
        ctx.session().loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray()); // seeds the 18 probes
        try {
            ScanPanel[] holder = new ScanPanel[1];
            SwingUtilities.invokeAndWait(() -> holder[0] = new ScanPanel(ctx, (t, n, c) -> {}));
            ScanPanel panel = holder[0];
            assertEquals(0, probes(panel).size(), "built after the login: nothing loaded, the symptom");

            SwingUtilities.invokeAndWait(() -> ctx.session().replayAuthenticated());
            int expected = ProbeDefinitionLoader.BUNDLED.length;
            long deadline = System.currentTimeMillis() + 15_000;
            while (probes(panel).size() != expected && System.currentTimeMillis() < deadline) Thread.sleep(50);
            assertEquals(expected, probes(panel).size(), "the replay loads the subject's rows as a login does");
        } finally {
            ctx.session().logout();
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Object> probes(ScanPanel panel) throws Exception {
        Field f = ScanPanel.class.getDeclaredField("probes");
        f.setAccessible(true);
        Object[] out = new Object[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                out[0] = f.get(panel);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        });
        return (List<Object>) out[0];
    }
}
