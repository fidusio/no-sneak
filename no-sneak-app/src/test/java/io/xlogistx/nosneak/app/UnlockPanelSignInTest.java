package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.UnlockPanel;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.io.File;
import java.util.UUID;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The launch-parameter sign-in ({@code subject=} + {@code password=}, 2026-10-25) goes through
 * {@link UnlockPanel#signIn}, the same path as typing on the sign-in step, against a real
 * encrypted store: the right password authenticates the session, a wrong one leaves it signed
 * out with the reason inline and the username kept.
 */
public class UnlockPanelSignInTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    public void launchCredentialsSignInThroughTheUnlockPanel() throws Exception {
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        ShiroDSDomainSecurityManager dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(), firstRun);
        AppContext ctx = new AppContext(dsm);
        try {
            UnlockPanel[] panel = new UnlockPanel[1];
            SwingUtilities.invokeAndWait(() -> {
                panel[0] = new UnlockPanel(NoSneakStore::openOrCreate, d -> {
                });
                panel[0].bindSession(ctx.session());
                panel[0].markStoreOpened(dir.getPath());
            });
            assertTrue(panel[0].isStoreOpen());

            // wrong password: refused, the reason shown inline, nothing authenticated
            SwingUtilities.invokeAndWait(() -> panel[0].signIn(OPERATOR, "not-the-password".toCharArray()));
            await(() -> !onEDT(panel[0]::getSignMessage).isEmpty() && !onEDT(panel[0]::getSignMessage).endsWith("\u2026"));
            assertFalse(ctx.session().isAuthenticated(), "a refused login must not authenticate");
            String refusal = onEDT(panel[0]::getSignMessage);
            assertFalse(refusal.isEmpty(), "the refusal is shown inline");

            // right password: authenticated, as the Sign in button would
            SwingUtilities.invokeAndWait(() -> panel[0].signIn(OPERATOR, OPERATOR_PWD.toCharArray()));
            await(ctx.session()::isAuthenticated);
            assertTrue(ctx.session().isAuthenticated());
        } finally {
            if (ctx.session().isAuthenticated()) ctx.session().logout();
            dsm.getDataStore().close();
        }
    }

    private static <T> T onEDT(java.util.concurrent.Callable<T> work) {
        try {
            java.util.concurrent.atomic.AtomicReference<T> out = new java.util.concurrent.atomic.AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    out.set(work.call());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            return out.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** The sign-in runs on a worker; wait for its outcome, at most 20 s. */
    private static void await(BooleanSupplier done) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 20_000;
        while (!done.getAsBoolean()) {
            assertTrue(System.currentTimeMillis() < deadline, "timed out waiting for the sign-in worker");
            Thread.sleep(50);
        }
    }
}
