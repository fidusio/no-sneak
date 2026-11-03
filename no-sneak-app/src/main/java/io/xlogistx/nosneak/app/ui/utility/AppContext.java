package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;

import java.util.function.Consumer;

/**
 * Per-application service locator. Holds the single shared {@link Session} and
 * {@link Navigator} so screens and the menu bar can reach them without wiring
 * dependencies through every constructor.
 */
public class AppContext {
    private final Session session;
    private Navigator navigator;
    private Consumer<NSAppUtil.Theme> themeSwitcher = _ -> {};

    public AppContext(ShiroDSDomainSecurityManager domainSecurityManager) {
        session = new Session(domainSecurityManager);
    }

    /**
     * @return the shared authentication/session state.
     */
    public Session session() {
        return session;
    }

    /**
     * @return the shared top-level screen navigator.
     */
    public Navigator nav() {
        return navigator;
    }

    /**
     * Registers the navigator. Called once by {@code AppShell} after the
     * CardLayout host exists.
     *
     * @param n the navigator to share
     */
    public void setNavigator(Navigator n) {
        this.navigator = n;
    }

    /**
     * Registers how a theme chosen on the Settings page is applied (2026-11-02): the frame
     * rebuilds the pages on this context, so the shell never needs to know the frame.
     */
    public void setThemeSwitcher(Consumer<NSAppUtil.Theme> switcher) {
        this.themeSwitcher = switcher != null ? switcher : _ -> {};
    }

    /** Applies a theme chosen on the Settings page through the registered switcher. */
    public void switchTheme(NSAppUtil.Theme theme) {
        themeSwitcher.accept(theme);
    }
}
