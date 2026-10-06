package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;

/**
 * Per-application service locator. Holds the single shared {@link Session} and
 * {@link Navigator} so screens and the menu bar can reach them without wiring
 * dependencies through every constructor.
 */
public class AppContext {
    private final Session session;
    private Navigator navigator;

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
}
