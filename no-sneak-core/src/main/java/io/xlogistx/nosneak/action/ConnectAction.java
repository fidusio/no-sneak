package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * connect — open a new TCP connection to the target (or an alternate {@code port}).
 * Fires {@code connected}, {@code error}, or {@code timeout}.
 * <p>
 * With {@code upgradable: true} (2026-10-26) the connection is opened on the TLS-capable
 * channel, in plaintext, so a later {@code tls-upgrade} can secure it in place after the
 * protocol's own preamble (PostgreSQL's SSLRequest). The Bouncy Castle path ({@code tls-handshake})
 * is not available on such a connection; it is for application data over JSSE, like {@code tls-connect}.
 */
public class ConnectAction implements Action {

    @Override
    public String name() {
        return "connect";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        if (ProbeState.flag(state.getUpgradable(), false)) {
            context.openSecureConnection(context.effectivePort(state.getPort()), false);
        } else {
            context.openConnection(context.effectivePort(state.getPort()));
        }
    }
}
