package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * tls-connect — open a fresh channel to the target (or an alternate {@code port})
 * and perform a JSSE TLS handshake (RSA-capable, trust-all). On success the session
 * is in secure mode, so the following {@code send}/{@code expect} actions exchange
 * application data <em>through</em> the established TLS session (e.g. an HTTPS
 * {@code GET} and its {@code Server:} response header). Fires {@code connected},
 * {@code error}, or {@code timeout}.
 */
public class TLSConnectAction implements Action {

    @Override
    public String name() {
        return "tls-connect";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.openSecureConnection(session.effectivePort(state.getPort()));
    }
}
