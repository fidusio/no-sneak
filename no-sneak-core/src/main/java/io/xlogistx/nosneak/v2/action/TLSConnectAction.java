package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * tls-connect — open a fresh channel to the target (or an alternate {@code port}) and
 * perform a JSSE TLS handshake (RSA-capable, trust-all). On success the context is in
 * secure mode, so the following {@code send}/{@code expect} actions exchange application
 * data <em>through</em> the established TLS session (e.g. an HTTPS {@code GET} and its
 * {@code Server:} header). Fires {@code connected}, {@code error}, or {@code timeout}.
 */
public class TLSConnectAction implements Action {

    @Override
    public String name() {
        return "tls-connect";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.openSecureConnection(context.effectivePort(state.getPort()));
    }
}
