package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * tls-upgrade (2026-10-26) — secure the current connection in place with a JSSE TLS handshake
 * (RSA-capable, trust-all), after the plaintext exchange the protocol requires first: the
 * connection must have been opened by a {@code connect} with {@code upgradable: true}. On
 * success the context is in secure mode, so the following {@code send}/{@code expect} exchange
 * application data through the TLS session, and the result records
 * {@code STARTTLS_UPGRADED} with the negotiated version and cipher. The bundled
 * {@code postgres-tls} is the example: SSLRequest, {@code S}, then this, then the StartupMessage
 * and the server version over TLS. Fires {@code connected}, {@code error}, or {@code timeout}.
 */
public class TLSUpgradeAction implements Action {

    @Override
    public String name() {
        return "tls-upgrade";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.upgradeSecureConnection();
    }
}
