package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * revocation-check — report certificate revocation status: from the handshake-stapled OCSP
 * response when one was stapled (instant, no network); otherwise an active OCSP request to
 * the leaf's AIA responder and, failing that, its CRL — both non-blocking over the probe's own
 * {@code NIOSocket}, bounded by the state's {@code revocationTimeoutMs} (default 5 s), soft-fail
 * to {@code UNKNOWN}. Requires a prior {@code tls-handshake}. Asynchronous: the context fires
 * {@code done} when the answer is in.
 */
public class RevocationAction implements Action {

    @Override
    public String name() {
        return "revocation-check";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.checkRevocation(state); // fires "done" itself, possibly after a network round trip
    }
}
