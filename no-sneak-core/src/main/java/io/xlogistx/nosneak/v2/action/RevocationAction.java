package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * revocation-check — report certificate revocation status from the handshake-stapled OCSP
 * response (instant, no network); UNKNOWN/NOT_CHECKED when nothing was stapled. Requires a
 * prior {@code tls-handshake}. Fires {@code done}.
 */
public class RevocationAction implements Action {

    @Override
    public String name() {
        return "revocation-check";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.checkRevocation();
        context.fire("done");
    }
}
