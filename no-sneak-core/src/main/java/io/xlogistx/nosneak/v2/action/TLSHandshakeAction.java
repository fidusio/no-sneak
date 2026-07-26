package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * tls-handshake — perform a Bouncy Castle TLS handshake on the current already-open
 * channel (a mid-session upgrade if reached after {@code starttls}). {@code mode:"pqc"}
 * (default) advertises ML-KEM hybrids + classical; {@code mode:"jsse"}/{@code "classical"}
 * advertises only classical groups. Fires {@code handshaked}, {@code error}, or
 * {@code timeout}.
 */
public class TLSHandshakeAction implements Action {

    @Override
    public String name() {
        return "tls-handshake";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        String mode = state.getMode();
        boolean classicalOnly = "jsse".equalsIgnoreCase(mode) || "classical".equalsIgnoreCase(mode);
        context.startTlsHandshake(context.isUpgrade(), classicalOnly);
    }
}
