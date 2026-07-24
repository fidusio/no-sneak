package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * tls-handshake — perform the TLS handshake on the CURRENT already-open channel
 * (a mid-session upgrade when reached after {@code starttls}). The state's
 * {@code mode} selects what the ClientHello advertises:
 * <ul>
 *   <li>{@code "pqc"} (default) — offer PQC hybrid groups (X25519MLKEM768, …) plus classical.</li>
 *   <li>{@code "jsse"} / {@code "classical"} — a fully classical handshake: only classical
 *       groups, no PQC hybrids.</li>
 * </ul>
 * Fires {@code handshaked} on success, {@code error}/{@code timeout} on failure.
 * Upgrade-vs-direct is tracked by the session (set by the {@code starttls} action).
 */
public class TLSHandshakeAction implements Action {

    @Override
    public String name() {
        return "tls-handshake";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        String mode = state.getMode();
        boolean classicalOnly = "jsse".equalsIgnoreCase(mode) || "classical".equalsIgnoreCase(mode);
        session.startTlsHandshake(session.isUpgrade(), classicalOnly);
    }
}
