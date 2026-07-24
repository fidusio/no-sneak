package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * reconnect — close the current channel, increment the session connection
 * counter, and open a fresh connection (to the target or an alternate
 * {@code port}) while the interpreter and accumulated result persist. This is
 * the primitive that makes multi-connection probes possible (e.g. connect once
 * to read the default, reconnect to test PQC-readiness). Fires the same
 * outcomes as {@code connect}: {@code connected}/{@code error}/{@code timeout}.
 */
public class ReconnectAction implements Action {

    @Override
    public String name() {
        return "reconnect";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.reconnect(session.effectivePort(state.getPort()));
    }
}
