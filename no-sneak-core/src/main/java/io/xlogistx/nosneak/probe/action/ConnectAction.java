package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * connect — open a new TCP connection to the target (or an alternate {@code port}).
 * Fires {@code connected}, {@code error}, or {@code timeout}.
 */
public class ConnectAction implements Action {

    @Override
    public String name() {
        return "connect";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.openConnection(session.effectivePort(state.getPort()));
    }
}
