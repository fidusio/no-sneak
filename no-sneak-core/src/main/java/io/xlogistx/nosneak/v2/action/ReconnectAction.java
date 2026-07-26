package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * reconnect — close the current channel and open a fresh one (to {@code port}, else the
 * target port) while the engine and accumulated result persist. This is how a probe uses
 * multiple connections. Fires {@code connected}, {@code error}, or {@code timeout}.
 */
public class ReconnectAction implements Action {

    @Override
    public String name() {
        return "reconnect";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.reconnect(context.effectivePort(state.getPort()));
    }
}
