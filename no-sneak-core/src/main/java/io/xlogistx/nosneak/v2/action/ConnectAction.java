package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

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
    public void execute(ProbeContext context, ProbeState state) {
        context.openConnection(context.effectivePort(state.getPort()));
    }
}
