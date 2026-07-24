package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * pqc-check — classify the negotiated key exchange (PQC vs classical) via the
 * reused {@code OPSecUtil} helpers and record TLS/cert facts into the result,
 * then fire {@code done}.
 */
public class PQCCheckAction implements Action {

    @Override
    public String name() {
        return "pqc-check";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.recordPQC();
        session.fire("done");
    }
}
