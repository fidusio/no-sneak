package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * record — merge the state's {@code note} (e.g. {@code "no-starttls"}) into the
 * result, then fire {@code done}. Facts already gathered (TLS state, PQC status)
 * are preserved; a plain {@code record} simply annotates the branch taken.
 */
public class RecordAction implements Action {

    @Override
    public String name() {
        return "record";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.recordNote(state.getNote());
        session.fire("done");
    }
}
