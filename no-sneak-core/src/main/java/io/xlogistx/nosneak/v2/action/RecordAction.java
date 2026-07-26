package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * record — merge the state's {@code note} into the result, then fire {@code done}. Facts
 * already gathered (captured version, TLS state, …) are preserved; a plain {@code record}
 * simply annotates the branch taken.
 */
public class RecordAction implements Action {

    @Override
    public String name() {
        return "record";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.recordNote(state.getNote());
        context.fire("done");
    }
}
