package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * enumerate-versions — probe each candidate TLS version in parallel (via the fan-out
 * primitive), record the server-accepted set as {@code supported-protocol-versions}, then
 * fire {@code done} once all children join.
 */
public class EnumerateVersionsAction implements Action {

    @Override
    public String name() {
        return "enumerate-versions";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.enumerateVersions(); // fires "done" via the join barrier
    }
}
