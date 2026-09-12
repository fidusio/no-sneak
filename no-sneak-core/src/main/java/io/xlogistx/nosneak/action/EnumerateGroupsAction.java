package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * enumerate-groups — one TLS 1.3 handshake per candidate named group, each offering only that
 * group, in parallel via the fan-out primitive; records the server-accepted set as
 * {@code supported-groups} and the group the server chose when every group was offered as
 * {@code server-group-preference}. Fires {@code done} once all children join. The state's
 * {@code maxInFlight} bounds the concurrent handshakes.
 */
public class EnumerateGroupsAction implements Action {

    @Override
    public String name() {
        return "enumerate-groups";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.enumerateGroups(state); // fires "done" via the join barrier
    }
}
