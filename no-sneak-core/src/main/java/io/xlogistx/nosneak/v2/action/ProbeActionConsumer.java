package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;
import org.zoxweb.server.fsm.TriggerConsumer;

/**
 * Bridges a fixed-library {@link Action} into zoxweb-core's trigger-based state
 * machine ({@code org.zoxweb.server.fsm}). One instance is created per JSON state and
 * registered under that state's id as its single canonical id, so publishing a trigger
 * for a state id enters that state and runs its action.
 * <p>
 * The trigger payload is the {@link ProbeContext}; {@link #accept(ProbeContext)} runs
 * the action against it. The action reports its outcome by calling
 * {@link ProbeContext#fire(String)}, which the machine resolves through the state's
 * {@code on{}} map. A thrown action failure becomes an {@code error} outcome so the JSON
 * graph can route it.
 */
public class ProbeActionConsumer extends TriggerConsumer<ProbeContext> {

    private final Action action;
    private final ProbeState state;

    public ProbeActionConsumer(String stateId, Action action, ProbeState state) {
        super(stateId);
        this.action = action;
        this.state = state;
    }

    @Override
    public void accept(ProbeContext context) {
        if (context == null || context.isTerminated()) {
            return;
        }
        try {
            action.execute(context, state);
        } catch (Exception e) {
            context.fire("error");
        }
    }
}
