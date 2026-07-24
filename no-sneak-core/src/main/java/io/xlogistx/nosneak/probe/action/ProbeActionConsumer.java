package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;
import org.zoxweb.server.fsm.TriggerConsumer;

/**
 * Bridges a fixed-library {@link Action} into zoxweb-core's trigger-based state
 * machine ({@code org.zoxweb.server.fsm}). One instance is created per JSON state
 * and registered under that state's id as its single canonical id, so publishing
 * a trigger for a state id enters that state and runs its action.
 * <p>
 * The trigger payload is the {@link ProbeSession}; {@link #accept(ProbeSession)}
 * runs the action against it. The action reports its outcome by calling
 * {@link ProbeSession#fire(String)}, which the machine resolves through the
 * state's {@code on{}} map to the next state. A thrown action failure is turned
 * into an {@code error} outcome so the JSON graph can route it.
 * <p>
 * This keeps the action library a set of trusted, stateless behaviours while the
 * state machine itself is fully built from the JSON definition.
 */
public class ProbeActionConsumer extends TriggerConsumer<ProbeSession> {

    private final Action action;
    private final ProbeState state;

    public ProbeActionConsumer(String stateId, Action action, ProbeState state) {
        super(stateId);
        this.action = action;
        this.state = state;
    }

    @Override
    public void accept(ProbeSession session) {
        if (session == null || session.isTerminated()) {
            return;
        }
        try {
            action.execute(session, state);
        } catch (Exception e) {
            session.fire("error");
        }
    }
}
