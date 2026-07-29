package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.action.ActionRegistry;
import io.xlogistx.nosneak.v2.action.ProbeActionConsumer;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeState;
import org.zoxweb.server.fsm.State;
import org.zoxweb.server.fsm.StateInt;
import org.zoxweb.server.fsm.StateMachine;
import org.zoxweb.server.logging.LogWrapper;

import java.util.Map;

/**
 * Builds and drives the probe's finite-state machine on zoxweb-core's trigger-based
 * {@link StateMachine} ({@code org.zoxweb.server.fsm}). The JSON
 * {@link ProbeDefinition} <b>builds</b> the machine: each JSON state becomes a
 * {@link State} (canonical id = state id) carrying a {@link ProbeActionConsumer} that
 * runs the state's action. Entering a state is publishing a trigger under its id; the
 * action reports an outcome via {@link ProbeContext#fire(String)}, which this class
 * resolves through the state's {@code on{}} map and publishes the next state's trigger.
 * <p>
 * An <em>inline executor</em> keeps sequential transitions on the calling thread (the
 * selector / scheduler thread that {@link ProbeContext} already serialises). Parallel
 * fan-out states dispatch through the executor of the {@code NIOSocket} the probe rides on.
 * No {@code MonoStateMachine} is used anywhere.
 */
public class ProbeEngine {

    public static final LogWrapper log = new LogWrapper(ProbeEngine.class).setEnabled(false);

    private final ProbeDefinition definition;
    private final ProbeContext context;
    private final StateMachine<ProbeContext> sm;

    public ProbeEngine(ProbeDefinition definition, ProbeContext context) {
        this.definition = definition;
        this.context = context;
        // Inline executor: publish() runs the consumer on the caller's thread (sequential).
        this.sm = new StateMachine<>("probe:" + definition.getName(), (Runnable r) -> r.run());

        for (Map.Entry<String, ProbeState> e : definition.getStates().entrySet()) {
            String id = e.getKey();
            ProbeState ps = e.getValue();
            State<ProbeContext> st = new State<>(id);
            st.register(new ProbeActionConsumer(id, ActionRegistry.get(ps.getAction()), ps));
            sm.register(st);
        }
        sm.setConfig(context);
    }

    /** Enter the definition's declared start state. */
    public void start() {
        if (context.isTerminated()) {
            return;
        }
        String startId = definition.getStart();
        StateInt<?> startState = sm.lookupState(startId);
        if (startState == null) {
            context.deliver(false, "undefined-start:" + startId);
            return;
        }
        sm.publishSync(startState, startId, context);
    }

    /**
     * Resolve {@code outcome} against the current state's transitions and enter the
     * next state. An unmapped outcome ends the probe as incomplete so a definition
     * gap surfaces in the result rather than silently hanging.
     */
    public void fire(String outcome) {
        if (context.isTerminated()) {
            return;
        }
        StateInt<?> cur = sm.getCurrentState();
        String curId = cur != null ? cur.getName() : null;
        ProbeState cst = curId != null ? definition.state(curId) : null;
        String next = cst != null ? cst.next(outcome) : null;
        if (log.isEnabled()) {
            log.getLogger().info("[" + definition.getName() + "] '" + curId + "' --" + outcome + "--> " + next);
        }
        if (next == null) {
            context.deliver(false, "unhandled-outcome:" + outcome + "@" + curId);
            return;
        }
        sm.publishSync(cur, next, context);
    }

    /** @return the id of the current state, or {@code null} before start. */
    public String currentId() {
        StateInt<?> cur = sm.getCurrentState();
        return cur != null ? cur.getName() : null;
    }

    /** Close the underlying state machine (idempotent). */
    public void close() {
        try {
            sm.close();
        } catch (Exception ignored) {
        }
    }
}
