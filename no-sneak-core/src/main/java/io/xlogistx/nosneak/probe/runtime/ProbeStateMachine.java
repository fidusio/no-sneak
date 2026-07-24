package io.xlogistx.nosneak.probe.runtime;

import io.xlogistx.nosneak.probe.action.ActionRegistry;
import io.xlogistx.nosneak.probe.action.ProbeActionConsumer;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.probe.model.ProbeState;
import org.zoxweb.server.fsm.State;
import org.zoxweb.server.fsm.StateInt;
import org.zoxweb.server.fsm.StateMachine;
import org.zoxweb.server.logging.LogWrapper;

import java.util.Map;

/**
 * Builds and drives the probe's finite-state machine on zoxweb-core's
 * trigger-based {@link StateMachine} ({@code org.zoxweb.server.fsm}). <b>The JSON
 * {@link ProbeDefinition} builds the state machine:</b> each JSON state becomes a
 * {@link State} whose canonical id is the state id, carrying a
 * {@link ProbeActionConsumer} that runs the state's action. Entering a state is
 * publishing a trigger under its id; the action reports an outcome via
 * {@link ProbeSession#fire(String)}, which this class resolves through the state's
 * {@code on{}} map and publishes the next state's trigger.
 * <p>
 * The machine uses an <em>inline executor</em> so every transition runs on the
 * calling thread (the NIO selector or task-scheduler thread), which {@link ProbeSession}
 * already serialises — no extra threading is introduced.
 * <p>
 * PROJECT CONSTRAINT: this uses the trigger-based {@code StateMachine}, never
 * {@code org.zoxweb.server.fsm.MonoStateMachine} (banned project-wide; see
 * PROBE-FRAMEWORK.md). The only remaining {@code MonoStateMachine} dependency in the
 * probe package is the inner TLS/PQC handshake reuse in {@link ProbeSession}
 * ({@code TODO(no-monostatemachine)}).
 */
public class ProbeStateMachine {

    public static final LogWrapper log = new LogWrapper(ProbeStateMachine.class).setEnabled(false);

    private final ProbeDefinition definition;
    private final ProbeSession session;
    private final StateMachine<ProbeSession> sm;

    public ProbeStateMachine(ProbeDefinition definition, ProbeSession session) {
        this.definition = definition;
        this.session = session;
        // Inline executor: publish() runs the consumer on the caller's thread.
        this.sm = new StateMachine<>("probe:" + definition.getName(), (Runnable r) -> r.run());

        for (Map.Entry<String, ProbeState> e : definition.getStates().entrySet()) {
            String id = e.getKey();
            ProbeState ps = e.getValue();
            State<ProbeSession> st = new State<>(id);
            st.register(new ProbeActionConsumer(id, ActionRegistry.get(ps.getAction()), ps));
            sm.register(st);
        }
        sm.setConfig(session);
    }

    /** Enter the definition's declared start state. */
    public void start() {
        if (session.isTerminated()) {
            return;
        }
        String startId = definition.getStart();
        StateInt<?> startState = sm.lookupState(startId);
        if (startState == null) {
            session.deliver(false, "undefined-start:" + startId);
            return;
        }
        sm.publishSync(startState, startId, session);
    }

    /**
     * Resolve {@code outcome} against the current state's transitions and enter the
     * next state. An unmapped outcome ends the probe as incomplete so a definition
     * gap surfaces in the result rather than silently hanging.
     */
    public void fire(String outcome) {
        if (session.isTerminated()) {
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
            session.deliver(false, "unhandled-outcome:" + outcome + "@" + curId);
            return;
        }
        sm.publishSync(cur, next, session);
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
