package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * done / fail — terminal states that deliver the {@link
 * io.xlogistx.nosneak.probe.ProbeResult} exactly once. {@code done} marks the
 * result complete; {@code fail} marks it incomplete. An optional state
 * {@code note} annotates the terminal reason.
 */
public class TerminalAction implements Action {

    private final String name;
    private final boolean success;

    public TerminalAction(String name, boolean success) {
        this.name = name;
        this.success = success;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        String note = state.getNote() != null ? state.getNote() : name;
        session.deliver(success, note);
    }
}
