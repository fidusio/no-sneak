package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * done / fail — terminal actions. {@code done} ends the probe as complete
 * ({@code complete=true}); {@code fail} ends it as incomplete. Delivers the result
 * exactly once via {@link ProbeContext#deliver(boolean, String)}.
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
    public void execute(ProbeContext context, ProbeState state) {
        String note = state.getNote() != null ? state.getNote() : name;
        context.deliver(success, note);
    }
}
