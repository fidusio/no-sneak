package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * expect — accumulate inbound bytes and fire the {@code outcome} of the first
 * matching {@code patterns[]} rule; fire {@code timeout} on the wait deadline,
 * or {@code nomatch}/{@code error} if the peer closes first.
 */
public class ExpectAction implements Action {

    @Override
    public String name() {
        return "expect";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.beginExpect(state.getPatterns());
    }
}
