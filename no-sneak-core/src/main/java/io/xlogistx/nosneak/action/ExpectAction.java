package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * expect — accumulate inbound bytes and fire the {@code outcome} of the first matching
 * {@code patterns[]} rule (capturing a service fact if the rule declares one); fire
 * {@code timeout} on the wait deadline, or {@code nomatch}/{@code error} if the peer
 * closes first.
 */
public class ExpectAction implements Action {

    @Override
    public String name() {
        return "expect";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.beginExpect(state.getPatterns());
    }
}
