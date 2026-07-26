package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.PatternRule;
import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

import java.util.Collections;

/**
 * starttls — send the protocol upgrade command (e.g. {@code STARTTLS\r\n}) and wait for
 * the server's {@code ready} regex (default {@code ^220}). Marks the context as an upgrade
 * so the following {@code tls-handshake} records {@code STARTTLS_UPGRADED}. Fires
 * {@code ready}, {@code timeout}, or {@code nomatch}/{@code error}.
 */
public class StartTLSAction implements Action {

    @Override
    public String name() {
        return "starttls";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.markStartTls();
        context.write(state.getCommand());
        String ready = state.getReady() != null ? state.getReady() : "^220";
        context.beginExpect(Collections.singletonList(new PatternRule(ready, "ready")));
    }
}
