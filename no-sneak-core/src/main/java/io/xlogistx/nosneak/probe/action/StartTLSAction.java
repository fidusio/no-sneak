package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.PatternRule;
import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

import java.util.List;

/**
 * starttls — send the protocol upgrade command (e.g. {@code STARTTLS\r\n}) and
 * wait for the server's {@code ready} regex (default {@code ^220}). Marks the
 * session as an upgrade so the following {@code tls-handshake} records
 * {@code STARTTLS_UPGRADED}. Fires {@code ready}, {@code timeout}, or
 * {@code nomatch}/{@code error}.
 */
public class StartTLSAction implements Action {

    @Override
    public String name() {
        return "starttls";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.markStartTls();
        session.write(state.getCommand());
        String ready = state.getReady() != null ? state.getReady() : "^220";
        session.beginExpect(List.of(new PatternRule(ready, "ready")));
    }
}
