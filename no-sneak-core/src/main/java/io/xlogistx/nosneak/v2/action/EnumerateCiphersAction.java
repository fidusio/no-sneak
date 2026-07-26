package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * enumerate-ciphers — probe each candidate cipher suite in parallel (via the fan-out
 * primitive), record the server-accepted set as {@code supported-cipher-suites}, then fire
 * {@code done} once all children join.
 */
public class EnumerateCiphersAction implements Action {

    @Override
    public String name() {
        return "enumerate-ciphers";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.enumerateCiphers(); // fires "done" via the join barrier
    }
}
