package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * pqc-check — record TLS facts (state, version, cipher, key-exchange group, cert) and
 * classify the negotiated key exchange as PQC / classical / unknown. Fires {@code done}.
 */
public class PQCCheckAction implements Action {

    @Override
    public String name() {
        return "pqc-check";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.recordPQC();
        context.fire("done");
    }
}
