package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * tls-facts — record TLS facts (state, version, cipher, key-exchange group, cert)
 * WITHOUT any PQC classification. For probes that only need to confirm TLS/STARTTLS.
 * Fires {@code done}.
 */
public class TLSFactsAction implements Action {

    @Override
    public String name() {
        return "tls-facts";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.recordTlsFacts();
        context.fire("done");
    }
}
