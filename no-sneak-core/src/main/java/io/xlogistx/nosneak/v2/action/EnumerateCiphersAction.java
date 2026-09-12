package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * enumerate-ciphers — probe each candidate cipher suite in parallel (via the fan-out
 * primitive), record the server-accepted set as {@code supported-cipher-suites}, then fire
 * {@code done} once all children join. The state's {@code includeWeak} / {@code includeInsecure}
 * (default true) decide whether opsec's weak and insecure TLS 1.2 sets are offered,
 * {@code rankServerPreference} (default false) adds the sequential ranking chain, and
 * {@code maxInFlight} bounds the concurrent handshakes.
 */
public class EnumerateCiphersAction implements Action {

    @Override
    public String name() {
        return "enumerate-ciphers";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.enumerateCiphers(state); // fires "done" via the join barrier
    }
}
