package io.xlogistx.nosneak.action;

import io.xlogistx.nosneak.model.ProbeState;
import io.xlogistx.nosneak.runtime.ProbeContext;

/**
 * enumerate-versions — probe each candidate TLS version in parallel (via the fan-out
 * primitive), record the server-accepted set as {@code supported-protocol-versions}, then
 * fire {@code done} once all children join. TLSv1.3 and TLSv1.2 are always offered; the
 * state's {@code includeSSLv3} / {@code includeTLS10} / {@code includeTLS11} (default true)
 * decide the legacy candidates, and {@code maxInFlight} bounds the concurrent handshakes.
 */
public class EnumerateVersionsAction implements Action {

    @Override
    public String name() {
        return "enumerate-versions";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.enumerateVersions(state); // fires "done" via the join barrier
    }
}
