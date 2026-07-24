package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * tls-facts — record the negotiated TLS facts (state, version, cipher,
 * key-exchange group, cert subject/issuer) from a completed handshake
 * <em>without</em> classifying post-quantum readiness. Use this instead of
 * {@code pqc-check} when a probe only needs to confirm TLS/STARTTLS, not assess
 * PQC. Always fires {@code done}.
 */
public class TLSFactsAction implements Action {

    @Override
    public String name() {
        return "tls-facts";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.recordTlsFacts();
        session.fire("done");
    }
}
