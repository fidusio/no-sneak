package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * cert-chain-validate — run PKIX chain-to-root validation on the handshake certificate
 * (via opsec) and record the trust verdict as {@code cert-chain-trust}. Requires a prior
 * {@code tls-handshake}. Fires {@code done}.
 */
public class CertChainAction implements Action {

    @Override
    public String name() {
        return "cert-chain-validate";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.validateCertChain();
        context.fire("done");
    }
}
