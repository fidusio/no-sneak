package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * send — write the state's payload to the current channel. Fires {@code sent} on a
 * successful write, else {@code error}. Resolves the codec-prefixed {@code data} field
 * ({@code hex:}/{@code base64:}/{@code text:}) or the templated {@code payload}.
 */
public class SendAction implements Action {

    @Override
    public String name() {
        return "send";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.fire(context.send(state) ? "sent" : "error");
    }
}
