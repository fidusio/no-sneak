package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * send — write a payload to the current channel. The payload comes from the
 * state's {@code data} field (codec-prefixed: {@code hex:} / {@code base64:} /
 * {@code text:}, or plain text if unprefixed — this is what makes binary
 * protocols like MongoDB expressible in JSON) or, as a text convenience, the
 * {@code payload} field. Text supports {@code {probe.hostname}}/{@code {probe.port}}
 * templating. Fires {@code sent} on success, {@code error} if the channel is gone
 * or the write fails (so a failed send surfaces immediately instead of degrading
 * into a later {@code expect} timeout).
 */
public class SendAction implements Action {

    @Override
    public String name() {
        return "send";
    }

    @Override
    public void execute(ProbeSession session, ProbeState state) {
        session.fire(session.send(state) ? "sent" : "error");
    }
}
