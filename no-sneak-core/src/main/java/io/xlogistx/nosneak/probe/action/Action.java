package io.xlogistx.nosneak.probe.action;

import io.xlogistx.nosneak.probe.model.ProbeState;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;

/**
 * One executable primitive of the fixed probe action library. An action is a
 * trusted, stateless Java behaviour selected by name from a JSON state's
 * {@code action} field; JSON configures actions but can never introduce new
 * executable code.
 * <p>
 * An action reads its configuration from {@code state}, performs its work
 * against {@code session}, and reports its outcome by calling
 * {@link ProbeSession#fire(String)} — either synchronously (e.g. {@code send},
 * {@code record}) or later from a NIO/scheduler event (e.g. {@code connect},
 * {@code expect}, {@code tls-handshake}). Implementations must be safe to share
 * across sessions (all mutable state lives in {@link ProbeSession}).
 */
public interface Action {

    /** The name this action registers under (matches the JSON {@code action} value). */
    String name();

    /**
     * Execute against the session. Must ultimately cause exactly one
     * {@link ProbeSession#fire(String)} (or a terminal delivery), whether now or
     * from a subsequent asynchronous event.
     */
    void execute(ProbeSession session, ProbeState state);
}
