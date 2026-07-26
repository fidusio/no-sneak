package io.xlogistx.nosneak.v2.action;

import io.xlogistx.nosneak.v2.model.ProbeState;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;

/**
 * A fixed, trusted probe primitive. A JSON state's {@code action} names one of these;
 * {@link #execute(ProbeContext, ProbeState)} runs it against the live context and the
 * state's config. Actions are stateless singletons shared across all runs — all mutable
 * per-run state lives in {@link ProbeContext}.
 * <p>
 * Contract: {@code execute} must ultimately cause exactly one
 * {@link ProbeContext#fire(String)} (synchronously or later from a NIO/scheduler event)
 * or a terminal {@link ProbeContext#deliver(boolean, String)}.
 */
public interface Action {

    /** The JSON {@code action} value this primitive registers under. */
    String name();

    void execute(ProbeContext context, ProbeState state);
}
