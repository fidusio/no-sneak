package io.xlogistx.nosneak.net.common;

/**
 * WHAT HAPPENED during a resolution attempt. An outcome is not a source — keep
 * this enum and {@link ResolveSource} separate.
 */
public enum ResolveOutcome {

    /** A MAC was obtained; {@link ResolveResult#source()} says from where. */
    RESOLVED,

    /** Nothing answered within the caller's bound. */
    TIMEOUT,

    /** This backend cannot resolve on this interface at all — check capabilities first. */
    UNSUPPORTED,

    /** A send or receive failed. */
    ERROR
}
