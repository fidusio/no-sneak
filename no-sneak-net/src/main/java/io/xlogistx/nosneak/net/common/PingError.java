package io.xlogistx.nosneak.net.common;

/**
 * Why a probe failed. Carried per-probe on {@link PingProbe} and per-call on
 * {@link PingResult}.
 * <p>
 * {@link #HOST_UNREACHABLE} is categorically stronger evidence than
 * {@link #TIMEOUT} and must never be collapsed into it: it means the kernel
 * exhausted its own neighbor solicitation retries, which is a positive
 * statement that the host is down on this segment. A timeout says only that
 * nothing came back.
 */
public enum PingError {

    /** No reply arrived before the probe's timeout fired. */
    TIMEOUT,

    /** {@code EHOSTUNREACH} — kernel ARP/ND failed; strong "down on this segment". */
    HOST_UNREACHABLE,

    /** {@code ENETUNREACH} — no route to the target network. */
    NETWORK_UNREACHABLE,

    /** {@code EACCES} / {@code EPERM} — insufficient privilege for the socket or send. */
    PERMISSION,

    /** The bound interface is down ({@code ENETDOWN}, {@code ENXIO}). */
    INTERFACE_DOWN,

    /** Anything else. */
    IO
}
