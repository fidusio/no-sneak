package io.xlogistx.nosneak.net.common;

/**
 * WHERE a MAC came from. This is provenance, and it is what {@link io.xlogistx.nosneak.net.util.IpMacCache}
 * stores against each entry.
 * <p>
 * Deliberately separate from {@link ResolveOutcome}: a source answers "how do we
 * know this", an outcome answers "what happened". Collapsing them loses the
 * ability to distinguish a cached answer from a fresh one, which the
 * fingerprinting layer cares about.
 */
public enum ResolveSource {

    /** We sent an ARP request and got a reply. */
    ACTIVE_ARP,

    /** We sent a Neighbor Solicitation and got an Advertisement. */
    ACTIVE_NDP,

    /** Observed on the segment, unsolicited. */
    PASSIVE,

    /** Read out of the OS neighbor table (macOS backend). */
    KERNEL_TABLE,

    /** Served from {@link io.xlogistx.nosneak.net.util.IpMacCache} without touching the wire. */
    CACHE_HIT
}
