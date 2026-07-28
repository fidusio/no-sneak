package io.xlogistx.nosneak.net.common;

import java.time.Duration;
import java.util.Optional;

/**
 * One echo request and the reply it did or did not get.
 * <p>
 * Named {@code PingProbe} rather than {@code Probe}: it belongs to the
 * {@link PingResult} / {@link PingError} family, and no-sneak-core already owns
 * "probe" for the Tier-1 TCP/UDP service-identification engine
 * ({@code ProbeDefinition}, {@code ProbeSession}, {@code ProbeResult}). Different
 * layer, same word — do not reintroduce the bare name.
 * <p>
 * A {@code PingProbe} states what happened to one packet, not whether the host is
 * up. An unreachable host produces probes with {@code replied == false}, never an
 * exception, and the host may still be alive via ARP.
 * <p>
 * NOTE: {@code rawReply} is an array, so the generated {@code equals} and
 * {@code hashCode} use reference identity. Instances are NOT value-comparable and
 * must not be used as map keys or in set membership tests.
 *
 * @param sequence                  the 16-bit ICMP sequence number sent, and half the
 *                                  correlation key; NOT an index into the probe list,
 *                                  since the allocator is per socket and shared across
 *                                  concurrent {@code ping()} calls
 * @param replied                   whether a matching reply arrived before this probe's
 *                                  own timeout fired
 * @param rtt                       null when {@code !replied}; derived from a monotonic
 *                                  {@code System.nanoTime()} carried in the echo payload,
 *                                  never wall-clock time
 * @param ttlOrHopLimit             TTL from the received IP header, or {@code -1} when the
 *                                  backend cannot tell. {@code -1} must NEVER be read as a
 *                                  distance — check
 *                                  {@link DiscoveryCapabilities#ttlAvailable()} first
 * @param rawReply                  full received bytes when
 *                                  {@link DiscoveryCapabilities#rawEvidence()} is set,
 *                                  otherwise empty
 * @param neighborResolutionPending true when the backend KNOWS L2 resolution was in flight
 *                                  at send time. Best-effort: {@code false} means "not known
 *                                  to be pending", never "known not to be pending". Linux
 *                                  cannot determine this at all — the kernel owns the
 *                                  neighbor table — so expect it to stay false there
 * @param localInterface            NO PACKET WAS SENT. The target is one of this host's own
 *                                  addresses, so its liveness is a fact about local
 *                                  configuration rather than anything observed on a wire:
 *                                  {@code replied} is true and {@code rtt} is null, because
 *                                  there is nothing to measure. The analogue of
 *                                  {@link ResolveSource#LOCAL_INTERFACE}, and like it, must
 *                                  never be read as a wire observation
 * @param error                     per-probe failure; empty when the probe replied
 */
public record PingProbe(
        int sequence,
        boolean replied,
        Duration rtt,
        int ttlOrHopLimit,
        byte[] rawReply,
        boolean neighborResolutionPending,
        boolean localInterface,
        Optional<PingError> error) {

    /** TTL sentinel meaning "this backend cannot report a TTL". */
    public static final int TTL_UNAVAILABLE = -1;

    private static final byte[] NO_BYTES = new byte[0];

    public PingProbe {
        if (rawReply == null) {
            rawReply = NO_BYTES;
        }
        if (error == null) {
            error = Optional.empty();
        }
    }

    /** A probe that replied, with no raw evidence and no usable TTL. */
    public static PingProbe replied(int sequence, Duration rtt) {
        return new PingProbe(sequence, true, rtt, TTL_UNAVAILABLE, NO_BYTES, false, false,
                             Optional.empty());
    }

    /** A probe that did not reply, for the given reason. */
    public static PingProbe failed(int sequence, PingError error) {
        return new PingProbe(sequence, false, null, TTL_UNAVAILABLE, NO_BYTES, false, false,
                             Optional.of(error));
    }

    /**
     * The target is one of this host's own addresses: alive by definition, and
     * nothing was transmitted.
     * <p>
     * {@code rtt} is deliberately NULL rather than zero. A zero would be a claim
     * about timing that no clock produced, and {@link PingResult#of} already drops
     * null-RTT probes from min/avg/max — so the aggregate reports no statistics
     * instead of a fabricated instant reply, while {@code received} still counts it
     * and {@link PingResult#reachable()} is true.
     * <p>
     * Only backends that cannot see their own loopback traffic need this. Where ICMP
     * goes through the kernel it routes a self-ping over loopback and returns a
     * genuine measurement, which is strictly better and must not be replaced by this.
     */
    public static PingProbe localInterface(int sequence) {
        return new PingProbe(sequence, true, null, TTL_UNAVAILABLE, NO_BYTES, false, true,
                             Optional.empty());
    }

    /** True when a TTL is actually present, i.e. not the {@link #TTL_UNAVAILABLE} sentinel. */
    public boolean hasTtl() {
        return ttlOrHopLimit >= 0;
    }
}
