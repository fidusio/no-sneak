package io.xlogistx.nosneak.net.util;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Allocators for the two 16-bit fields that correlate an ICMP reply to the probe
 * that caused it.
 * <p>
 * The identifier allocator is PROCESS-WIDE, and that is not an optimisation. A
 * raw ICMP socket receives a copy of every ICMP packet delivered to the host, so
 * the identifier is the only thing separating our replies from another socket's.
 * Two sockets that derived it the same way — from the PID, from a constant, from
 * a per-instance counter starting at zero — would match each other's replies and
 * complete the wrong probe. Hand each socket a distinct value from
 * {@link #nextIdentifier()} at construction.
 * <p>
 * Sequence numbers are allocated PER SOCKET, from a
 * {@link #newSequenceAllocator()} shared by every concurrent call on that socket.
 * A per-call counter starting at zero collides immediately once two callers ping
 * at once.
 */
public final class Identifiers {

    private static final AtomicInteger IDENTIFIERS = new AtomicInteger(1);

    private Identifiers() {
    }

    /**
     * A 16-bit ICMP identifier unique among all sockets in this JVM.
     * <p>
     * Never returns zero: some stacks and middleboxes treat identifier 0 as
     * unset, and it is the value a zeroed buffer would carry, so skipping it
     * keeps a forgotten assignment from looking like a valid one.
     */
    public static int nextIdentifier() {
        int id = IDENTIFIERS.getAndIncrement() & 0xFFFF;
        return id == 0 ? IDENTIFIERS.getAndIncrement() & 0xFFFF : id;
    }

    /** A 16-bit sequence allocator for one socket. */
    public static SequenceAllocator newSequenceAllocator() {
        return new SequenceAllocator();
    }

    /**
     * Wraps at 65536, which {@code maxInFlight} already keeps far out of reach —
     * reuse would need that many probes outstanding at once.
     */
    public static final class SequenceAllocator {

        private final AtomicInteger next = new AtomicInteger();

        private SequenceAllocator() {
        }

        public int next() {
            return next.getAndIncrement() & 0xFFFF;
        }
    }

    /** Packs identifier and sequence into one key for the in-flight map. */
    public static long correlationKey(int identifier, int sequence) {
        return ((long) (identifier & 0xFFFF) << 16) | (sequence & 0xFFFF);
    }
}
