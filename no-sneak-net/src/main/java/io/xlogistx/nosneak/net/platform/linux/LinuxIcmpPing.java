package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.codecs.Icmp4Echo;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.ICMPPing;
import io.xlogistx.nosneak.net.common.PingError;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.util.Identifiers;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * ICMP and ICMPv6 echo on Linux, over raw sockets.
 * <p>
 * NOT bound to an interface: the kernel routes each request and picks the source
 * address, and one instance serves the whole JVM — two sockets and two reader
 * threads regardless of how many NICs exist.
 * <p>
 * The two families are deliberately asymmetric, and §4.2 is the reason:
 * <ul>
 *   <li><b>IPv4</b> — we own the identifier AND the checksum. Receives deliver the
 *       FULL IPv4 header, so the TTL is read straight from offset 8 with no
 *       {@code recvmsg}. That is the entire reason for choosing {@code SOCK_RAW},
 *       and it makes both {@code ttlAvailable} and {@code rawEvidence} true.</li>
 *   <li><b>IPv6</b> — we own the identifier, but the KERNEL computes the checksum
 *       (mandatory, RFC 3542), so it is left zero. The kernel also strips the IPv6
 *       header, so the hop limit is unavailable and reported as {@code -1}.</li>
 * </ul>
 * A raw ICMP socket receives a copy of EVERY ICMP packet delivered to the host,
 * including other processes' traffic, so filtering on our identifier is mandatory
 * rather than an optimisation.
 */
public final class LinuxIcmpPing implements ICMPPing {

    private static final int RECEIVE_BUFFER = 65536;

    private final Arena arena = Arena.ofShared();
    private final MemorySegment state = arena.allocate(Libc.CAPTURE);

    private final int v4Socket;
    private final int v6Socket;

    /** Distinct per socket and unique across the JVM — §4.2's mandatory filter. */
    private final int v4Identifier = Identifiers.nextIdentifier();
    private final int v6Identifier = Identifiers.nextIdentifier();
    private final Identifiers.SequenceAllocator v4Sequences = Identifiers.newSequenceAllocator();
    private final Identifiers.SequenceAllocator v6Sequences = Identifiers.newSequenceAllocator();

    private final ConcurrentHashMap<Long, PendingProbe> inFlight = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private final List<Thread> readers = new ArrayList<>(2);

    /** Serializes sends per socket — the §12.7 choke point. */
    private final Object v4SendLock = new Object();
    private final Object v6SendLock = new Object();

    private LinuxIcmpPing(int v4Socket, int v6Socket,
                          ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        this.v4Socket = v4Socket;
        this.v6Socket = v6Socket;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
    }

    /**
     * Opens both raw sockets and starts their reader threads.
     *
     * @throws DiscoveryException without root or {@code CAP_NET_RAW}, naming the reason
     */
    public static LinuxIcmpPing open(ScheduledExecutorService scheduler,
                                     ExecutorService dispatcher) throws DiscoveryException {
        LinuxIcmpPing ping = null;
        Arena arena = Arena.ofConfined();
        try {
            MemorySegment bootstrap = arena.allocate(Libc.CAPTURE);
            int v4 = Libc.socket(bootstrap, Libc.AF_INET, Libc.SOCK_RAW, Libc.IPPROTO_ICMP);
            int v6;
            try {
                v6 = Libc.socket(bootstrap, Libc.AF_INET6, Libc.SOCK_RAW, Libc.IPPROTO_ICMPV6);
            } catch (DiscoveryException e) {
                Libc.closeQuietly(bootstrap, v4);
                throw e;
            }
            ping = new LinuxIcmpPing(v4, v6, scheduler, dispatcher);
            Libc.setReceiveTimeout(ping.arena, ping.state, v4);
            Libc.setReceiveTimeout(ping.arena, ping.state, v6);
            // Cut reader-thread noise substantially: only echo replies get through.
            Libc.setIcmp6Filter(ping.arena, ping.state, v6, Icmp6.TYPE_ECHO_REPLY);
            ping.startReaders();
            return ping;
        } catch (DiscoveryException | RuntimeException e) {
            if (ping != null) {
                ping.close();
            }
            throw e;
        } finally {
            arena.close();
        }
    }

    @Override
    public DiscoveryCapabilities capabilities() {
        return new DiscoveryCapabilities(
                true,    // icmpV4
                true,    // icmpV6
                false,   // activeArp  - L2 belongs to LinuxHostDiscovery
                false,   // activeNdp
                false,   // passiveObservation
                true,    // rawEvidence  - IPv4 raw sockets deliver the whole packet
                true,    // ttlAvailable - IPv4 only; v6 probes report -1
                true,    // offLinkIcmp  - the kernel routes
                DiscoveryCapabilities.Backend.LINUX_NATIVE);
    }

    @Override
    public CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout) {
        if (count < 1) {
            throw new IllegalArgumentException("count must be >= 1, got " + count);
        }
        if (closed.get()) {
            return CompletableFuture.completedFuture(allFailed(target, count, PingError.IO));
        }
        boolean v4 = target instanceof Inet4Address;
        if (!v4 && isUnscopedLinkLocal(target)) {
            // fe80:: cannot be routed without a scope id, and an unbound pinger
            // has no interface of its own to supply one.
            return CompletableFuture.completedFuture(
                    allFailed(target, count, PingError.NETWORK_UNREACHABLE));
        }

        PendingCall call = new PendingCall(target, count);
        // PIPELINED: every probe goes out immediately with a distinct sequence, so
        // worst-case wall time is one timeout rather than count of them.
        for (int i = 0; i < count; i++) {
            int identifier = v4 ? v4Identifier : v6Identifier;
            int seq = (v4 ? v4Sequences : v6Sequences).next();
            long key = Identifiers.correlationKey(identifier, seq);
            PendingProbe probe = new PendingProbe(call, seq, System.nanoTime());
            inFlight.put(key, probe);

            PingError sendError = v4 ? sendV4(target, identifier, seq) : sendV6(target, seq);
            if (sendError != null) {
                inFlight.remove(key);
                call.settle(PingProbe.failed(seq, sendError));
                continue;
            }
            probe.expiry = scheduler.schedule(() -> {
                if (inFlight.remove(key) != null) {
                    call.settle(PingProbe.failed(seq, PingError.TIMEOUT));
                }
            }, Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS);
        }
        return call.future;
    }

    /** @return null on success, or the mapped errno */
    private PingError sendV4(InetAddress target, int identifier, int seq) {
        byte[] echo = Icmp4Echo.request(identifier, seq, timestampPayload());
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(Libc.SOCKADDR_IN);
            Libc.fillSockaddrIn(dest, target.getAddress());
            synchronized (v4SendLock) {
                long sent = (long) Libc.Handles.SENDTO.invokeExact(state, v4Socket, buf,
                        (long) echo.length, 0, dest, (int) Libc.SOCKADDR_IN.byteSize());
                return sent < 0 ? Libc.toPingError(Libc.errno(state)) : null;
            }
        } catch (Throwable t) {
            return PingError.IO;
        }
    }

    private PingError sendV6(InetAddress target, int seq) {
        // Checksum LEFT ZERO on purpose: RFC 3542 requires the kernel to compute
        // it for IPPROTO_ICMPV6, and computing it here as well is wasted work.
        byte[] echo = Icmp6.echoRequestUnchecksummed(v6Identifier, seq, timestampPayload());
        int scope = target instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(Libc.SOCKADDR_IN6);
            Libc.fillSockaddrIn6(dest, target.getAddress(), scope);
            synchronized (v6SendLock) {
                long sent = (long) Libc.Handles.SENDTO.invokeExact(state, v6Socket, buf,
                        (long) echo.length, 0, dest, (int) Libc.SOCKADDR_IN6.byteSize());
                return sent < 0 ? Libc.toPingError(Libc.errno(state)) : null;
            }
        } catch (Throwable t) {
            return PingError.IO;
        }
    }

    private void startReaders() {
        readers.add(startReader("nosneak-icmp4", () -> readLoop(v4Socket, true)));
        readers.add(startReader("nosneak-icmp6", () -> readLoop(v6Socket, false)));
    }

    private Thread startReader(String name, Runnable body) {
        // A DEDICATED PLATFORM THREAD, never a pool thread: this loop runs until
        // shutdown and would permanently consume one (§4.4).
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    /**
     * Blocking receive loop. {@code SO_RCVTIMEO} makes {@code recvfrom} return
     * {@code EAGAIN} roughly every 200 ms, which is the only way this thread ever
     * notices {@code running} went false — closing the fd would NOT wake it.
     */
    private void readLoop(int fd, boolean v4) {
        try (Arena local = Arena.ofConfined()) {
            MemorySegment localState = local.allocate(Libc.CAPTURE);
            MemorySegment buf = local.allocate(RECEIVE_BUFFER);
            while (running) {
                long n;
                try {
                    n = (long) Libc.Handles.RECVFROM.invokeExact(localState, fd, buf,
                            (long) RECEIVE_BUFFER, 0, MemorySegment.NULL, MemorySegment.NULL);
                } catch (Throwable t) {
                    return;
                }
                if (n < 0) {
                    continue;   // EAGAIN tick, or a transient error: re-check running
                }
                byte[] packet = buf.asSlice(0, n).toArray(JAVA_BYTE);
                try {
                    if (v4) {
                        onV4(packet);
                    } else {
                        onV6(packet);
                    }
                } catch (RuntimeException ignored) {
                    // a malformed packet must never kill the reader
                }
            }
        }
    }

    /** IPv4 raw sockets deliver the IP header, so the TTL is at offset 8. */
    private void onV4(byte[] packet) {
        if (packet.length < 20) {
            return;
        }
        int ihl = (packet[0] & 0x0F) * 4;
        if ((packet[0] & 0xFF) >>> 4 != 4 || ihl < 20 || packet.length < ihl + 8) {
            return;
        }
        int ttl = packet[8] & 0xFF;
        Icmp4Echo.parseReply(packet, ihl, packet.length - ihl).ifPresent(echo -> {
            if (echo.id() != v4Identifier) {
                return;   // another process's ICMP - the identifier is the only filter
            }
            complete(v4Identifier, echo.seq(), ttl, packet);
        });
    }

    /** The kernel strips the IPv6 header, so no hop limit is available (§1). */
    private void onV6(byte[] packet) {
        Icmp6.parseEchoReply(packet, 0, packet.length).ifPresent(echo -> {
            if (echo.id() != v6Identifier) {
                return;
            }
            complete(v6Identifier, echo.seq(), PingProbe.TTL_UNAVAILABLE, packet);
        });
    }

    private void complete(int identifier, int seq, int ttl, byte[] raw) {
        PendingProbe probe = inFlight.remove(Identifiers.correlationKey(identifier, seq));
        if (probe == null) {
            return;   // already timed out, or never ours
        }
        if (probe.expiry != null) {
            probe.expiry.cancel(false);
        }
        Duration rtt = Duration.ofNanos(System.nanoTime() - probe.sentAtNanos);
        // neighborResolutionPending stays FALSE: on Linux the kernel owns the
        // neighbor table and we cannot see it, so we never know (§4.6).
        probe.call.settle(new PingProbe(seq, true, rtt, ttl, raw, false, false, Optional.empty()));
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        running = false;
        for (Thread reader : readers) {
            try {
                reader.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        Libc.closeQuietly(state, v4Socket);
        Libc.closeQuietly(state, v6Socket);

        // Pending futures complete NORMALLY with an error result, never
        // exceptionally - that would contradict the ping contract.
        inFlight.forEach((key, probe) -> {
            if (probe.expiry != null) {
                probe.expiry.cancel(false);
            }
            probe.call.settle(PingProbe.failed(probe.sequence, PingError.IO));
        });
        inFlight.clear();
        try {
            arena.close();
        } catch (IllegalStateException e) {
            // a reader still inside a downcall; the fds are closed either way
        }
        // The scheduler and dispatcher are BORROWED - never shut them down here.
    }

    private static boolean isUnscopedLinkLocal(InetAddress target) {
        return target.isLinkLocalAddress()
                && (!(target instanceof Inet6Address v6) || v6.getScopeId() == 0);
    }

    /** Monotonic, never wall-clock — the reply is timed against this. */
    private static byte[] timestampPayload() {
        long now = System.nanoTime();
        byte[] p = new byte[16];
        for (int i = 0; i < 8; i++) {
            p[i] = (byte) (now >>> (56 - 8 * i));
        }
        System.arraycopy("nosneak".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                         0, p, 8, 7);
        return p;
    }

    private static PingResult allFailed(InetAddress target, int count, PingError error) {
        List<PingProbe> probes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            probes.add(PingProbe.failed(i, error));
        }
        return PingResult.of(target, probes, error);
    }

    private static final class PendingProbe {
        final PendingCall call;
        final int sequence;
        final long sentAtNanos;
        volatile ScheduledFuture<?> expiry;

        PendingProbe(PendingCall call, int sequence, long sentAtNanos) {
            this.call = call;
            this.sequence = sequence;
            this.sentAtNanos = sentAtNanos;
        }
    }

    /** Collects one ping() call's probes and completes when all have settled. */
    private static final class PendingCall {
        final CompletableFuture<PingResult> future = new CompletableFuture<>();
        final InetAddress target;
        final int expected;
        final List<PingProbe> settled = new ArrayList<>();

        PendingCall(InetAddress target, int expected) {
            this.target = target;
            this.expected = expected;
        }

        void settle(PingProbe probe) {
            List<PingProbe> finished = null;
            synchronized (settled) {
                settled.add(probe);
                if (settled.size() >= expected) {
                    finished = new ArrayList<>(settled);
                }
            }
            if (finished != null) {
                finished.sort(Comparator.comparingInt(PingProbe::sequence));
                future.complete(PingResult.of(target, finished, null));
            }
        }
    }
}
