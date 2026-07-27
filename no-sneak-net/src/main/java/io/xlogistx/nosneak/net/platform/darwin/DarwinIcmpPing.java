package io.xlogistx.nosneak.net.platform.darwin;

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

/**
 * ICMP and ICMPv6 echo on macOS, over UNPRIVILEGED datagram sockets.
 * <p>
 * This is the least-privileged path in the whole subsystem: {@code SOCK_DGRAM}
 * with {@code IPPROTO_ICMP} needs no root on Darwin. The kernel routes, so
 * off-link targets work.
 * <p>
 * TWO consequences of the kernel doing more of the work, both of which change how
 * replies are matched (§4.2):
 * <ul>
 *   <li>The kernel <b>OVERWRITES the identifier</b> with the socket's own assigned
 *       value, so ours never reaches the wire. Correlation therefore matches on
 *       <b>SEQUENCE ALONE</b> — the identifier we sent is meaningless here, unlike
 *       on Linux raw sockets and Windows pcap where we own it.</li>
 *   <li>The kernel computes the checksum, and strips the IP header on receive — so
 *       there is no TTL. {@code ttlAvailable} is false and every probe reports
 *       {@link PingProbe#TTL_UNAVAILABLE}. Obtaining it would need
 *       {@code IP_RECVTTL} plus {@code recvmsg}, which §1 rules out.</li>
 * </ul>
 * Because correlation is by sequence only, ONE sequence allocator is shared
 * across both families rather than one per socket: a v4 and a v6 probe must not
 * be able to collide on a bare sequence number.
 */
public final class DarwinIcmpPing implements ICMPPing {

    private static final int RECEIVE_BUFFER = 65536;

    private final Arena arena = Arena.ofShared();
    private final MemorySegment state = arena.allocate(DarwinLibc.CAPTURE);

    private final int v4Socket;
    private final int v6Socket;

    /**
     * ONE allocator for both families. The kernel rewrites the identifier, so the
     * sequence is the entire correlation key and must be unique across sockets.
     */
    private final Identifiers.SequenceAllocator sequences = Identifiers.newSequenceAllocator();

    private final ConcurrentHashMap<Integer, PendingProbe> inFlight = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private final List<Thread> readers = new ArrayList<>(2);

    private final Object v4SendLock = new Object();
    private final Object v6SendLock = new Object();

    private DarwinIcmpPing(int v4Socket, int v6Socket,
                           ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        this.v4Socket = v4Socket;
        this.v6Socket = v6Socket;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
    }

    /** Opens both datagram sockets. No privilege required. */
    public static DarwinIcmpPing open(ScheduledExecutorService scheduler,
                                      ExecutorService dispatcher) throws DiscoveryException {
        DarwinIcmpPing ping = null;
        try (Arena bootstrapArena = Arena.ofConfined()) {
            MemorySegment bootstrap = bootstrapArena.allocate(DarwinLibc.CAPTURE);
            int v4 = DarwinLibc.socket(bootstrap, DarwinLibc.AF_INET,
                                       DarwinLibc.SOCK_DGRAM, DarwinLibc.IPPROTO_ICMP);
            int v6;
            try {
                v6 = DarwinLibc.socket(bootstrap, DarwinLibc.AF_INET6,
                                       DarwinLibc.SOCK_DGRAM, DarwinLibc.IPPROTO_ICMPV6);
            } catch (DiscoveryException e) {
                DarwinLibc.closeQuietly(bootstrap, v4);
                throw e;
            }
            ping = new DarwinIcmpPing(v4, v6, scheduler, dispatcher);
            DarwinLibc.setReceiveTimeout(ping.arena, ping.state, v4);
            DarwinLibc.setReceiveTimeout(ping.arena, ping.state, v6);
            ping.startReaders();
            return ping;
        } catch (DiscoveryException | RuntimeException e) {
            if (ping != null) {
                ping.close();
            }
            throw e;
        }
    }

    @Override
    public DiscoveryCapabilities capabilities() {
        return new DiscoveryCapabilities(
                true,    // icmpV4
                true,    // icmpV6
                false,   // activeArp  - the neighbor table belongs to the HostDiscovery half
                false,   // activeNdp
                false,   // passiveObservation - Darwin cannot, at all
                false,   // rawEvidence - the kernel strips the IP header
                false,   // ttlAvailable - likewise; -1 must never read as a distance
                true,    // offLinkIcmp - the kernel routes
                DiscoveryCapabilities.Backend.MACOS_NATIVE);
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
        if (!v4 && target.isLinkLocalAddress()
                && (!(target instanceof Inet6Address v6) || v6.getScopeId() == 0)) {
            return CompletableFuture.completedFuture(
                    allFailed(target, count, PingError.NETWORK_UNREACHABLE));
        }

        PendingCall call = new PendingCall(target, count);
        for (int i = 0; i < count; i++) {
            int seq = sequences.next();
            PendingProbe probe = new PendingProbe(call, seq, System.nanoTime());
            inFlight.put(seq, probe);

            PingError sendError = v4 ? sendV4(target, seq) : sendV6(target, seq);
            if (sendError != null) {
                inFlight.remove(seq);
                call.settle(PingProbe.failed(seq, sendError));
                continue;
            }
            probe.expiry = scheduler.schedule(() -> {
                if (inFlight.remove(seq) != null) {
                    call.settle(PingProbe.failed(seq, PingError.TIMEOUT));
                }
            }, Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS);
        }
        return call.future;
    }

    /**
     * The identifier passed here is discarded by the kernel; it is written only so
     * the packet is well-formed. Never correlate on it (§4.2).
     */
    private PingError sendV4(InetAddress target, int seq) {
        byte[] echo = Icmp4Echo.request(0, seq, timestampPayload());
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(DarwinLibc.SOCKADDR_IN);
            DarwinLibc.fillSockaddrIn(dest, target.getAddress());
            synchronized (v4SendLock) {
                long sent = (long) DarwinLibc.Handles.SENDTO.invokeExact(state, v4Socket, buf,
                        (long) echo.length, 0, dest, (int) DarwinLibc.SOCKADDR_IN.byteSize());
                return sent < 0 ? DarwinLibc.toPingError(DarwinLibc.errno(state)) : null;
            }
        } catch (Throwable t) {
            return PingError.IO;
        }
    }

    private PingError sendV6(InetAddress target, int seq) {
        byte[] echo = Icmp6.echoRequestUnchecksummed(0, seq, timestampPayload());
        int scope = target instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(DarwinLibc.SOCKADDR_IN6);
            DarwinLibc.fillSockaddrIn6(dest, target.getAddress(), scope);
            synchronized (v6SendLock) {
                long sent = (long) DarwinLibc.Handles.SENDTO.invokeExact(state, v6Socket, buf,
                        (long) echo.length, 0, dest, (int) DarwinLibc.SOCKADDR_IN6.byteSize());
                return sent < 0 ? DarwinLibc.toPingError(DarwinLibc.errno(state)) : null;
            }
        } catch (Throwable t) {
            return PingError.IO;
        }
    }

    private void startReaders() {
        readers.add(startReader("nosneak-darwin-icmp4", () -> readLoop(v4Socket, true)));
        readers.add(startReader("nosneak-darwin-icmp6", () -> readLoop(v6Socket, false)));
    }

    private Thread startReader(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private void readLoop(int fd, boolean v4) {
        try (Arena local = Arena.ofConfined()) {
            MemorySegment localState = local.allocate(DarwinLibc.CAPTURE);
            MemorySegment buf = local.allocate(RECEIVE_BUFFER);
            while (running) {
                long n;
                try {
                    n = (long) DarwinLibc.Handles.RECVFROM.invokeExact(localState, fd, buf,
                            (long) RECEIVE_BUFFER, 0, MemorySegment.NULL, MemorySegment.NULL);
                } catch (Throwable t) {
                    return;
                }
                if (n < 0) {
                    continue;   // EAGAIN tick from SO_RCVTIMEO
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

    /**
     * Darwin is documented as stripping the IP header on a datagram ICMP socket,
     * but behaviour has varied across releases, so this tolerates BOTH shapes:
     * parse at offset 0 first, and if that fails and the buffer opens with a
     * plausible IPv4 header, retry past it. Being wrong in either direction would
     * mean every reply is silently dropped.
     */
    private void onV4(byte[] packet) {
        if (Icmp4Echo.parseReply(packet, 0, packet.length)
                     .map(echo -> complete(echo.seq(), packet))
                     .orElse(false)) {
            return;
        }
        if (packet.length < 20 || (packet[0] & 0xFF) >>> 4 != 4) {
            return;
        }
        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.length < ihl + 8) {
            return;
        }
        Icmp4Echo.parseReply(packet, ihl, packet.length - ihl)
                 .ifPresent(echo -> complete(echo.seq(), packet));
    }

    private void onV6(byte[] packet) {
        Icmp6.parseEchoReply(packet, 0, packet.length)
             .ifPresent(echo -> complete(echo.seq(), packet));
    }

    /** @return true when the sequence matched an outstanding probe */
    private boolean complete(int seq, byte[] raw) {
        PendingProbe probe = inFlight.remove(seq);
        if (probe == null) {
            return false;
        }
        if (probe.expiry != null) {
            probe.expiry.cancel(false);
        }
        Duration rtt = Duration.ofNanos(System.nanoTime() - probe.sentAtNanos);
        // rawEvidence is false here, so no bytes are retained; TTL is unavailable.
        probe.call.settle(new PingProbe(seq, true, rtt, PingProbe.TTL_UNAVAILABLE,
                                        new byte[0], false, Optional.empty()));
        return true;
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
        DarwinLibc.closeQuietly(state, v4Socket);
        DarwinLibc.closeQuietly(state, v6Socket);

        inFlight.forEach((seq, probe) -> {
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
    }

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
