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
import io.xlogistx.nosneak.net.util.PendingCall;
import io.xlogistx.nosneak.net.util.RecvErrors;

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

    /** {@code -1} when the kernel refused this family — see {@link #open}. */
    private final int v4Socket;
    private final int v6Socket;

    /** Why a family is unavailable, or null when it opened. Reported by ping(). */
    private final PingError v4Unavailable;
    private final PingError v6Unavailable;

    /** Why a family's reader died, or null while it lives (§13.23-B). */
    private volatile String v4ReaderFailure;
    private volatile String v6ReaderFailure;

    /**
     * ONE allocator for both families. The kernel rewrites the identifier, so the
     * sequence is the entire correlation key and must be unique across sockets.
     */
    private final Identifiers.SequenceAllocator sequences = Identifiers.newSequenceAllocator();

    private final ConcurrentHashMap<Integer, PendingCall.Probe> inFlight = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private final List<Thread> readers = new ArrayList<>(2);

    private final Object v4SendLock = new Object();
    private final Object v6SendLock = new Object();

    private DarwinIcmpPing(int v4Socket, PingError v4Unavailable,
                           int v6Socket, PingError v6Unavailable,
                           ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        this.v4Socket = v4Socket;
        this.v6Socket = v6Socket;
        this.v4Unavailable = v4Unavailable;
        this.v6Unavailable = v6Unavailable;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
    }

    /**
     * Opens the two datagram sockets INDEPENDENTLY, and succeeds when EITHER one
     * does. No privilege is required for IPv4.
     * <p>
     * The families are deliberately not all-or-nothing. Darwin hands
     * {@code SOCK_DGRAM}/{@code IPPROTO_ICMP} to any user — that is why
     * {@code /sbin/ping} no longer needs setuid — but the ICMPv6 equivalent is
     * not dependably unprivileged, and an earlier version aborted the whole
     * pinger when it was refused, taking perfectly good IPv4 ICMP down with a
     * v6-only problem. A family the kernel withholds is now reported through
     * {@link #capabilities()} and returned as a failed {@link PingResult} by
     * {@link #ping}, per the honest-degradation rule.
     *
     * @throws DiscoveryException only when NEITHER family is available, with both
     *                            errnos named so the cause is diagnosable
     */
    public static DarwinIcmpPing open(ScheduledExecutorService scheduler,
                                      ExecutorService dispatcher) throws DiscoveryException {
        int v4;
        int v6;
        int v4Errno = 0;
        int v6Errno = 0;
        try (Arena bootstrapArena = Arena.ofConfined()) {
            MemorySegment bootstrap = bootstrapArena.allocate(DarwinLibc.CAPTURE);

            v4 = DarwinLibc.trySocket(bootstrap, DarwinLibc.AF_INET,
                                      DarwinLibc.SOCK_DGRAM, DarwinLibc.IPPROTO_ICMP);
            if (v4 < 0) {
                v4Errno = DarwinLibc.errno(bootstrap);
            }
            v6 = DarwinLibc.trySocket(bootstrap, DarwinLibc.AF_INET6,
                                      DarwinLibc.SOCK_DGRAM, DarwinLibc.IPPROTO_ICMPV6);
            if (v6 < 0) {
                v6Errno = DarwinLibc.errno(bootstrap);
            }

            if (v4 < 0 && v6 < 0) {
                throw new DiscoveryException(
                        "No ICMP socket could be opened on macOS: "
                        + "socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP) failed with "
                        + DarwinLibc.errnoName(v4Errno)
                        + " and socket(AF_INET6,SOCK_DGRAM,IPPROTO_ICMPV6) failed with "
                        + DarwinLibc.errnoName(v6Errno) + ".");
            }
        }

        DarwinIcmpPing ping = new DarwinIcmpPing(
                v4, v4 < 0 ? DarwinLibc.toPingError(v4Errno) : null,
                v6, v6 < 0 ? DarwinLibc.toPingError(v6Errno) : null,
                scheduler, dispatcher);
        try {
            if (v4 >= 0) {
                DarwinLibc.setReceiveTimeout(ping.arena, ping.state, v4);
            }
            if (v6 >= 0) {
                DarwinLibc.setReceiveTimeout(ping.arena, ping.state, v6);
            }
            ping.startReaders();
            return ping;
        } catch (DiscoveryException | RuntimeException e) {
            ping.close();
            throw e;
        }
    }

    /**
     * Computed per call, never a literal: a family is available when the kernel gave us
     * its socket AND its reader is still alive (§13.23-B). Everything else is false —
     * the neighbour table belongs to the HostDiscovery half, passive observation to
     * {@code DarwinPcapBackend} (§13.14), and the datagram socket strips the IP header so
     * there is no raw evidence and no TTL (-1 must never read as a distance).
     */
    @Override
    public DiscoveryCapabilities capabilities() {
        return new DiscoveryCapabilities(
                v4Socket >= 0 && v4ReaderFailure == null,   // icmpV4
                v6Socket >= 0 && v6ReaderFailure == null,   // icmpV6
                false,   // activeArp
                false,   // activeNdp
                false,   // passiveObservation
                false,   // rawEvidence
                false,   // ttlAvailable
                true,    // offLinkIcmp - the kernel routes
                DiscoveryCapabilities.Backend.MACOS_NATIVE);
    }

    @Override
    public CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout) {
        if (count < 1) {
            throw new IllegalArgumentException("count must be >= 1, got " + count);
        }
        if (closed.get()) {
            return CompletableFuture.completedFuture(allFailed(target, count, PingError.IO, "closed"));
        }
        boolean v4 = target instanceof Inet4Address;
        // A family the kernel refused at open() is a reduced result, not a hang:
        // sending on fd -1 would otherwise leave every probe to time out.
        if (v4 && v4Socket < 0) {
            return CompletableFuture.completedFuture(allFailed(target, count, v4Unavailable));
        }
        if (!v4 && v6Socket < 0) {
            return CompletableFuture.completedFuture(allFailed(target, count, v6Unavailable));
        }
        // A dead reader cannot see the reply: fail now with its cause rather than send
        // and report TIMEOUT at full budget (§13.23-B, S14).
        String dead = v4 ? v4ReaderFailure : v6ReaderFailure;
        if (dead != null) {
            return CompletableFuture.completedFuture(allFailed(target, count, PingError.IO, dead));
        }
        if (!v4 && target.isLinkLocalAddress()
                && (!(target instanceof Inet6Address v6) || v6.getScopeId() == 0)) {
            return CompletableFuture.completedFuture(
                    allFailed(target, count, PingError.NETWORK_UNREACHABLE));
        }

        PendingCall call = new PendingCall(target, count, dispatcher);
        try {
            for (int i = 0; i < count; i++) {
                int seq = sequences.next();
                PendingCall.Probe probe = call.newProbe(seq, System.nanoTime());
                inFlight.put(seq, probe);

                SendFailure failed = v4 ? sendV4(target, seq) : sendV6(target, seq);
                if (failed != null) {
                    inFlight.remove(seq, probe);
                    call.setDetail(failed.detail());
                    probe.fail(failed.error());
                    continue;
                }
                probe.expiry = scheduler.schedule(() -> {
                    // Claim THIS probe (remove(key, value)): a sequence that wrapped onto a
                    // newer probe must not be timed out by the older one's deadline.
                    if (inFlight.remove(seq, probe)) {
                        probe.fail(PingError.TIMEOUT);
                    }
                }, Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS);
            }
        } catch (RuntimeException e) {
            // A probe registered but never sent (or never given a deadline) would leave
            // the call incomplete forever (§13.23-E). Drop its map entry so a wrapped
            // sequence cannot find it, then close every open slot with the cause.
            inFlight.values().removeIf(p -> p.call == call && !p.isSettled());
            call.failRemaining(PingError.IO, "ping aborted before every probe was sent: " + e);
        }
        return call.future;
    }

    /** A {@code sendto} that failed: the §4.7 mapping plus the errno name for the caller. */
    private record SendFailure(PingError error, String detail) {
        static SendFailure of(int errno, boolean v4) {
            return new SendFailure(DarwinLibc.toPingError(errno),
                                   "sendto(" + (v4 ? "ICMP" : "ICMPv6") + ") failed: "
                                   + DarwinLibc.errnoName(errno));
        }
    }

    /**
     * The identifier passed here is discarded by the kernel; it is written only so
     * the packet is well-formed. Never correlate on it (§4.2).
     */
    /** @return null when the kernel accepted the datagram */
    private SendFailure sendV4(InetAddress target, int seq) {
        byte[] echo = Icmp4Echo.request(0, seq, timestampPayload());
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(DarwinLibc.SOCKADDR_IN);
            DarwinLibc.fillSockaddrIn(dest, target.getAddress());
            // errno is captured PER SEND, in this confined scratch, never in a segment
            // shared with the other family's lock (§13.23-B, S3).
            MemorySegment errState = scratch.allocate(DarwinLibc.CAPTURE);
            synchronized (v4SendLock) {
                long sent = (long) DarwinLibc.Handles.SENDTO.invokeExact(errState, v4Socket, buf,
                        (long) echo.length, 0, dest, (int) DarwinLibc.SOCKADDR_IN.byteSize());
                return sent < 0 ? SendFailure.of(DarwinLibc.errno(errState), true) : null;
            }
        } catch (Throwable t) {
            return new SendFailure(PingError.IO, "sendto downcall failed: " + t);
        }
    }

    /** @return null when the kernel accepted the datagram */
    private SendFailure sendV6(InetAddress target, int seq) {
        byte[] echo = Icmp6.echoRequestUnchecksummed(0, seq, timestampPayload());
        int scope = target instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, echo);
            MemorySegment dest = scratch.allocate(DarwinLibc.SOCKADDR_IN6);
            DarwinLibc.fillSockaddrIn6(dest, target.getAddress(), scope);
            MemorySegment errState = scratch.allocate(DarwinLibc.CAPTURE);
            synchronized (v6SendLock) {
                long sent = (long) DarwinLibc.Handles.SENDTO.invokeExact(errState, v6Socket, buf,
                        (long) echo.length, 0, dest, (int) DarwinLibc.SOCKADDR_IN6.byteSize());
                return sent < 0 ? SendFailure.of(DarwinLibc.errno(errState), false) : null;
            }
        } catch (Throwable t) {
            return new SendFailure(PingError.IO, "sendto downcall failed: " + t);
        }
    }

    /** One reader per socket that actually opened — never one blocked on fd -1. */
    private void startReaders() {
        if (v4Socket >= 0) {
            readers.add(startReader("nosneak-darwin-icmp4", () -> readLoop(v4Socket, true)));
        }
        if (v6Socket >= 0) {
            readers.add(startReader("nosneak-darwin-icmp6", () -> readLoop(v6Socket, false)));
        }
    }

    private Thread startReader(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private void readLoop(int fd, boolean v4) {
        RecvErrors guard = new RecvErrors();
        try (Arena local = Arena.ofConfined()) {
            MemorySegment localState = local.allocate(DarwinLibc.CAPTURE);
            MemorySegment buf = local.allocate(RECEIVE_BUFFER);
            while (running) {
                long n;
                try {
                    n = (long) DarwinLibc.Handles.RECVFROM.invokeExact(localState, fd, buf,
                            (long) RECEIVE_BUFFER, 0, MemorySegment.NULL, MemorySegment.NULL);
                } catch (Throwable t) {
                    failReader(v4, "recvfrom downcall failed: " + t);
                    return;
                }
                if (n < 0) {
                    // The errno decides (§4.4): EAGAIN/EINTR is the SO_RCVTIMEO tick;
                    // EBADF/ENOTSOCK means the fd is gone; anything else backs off one
                    // tick ON THIS DEDICATED THREAD and is fatal after five in a row.
                    int errno = DarwinLibc.errno(localState);
                    switch (guard.next(DarwinLibc.isTimeout(errno), DarwinLibc.isDeadDescriptor(errno))) {
                        case TICK -> {
                        }
                        case BACKOFF -> {
                            try {
                                Thread.sleep(DarwinLibc.RECV_TIMEOUT_USEC / 1000);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return;
                            }
                        }
                        case FATAL -> {
                            if (running) {
                                failReader(v4, "recvfrom(" + (v4 ? "ICMP" : "ICMPv6") + "): "
                                               + DarwinLibc.errnoName(errno));
                            }
                            return;
                        }
                    }
                    continue;
                }
                guard.success();
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
        PendingCall.Probe probe = inFlight.remove(seq);
        if (probe == null) {
            return false;
        }
        Duration rtt = Duration.ofNanos(System.nanoTime() - probe.sentAtNanos);
        // rawEvidence is false here, so no bytes are retained; TTL is unavailable.
        probe.settle(new PingProbe(seq, true, rtt, PingProbe.TTL_UNAVAILABLE,
                                   new byte[0], false, false, Optional.empty()));
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

        failPending("closed");
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
        return allFailed(target, count, error, null);
    }

    private static PingResult allFailed(InetAddress target, int count, PingError error,
                                        String detail) {
        List<PingProbe> probes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            probes.add(PingProbe.failed(i, error));
        }
        return PingResult.of(target, probes, error, detail);
    }

    /**
     * One family's reader is dead: record why, so {@code ping()} and {@code capabilities()}
     * report it honestly from now on, and fail every probe still waiting on it. The other
     * family keeps working — its socket and its thread are its own.
     */
    private void failReader(boolean v4, String why) {
        if (v4) {
            v4ReaderFailure = why;
        } else {
            v6ReaderFailure = why;
        }
        // Sequences are shared across families, so the map cannot tell a v4 probe from a
        // v6 one; failing all of them is the honest over-approximation, and they carry why.
        failPending(why);
    }

    /** Claims each probe with {@code remove(key, value)} before failing it (§13.23-B, S13). */
    private void failPending(String why) {
        inFlight.forEach((seq, probe) -> {
            if (inFlight.remove(seq, probe)) {
                probe.call.setDetail(why);
                probe.fail(PingError.IO);
            }
        });
    }
}
