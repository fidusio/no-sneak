package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.codecs.Ipv4Header;
import io.xlogistx.nosneak.net.codecs.Ipv6Header;
import io.xlogistx.nosneak.net.codecs.TtlDistance;
import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.ICMPPing;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservationKind;
import io.xlogistx.nosneak.net.common.ObservedNeighbor;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.ResolveSource;
import io.xlogistx.nosneak.net.common.Subscription;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;
import io.xlogistx.nosneak.net.util.IpMacCache;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * ARP, NDP and passive observation on Linux, over {@code AF_PACKET}.
 * <p>
 * Two TYPED sockets rather than one {@code ETH_P_ALL} socket, so the kernel does
 * the filtering and each reader thread has one job: {@code ETH_P_ARP} and
 * {@code ETH_P_IPV6}. Both use {@code SOCK_DGRAM}, not {@code SOCK_RAW}, so the
 * kernel prepends and strips the Ethernet header — no Ethernet header is ever
 * hand-built here, unlike the pcap backend.
 * <p>
 * Three consequences of {@code SOCK_DGRAM} that are the usual source of bugs on
 * this path, all handled below:
 * <ol>
 *   <li>On SEND, the on-wire ethertype comes from {@code sll_protocol} in the
 *       DESTINATION sockaddr, not from the socket's protocol argument.</li>
 *   <li>On RECEIVE, there is no ethertype in the buffer — it arrives in
 *       {@code sll_protocol} of the sockaddr {@code recvfrom} fills in. Parsing one
 *       out of the payload would read the ARP hardware type instead.</li>
 *   <li>The source MAC arrives in {@code sll_addr} of that same sockaddr, which is
 *       what catches a mismatch against the ARP payload's own sender address.</li>
 * </ol>
 */
public final class LinuxHostDiscovery implements HostDiscovery {

    private static final int RECEIVE_BUFFER = 65536;
    private static final Duration RETRANSMIT = Duration.ofSeconds(1);
    private static final int SOLICIT_ATTEMPTS = 3;


    private final NicBinding binding;
    private final Arena arena = Arena.ofShared();
    private final MemorySegment state = arena.allocate(Libc.CAPTURE);

    private final int arpSocket;
    private final int ndpSocket;

    /**
     * {@code ETH_P_IP}, for PASSIVE LEARNING only — nothing is ever sent on it.
     * <p>
     * Every Ethernet frame carries its sender's MAC, so ordinary IPv4 traffic teaches us
     * the segment's IP-to-MAC map for free. That matters because broadcast ARP is not
     * universally delivered: an access point buffers broadcast against the DTIM interval
     * and commonly suppresses it, so a station can be fully reachable by unicast while
     * never answering a broadcast ARP. Its ICMP echo REPLY, however, is unicast straight
     * back to us — and its source MAC is exactly the address we could not solicit.
     * <p>
     * This is the third socket per NIC, taking the reader arithmetic from §2.0's
     * {@code 2+2N} to {@code 2+3N}. It is worth the thread: the alternative is
     * consulting the kernel's own neighbour table, which only ever knows what the kernel
     * has already resolved and is therefore useless in precisely the case that needs it.
     */
    private final int ipSocket;

    private final IpMacCache cache = IpMacCache.withDefaults(256);
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final ConcurrentHashMap<InetAddress, PendingResolve> pending = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Consumer<ObservedNeighbor>> observers =
            new CopyOnWriteArrayList<>();

    private final Object arpSendLock = new Object();
    private final Object ndpSendLock = new Object();

    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private final List<Thread> readers = new ArrayList<>(2);

    /** Set once by the factory, before publication (§3.2). */
    private volatile ICMPPing pinger;
    private volatile boolean promiscuous;


    private LinuxHostDiscovery(NicBinding binding, int arpSocket, int ndpSocket, int ipSocket,
                               ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        this.binding = binding;
        this.arpSocket = arpSocket;
        this.ndpSocket = ndpSocket;
        this.ipSocket = ipSocket;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
    }

    /**
     * Opens both {@code AF_PACKET} sockets, BINDS each to this interface, and
     * starts the reader threads.
     * <p>
     * The bind is not optional: an unbound {@code AF_PACKET} socket receives from
     * EVERY interface, so the eth0 instance would otherwise learn eth1's
     * neighbours into a cache that claims to be per-binding.
     */
    public static LinuxHostDiscovery open(NicBinding binding,
                                          ScheduledExecutorService scheduler,
                                          ExecutorService dispatcher,
                                          boolean promiscuous) throws DiscoveryException {
        if (!binding.supportsLayer2()) {
            throw new DiscoveryException("Interface " + binding.javaName()
                    + " has no hardware address, so it cannot originate ARP or NDP. "
                    + "Use ICMPPing for liveness on such interfaces.");
        }
        LinuxHostDiscovery backend = null;
        try (Arena bootstrapArena = Arena.ofConfined()) {
            MemorySegment bootstrap = bootstrapArena.allocate(Libc.CAPTURE);
            int arp = Libc.socket(bootstrap, Libc.AF_PACKET, Libc.SOCK_DGRAM,
                                  Libc.htons(Libc.ETH_P_ARP) & 0xFFFF);
            int ndp;
            int ip;
            try {
                ndp = Libc.socket(bootstrap, Libc.AF_PACKET, Libc.SOCK_DGRAM,
                                  Libc.htons(Libc.ETH_P_IPV6) & 0xFFFF);
            } catch (DiscoveryException e) {
                Libc.closeQuietly(bootstrap, arp);
                throw e;
            }
            try {
                ip = Libc.socket(bootstrap, Libc.AF_PACKET, Libc.SOCK_DGRAM,
                                 Libc.htons(Libc.ETH_P_IP) & 0xFFFF);
            } catch (DiscoveryException e) {
                Libc.closeQuietly(bootstrap, arp);
                Libc.closeQuietly(bootstrap, ndp);
                throw e;
            }
            backend = new LinuxHostDiscovery(binding, arp, ndp, ip, scheduler, dispatcher);
            backend.bindToInterface(arp, Libc.ETH_P_ARP);
            backend.bindToInterface(ndp, Libc.ETH_P_IPV6);
            backend.bindToInterface(ip, Libc.ETH_P_IP);
            Libc.setReceiveTimeout(backend.arena, backend.state, arp);
            Libc.setReceiveTimeout(backend.arena, backend.state, ndp);
            Libc.setReceiveTimeout(backend.arena, backend.state, ip);
            if (promiscuous) {
                backend.setPromiscuous(true);
            }
            backend.startReaders();
            return backend;
        } catch (DiscoveryException | RuntimeException e) {
            if (backend != null) {
                backend.close();
            }
            throw e;
        }
    }

    private void bindToInterface(int fd, int ethertype) throws DiscoveryException {
        MemorySegment sa = arena.allocate(Libc.SOCKADDR_LL);
        sa.fill((byte) 0);
        sa.set(JAVA_SHORT, 0, (short) Libc.AF_PACKET);
        sa.set(JAVA_SHORT, Libc.SLL_PROTOCOL, Libc.htons(ethertype));
        sa.set(JAVA_INT, Libc.SLL_IFINDEX, binding.ifIndex());
        try {
            int rc = (int) Libc.Handles.BIND.invokeExact(state, fd, sa, (int) Libc.SOCKADDR_LL.byteSize());
            if (rc != 0) {
                throw new DiscoveryException("bind(AF_PACKET, ifIndex=" + binding.ifIndex()
                        + ") failed: " + Libc.errnoName(Libc.errno(state)));
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("bind() downcall failed", t);
        }
    }

    /** Required for observe() to see third-party traffic on a switched network. */
    private void setPromiscuous(boolean enable) throws DiscoveryException {
        Libc.setPromiscuous(arena, state, arpSocket, binding.ifIndex(), enable);
        Libc.setPromiscuous(arena, state, ndpSocket, binding.ifIndex(), enable);
        this.promiscuous = enable;
    }

    // ---- HostDiscovery ----

    @Override
    public NicBinding binding() {
        return binding;
    }

    @Override
    public DiscoveryCapabilities capabilities() {
        ICMPPing p = pinger;
        return new DiscoveryCapabilities(
                p != null && p.capabilities().icmpV4(),
                p != null && p.capabilities().icmpV6(),
                true,    // activeArp
                true,    // activeNdp - AF_PACKET, per the section 12.1 decision
                true,    // passiveObservation
                true,    // rawEvidence
                p != null && p.capabilities().ttlAvailable(),
                p != null && p.capabilities().offLinkIcmp(),
                DiscoveryCapabilities.Backend.LINUX_NATIVE);
    }

    @Override
    public Optional<ICMPPing> icmpPing() {
        return Optional.ofNullable(pinger);
    }

    /** Set-once, by the factory, before this object is published. */
    @Override
    public void attachPinger(ICMPPing p) {
        if (this.pinger == null) {
            this.pinger = p;
        }
    }

    @Override
    public IpMacCache cache() {
        return cache;
    }

    @Override
    public CompletableFuture<ResolveResult> resolve(InetAddress target, Duration timeout) {
        return resolve(target, timeout, true);
    }

    /**
     * @param provoke whether to emit the ICMP echo that makes the target reveal its MAC
     *                (see {@link #provokeKernelResolution}). {@code sweep()} passes
     *                {@code false} because it already pings every host CONCURRENTLY with
     *                the resolve, which achieves the same thing — provoking as well
     *                would put two echoes on the wire per host, and on a mostly-dead /24
     *                that is hundreds of wasted probes.
     */
    private CompletableFuture<ResolveResult> resolve(InetAddress target, Duration timeout,
                                                     boolean provoke) {
        Instant started = Instant.now();

        Optional<IpMacCache.Entry> cached = cache.get(target);
        if (cached.isPresent() && cached.get().hasMac()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, cached.get().mac(), ResolveSource.CACHE_HIT,
                    Duration.between(started, Instant.now())));
        }
        // Our own address: nothing on the segment will answer an ARP request for it,
        // because the only host that owns it is the one asking. Without this the call
        // burns the whole timeout and reports TIMEOUT for a MAC we have held since
        // construction.
        if (binding.isLocalAddress(target) && binding.supportsLayer2()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, binding.hardwareAddress(), ResolveSource.LOCAL_INTERFACE,
                    Duration.between(started, Instant.now())));
        }
        if (!binding.isOnLink(target)) {
            // Nothing off-link answers ARP or NDP; that is not a failure to report
            // as a timeout after waiting.
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        PendingResolve entry = pending.computeIfAbsent(target, k -> new PendingResolve(target));
        CompletableFuture<ResolveResult> future = entry.await();

        if (entry.started.compareAndSet(false, true)) {
            cache.markIncomplete(target);
            // Provoke FIRST, so the kernel's resolution and our broadcast are in flight
            // together. Deferring this to the first retry cost a full second on exactly
            // the hosts it exists for: measured on a broadcast-suppressed host, resolve
            // was bimodal at ~300 ms (it happened to speak) or ~1015 ms (it did not, and
            // we waited for the retry). Firing at attempt 0 collapses that.
            if (provoke) {
                provokeKernelResolution(target, Math.max(1, timeout.toMillis()));
            }
            solicit(target, 0);
            scheduleRetries(target, timeout);
        }
        return future;
    }

    /** ARP 3 attempts 1s apart; NDP the same, which is RFC 4861's RETRANS_TIMER. */
    private void scheduleRetries(InetAddress target, Duration timeout) {
        long budget = Math.max(1, timeout.toMillis());
        for (int attempt = 1; attempt < SOLICIT_ATTEMPTS; attempt++) {
            long at = attempt * RETRANSMIT.toMillis();
            if (at >= budget) {
                break;
            }
            int retry = attempt;
            scheduler.schedule(() -> {
                if (pending.containsKey(target)) {
                    solicit(target, retry);
                }
            }, at, TimeUnit.MILLISECONDS);
        }
        scheduler.schedule(() -> {
            PendingResolve dropped = pending.remove(target);
            if (dropped != null) {
                // A send that the kernel rejected is an ERROR, not a TIMEOUT: nothing
                // ever went out, so "nobody answered" would misreport the cause. The
                // flag is per-resolve, so one transient failure cannot make every
                // later timeout claim to be that error.
                ResolveOutcome outcome = dropped.sendError == null
                        ? ResolveOutcome.TIMEOUT
                        : ResolveOutcome.ERROR;
                dropped.completeAll(ResolveResult.notResolved(target, outcome,
                        Duration.between(dropped.startedAt, Instant.now())));
            }
        }, budget, TimeUnit.MILLISECONDS);
    }

    /**
     * Makes the KERNEL resolve {@code target}, by sending it one ICMP echo and throwing
     * the result away.
     * <p>
     * The echo is a means, not an end. A host cannot be sent an IP datagram until its
     * link-layer address is known, so the kernel performs neighbour resolution as a side
     * effect of the attempt — and it does so <em>whether or not the echo is ever
     * answered</em>, which is why this works against an ICMP-filtered host. That is the
     * same separation §3.2 draws between ARP as the liveness oracle and {@code icmpAlive}
     * as a distinct fact, used here to provoke rather than to interpret.
     * <p>
     * §7.4 specifies the same move for macOS — "emit traffic to the target — the ICMP echo
     * from {@code ping()} is sufficient". macOS then has to poll the kernel's neighbour
     * table, because it has no way to watch the wire. We do: the echo REPLY comes back
     * unicast and {@link #onIpv4} reads the sender's MAC straight off the frame, which is
     * our own evidence rather than the kernel's opinion, and arrives the moment it lands
     * instead of on a polling interval.
     * <p>
     * <b>Scoped, because the cost is a packet on someone's network.</b> It fires only for
     * IPv4, only when a pinger is wired, only when we do not already hold a hint, and
     * only for callers that are not pinging anyway — {@code sweep()} opts out, since it
     * runs its own echo concurrently with the resolve and a second one would double the
     * probes on a mostly-dead range.
     * <p>
     * It fires at attempt 0 rather than on the first retry. Deferring it looked frugal —
     * hosts that answer broadcast normally never need it — but those hosts resolve in
     * ~10 ms and never reach the retry either, so the saving was imaginary while the cost
     * was a flat extra second on every host that did need it.
     * <p>
     * <b>What it does not fix.</b> If the kernel holds no entry at all, its own cold
     * resolution is also a broadcast ARP, and an access point that suppresses ours
     * suppresses the kernel's too. This rescues the cases where the kernel can get there
     * and we cannot — a stale entry it revalidates by unicast, or an {@code INCOMPLETE}
     * row that completes while we wait — not the genuinely never-seen host.
     * <p>
     * No recursion: Linux {@code ping()} routes through the kernel and never calls
     * {@code resolve()}. That is NOT true on Windows, where the two roles are one object.
     */
    private void provokeKernelResolution(InetAddress target, long budgetMillis) {
        ICMPPing p = pinger;
        if (p == null || !(target instanceof Inet4Address) || unicastHint(target).isPresent()) {
            return;
        }
        try {
            p.ping(target, 1, Duration.ofMillis(Math.min(budgetMillis, 1000)));
        } catch (RuntimeException ignored) {
            // Best effort. A pinger that refuses just means no hint; the broadcast
            // retries continue regardless.
        }
        // No polling: the reply, if it comes, arrives on the ETH_P_IP reader and
        // onIpv4 fires the unicast solicitation from there.
    }

    /**
     * Sends one solicitation and records a native send failure against the in-flight
     * entry, so the resolve can report ERROR rather than a TIMEOUT that never
     * transmitted.
     */
    private void solicit(InetAddress target, int attempt) {
        boolean sent = target instanceof Inet4Address
                ? sendArp(target, attempt)
                : sendNeighborSolicitation(target);
        if (!sent) {
            PendingResolve entry = pending.get(target);
            if (entry != null) {
                entry.sendError = lastSendError;
            }
        }
    }

    /**
     * Sends one ARP request, BROADCAST on the first attempt and UNICAST on later ones
     * whenever a MAC hint is available.
     * <p>
     * Broadcast alone is not sufficient in practice. Wi-Fi access points buffer
     * broadcast and multicast against the DTIM interval and commonly suppress or
     * proxy it, so a station can be fully reachable by unicast while never seeing a
     * broadcast ARP at all. Measured on this segment: a host answered 0 of 3
     * broadcast requests and 3 of 3 unicast requests to the same MAC, in the same
     * second, while answering ICMP throughout. The kernel does not hit this because
     * it revalidates a known neighbour with unicast probes rather than broadcast.
     * <p>
     * Both frames go out on attempt 0 when a hint exists, because neither alone is
     * safe: unicast to a stale MAC reaches a host that has moved, and broadcast alone
     * is the case that fails here. Later attempts are unicast only, the hint having
     * already been shown to be the useful one. Note {@code sweep()} with the default
     * one-second per-host budget gets ONLY attempt 0, so covering both paths there is
     * what makes a swept host resolvable at all.
     * <p>
     * A hint is only ever a hint. Resolution still requires a genuine reply on our own
     * socket, so the reported {@link ResolveSource} remains {@code ACTIVE_ARP} and a
     * wrong hint costs one wasted frame rather than a wrong answer.
     */
    private boolean sendArp(InetAddress target, int attempt) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            lastSendError = "no local IPv4 address on " + binding.javaName()
                    + " to use as the ARP sender address";
            return false;
        }
        byte[] payload = ArpPacket.request(binding.hardwareAddress(),
                                           source.get().address().getAddress(),
                                           target.getAddress());
        Optional<MacAddress> hint = unicastHint(target);
        // Either frame reaching the wire is enough for the solicitation to count as
        // sent — the point of sending both is that they fail independently.
        boolean sent = hint.isPresent()
                && sendPacket(arpSocket, arpSendLock, Libc.ETH_P_ARP, hint.get().bytes(), payload);
        if (hint.isEmpty() || attempt == 0) {
            sent |= sendPacket(arpSocket, arpSendLock, Libc.ETH_P_ARP,
                               MacAddress.BROADCAST.bytes(), payload);
        }
        return sent;
    }

    /**
     * A MAC to aim a unicast ARP request at, from {@link IpMacCache} — which is to say,
     * from something this process saw on the wire itself.
     * <p>
     * An earlier version fell back to reading the kernel's {@code /proc/net/arp}. That
     * was removed: it can only ever report what the kernel has already resolved, and the
     * kernel resolves a cold neighbour by BROADCAST — the very thing being suppressed.
     * Measured directly: with the kernel entry flushed, a resolve still timed out and the
     * kernel's own entry sat at {@code INCOMPLETE}, its broadcast unanswered exactly like
     * ours. Passive learning on the {@code ETH_P_IP} socket replaces it and is strictly
     * better — it is our own observation, it carries {@code PASSIVE} provenance, and it
     * catches any host that speaks at all rather than only ones the kernel happens to
     * have talked to.
     * <p>
     * A {@code STALE} entry is accepted deliberately — staleness is precisely the state
     * in which a neighbour wants revalidating, and it still carries the only MAC that
     * makes a unicast probe possible. {@code INCOMPLETE} entries carry none and are
     * skipped, which also stops {@code resolve()} reading back the placeholder it just
     * wrote via {@code markIncomplete}.
     */
    private Optional<MacAddress> unicastHint(InetAddress target) {
        return cache.get(target)
                .filter(IpMacCache.Entry::hasMac)
                .map(IpMacCache.Entry::mac)
                .filter(mac -> !mac.isBroadcast() && !mac.isMulticast() && !mac.isZero());
    }

    /**
     * NDP goes over {@code AF_PACKET} with a hand-built IPv6 header, per the §12.1
     * decision — the socket exists for ARP anyway, and this keeps full-frame raw
     * evidence for NS/NA.
     * <p>
     * The hop limit MUST be 255 (RFC 4861 §7.1.1); the builder pins it so it
     * cannot be got wrong.
     */
    private boolean sendNeighborSolicitation(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            lastSendError = "no local IPv6 address on " + binding.javaName()
                    + " to source a Neighbor Solicitation from";
            return false;
        }
        byte[] src = source.get().address().getAddress();
        byte[] targetRaw = target.getAddress();
        byte[] ns = Icmp6.neighborSolicitation(src, targetRaw, binding.hardwareAddress());
        byte[] dst = Icmp6.solicitedNodeMulticast(targetRaw);
        byte[] header = Ipv6Header.forNeighborDiscovery(src, dst, ns.length);

        byte[] payload = new byte[header.length + ns.length];
        System.arraycopy(header, 0, payload, 0, header.length);
        System.arraycopy(ns, 0, payload, header.length, ns.length);

        return sendPacket(ndpSocket, ndpSendLock, Libc.ETH_P_IPV6,
                          Icmp6.solicitedNodeMac(targetRaw).bytes(), payload);
    }

    /**
     * The ONE send path for this backend, serialized per socket — the §12.7 choke
     * point. If global pacing is ever needed, a writer thread replaces the body
     * here and nothing else changes.
     */
    /** @return true when the frame was handed to the kernel; false leaves errno reported. */
    private boolean sendPacket(int fd, Object lock, int ethertype, byte[] destMac, byte[] payload) {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, payload);
            MemorySegment dest = scratch.allocate(Libc.SOCKADDR_LL);
            Libc.fillSockaddrLl(dest, binding.ifIndex(), ethertype, destMac);
            long sent;
            int errno;
            synchronized (lock) {
                sent = (long) Libc.Handles.SENDTO.invokeExact(state, fd, buf,
                        (long) payload.length, 0, dest, (int) Libc.SOCKADDR_LL.byteSize());
                errno = sent < 0 ? Libc.errno(state) : 0;
            }
            if (sent >= 0) {
                return true;
            }
            lastSendError = "sendto(ethertype=0x" + Integer.toHexString(ethertype)
                    + ") failed: " + Libc.errnoName(errno);
            return false;
        } catch (Throwable t) {
            lastSendError = "sendto downcall failed: " + t;
            return false;
        }
    }

    /**
     * The reason the last send failed, valid only immediately after a {@code false}
     * from {@link #sendPacket}. Read into the owning {@link PendingResolve} straight
     * away rather than consulted later: this module has no logger, so the caller's
     * result is the only place a native error can surface, and a field that outlives
     * one solicitation would make every subsequent timeout claim to be that error.
     */
    private volatile String lastSendError;

    @Override
    public Subscription observe(Consumer<ObservedNeighbor> onNeighbor) {
        observers.add(onNeighbor);
        if (!promiscuous) {
            // Without promiscuous mode this still sees broadcast ARP and multicast
            // NS/NA, which is most of what matters on a switched segment.
            try {
                setPromiscuous(true);
            } catch (DiscoveryException ignored) {
                // Keep the subscription: degraded visibility beats refusing.
            }
        }
        return () -> observers.remove(onNeighbor);
    }

    @Override
    public CompletableFuture<SweepSummary> sweep(CidrRange range, SweepOptions options,
                                                 Consumer<HostRecord> onHost) {
        if (range.hostCount().compareTo(BigInteger.valueOf(options.maxHosts())) > 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException(
                    "Range " + range + " holds " + range.hostCount()
                    + " addresses, above maxHosts " + options.maxHosts()
                    + "; use discoverIpv6Segment for v6 segments"));
        }
        Instant started = Instant.now();
        List<InetAddress> targets = range.hosts().toList();
        AtomicInteger alive = new AtomicInteger();
        AtomicInteger macs = new AtomicInteger();
        AtomicInteger icmp = new AtomicInteger();
        Semaphore window = new Semaphore(options.maxInFlight());
        // maxInFlight bounds how many probes are OUTSTANDING; the rate limiter
        // bounds how fast they leave. They are different constraints (spec 3.5).
        io.xlogistx.nosneak.net.util.RateLimiter pacer =
                io.xlogistx.nosneak.net.util.RateLimiter.perSecond(options.maxPacketsPerSecond());
        // Two ARP frames per host, not one: a hinted target gets both a unicast and a
        // broadcast solicitation on the first attempt (see sendArp). Reserving the
        // worst case keeps the emitted rate at or UNDER maxPacketsPerSecond, which is
        // the only direction a safety cap may err in.
        int packetsPerHost = (options.doMac() ? 2 : 0)
                + (options.doIcmp() ? options.pingCount() : 0);

        List<CompletableFuture<Void>> all = new ArrayList<>(targets.size());
        for (InetAddress target : targets) {
            all.add(CompletableFuture.completedFuture(null).thenComposeAsync(ignored -> {
                try {
                    window.acquire();
                    io.xlogistx.nosneak.net.util.RateLimiter.acquire(pacer, packetsPerHost);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return CompletableFuture.completedFuture(null);
                }
                return sweepOne(target, options, onHost, alive, macs, icmp)
                        .whenComplete((r, t) -> window.release());
            }, dispatcher));
        }
        return CompletableFuture.allOf(all.toArray(CompletableFuture[]::new))
                .thenApply(ignored -> new SweepSummary(targets.size(), alive.get(), macs.get(),
                        icmp.get(), Duration.between(started, Instant.now())));
    }

    private CompletableFuture<Void> sweepOne(InetAddress target, SweepOptions options,
                                             Consumer<HostRecord> onHost, AtomicInteger alive,
                                             AtomicInteger macs, AtomicInteger icmp) {
        // NEVER probe the local network or directed broadcast: an echo to a
        // directed broadcast is answered by every host at once.
        if (binding.isNetworkOrBroadcast(target)) {
            return CompletableFuture.completedFuture(null);
        }
        // BOTH probes start NOW. They used to be sequenced — resolve, then ping — and
        // that quietly defeated passive learning for the hosts that need it most. The
        // echo REPLY carries the target's MAC in its Ethernet header, and onIpv4 turns
        // that into an immediate unicast ARP; but if the ping only starts once resolve
        // has finished, the reply always lands after resolve has already given up. The
        // symptom is a host reported icmp-alive with an empty MAC — precisely the two
        // facts §3.2 insists are independent, collapsed by an ordering accident.
        // Running them concurrently costs nothing: both are bounded by perHostTimeout,
        // so wall time is the slower of the two rather than their sum.
        CompletableFuture<ResolveResult> mac = options.doMac()
                ? resolve(target, options.perHostTimeout(), false)
                : CompletableFuture.completedFuture(ResolveResult.notResolved(
                        target, ResolveOutcome.UNSUPPORTED, Duration.ZERO));

        ICMPPing p = pinger;
        // DEGRADES CLEANLY: no pinger means ARP alone still finds every on-link host -
        // a reduced result, not an error.
        CompletableFuture<PingResult> pinged = options.doIcmp() && p != null
                ? p.ping(target, options.pingCount(), options.perHostTimeout())
                : CompletableFuture.completedFuture(PingResult.of(target, List.of(), null));

        return mac.thenAcceptBoth(pinged, (resolved, result) -> {
            boolean haveMac = resolved.resolved();
            if (!haveMac && !result.reachable()) {
                return;
            }
            alive.incrementAndGet();
            if (haveMac) {
                macs.incrementAndGet();
            }
            if (result.reachable()) {
                icmp.incrementAndGet();
            }
            int ttl = result.probes().stream().filter(PingProbe::hasTtl)
                            .mapToInt(PingProbe::ttlOrHopLimit).findFirst()
                            .orElse(PingProbe.TTL_UNAVAILABLE);
            HostRecord record = new HostRecord(target, resolved.mac(), result.reachable(),
                    result.reachable() ? Optional.of(result.avgRtt()) : Optional.empty(),
                    ttl, ttl > 0 ? TtlDistance.hopCount(ttl) : Optional.empty(),
                    haveMac ? resolved.source() : null, Instant.now());
            dispatcher.execute(() -> onHost.accept(record));
        });
    }

    /**
     * Echoes to the all-nodes link-local multicast address, SCOPED to this
     * interface — {@code ff02::1} cannot be routed without a scope id, and an
     * unbound pinger cannot guess which segment is meant.
     */
    @Override
    public CompletableFuture<SweepSummary> discoverIpv6Segment(SweepOptions options,
                                                               Consumer<HostRecord> onHost) {
        Instant started = Instant.now();
        ICMPPing p = pinger;
        CompletableFuture<PingResult> echoed;
        if (p != null && options.doIcmp()) {
            try {
                InetAddress allNodes = Inet6Address.getByAddress(
                        null, InetAddress.ofLiteral("ff02::1").getAddress(), binding.ifIndex());
                echoed = p.ping(allNodes, Math.max(1, options.pingCount()),
                                options.perHostTimeout());
            } catch (java.net.UnknownHostException e) {
                echoed = CompletableFuture.completedFuture(null);
            }
        } else {
            echoed = CompletableFuture.completedFuture(null);
        }

        return echoed.thenApply(ignored -> {
            // Responders land in the cache through the NDP reader; report whatever
            // is known, active or passive.
            List<HostRecord> found = new ArrayList<>();
            for (IpMacCache.Entry e : cache.snapshot()) {
                if (e.ip() instanceof Inet6Address && e.hasMac()) {
                    found.add(new HostRecord(e.ip(), Optional.of(e.mac()), false,
                            Optional.empty(), PingProbe.TTL_UNAVAILABLE, Optional.empty(),
                            e.provenance(), e.lastSeen()));
                }
            }
            found.forEach(r -> dispatcher.execute(() -> onHost.accept(r)));
            return new SweepSummary(found.size(), found.size(), found.size(), 0,
                                    Duration.between(started, Instant.now()));
        });
    }

    // ---- capture ----

    private void startReaders() {
        readers.add(startReader("nosneak-arp-" + binding.javaName(),
                                () -> readLoop(arpSocket)));
        readers.add(startReader("nosneak-ndp-" + binding.javaName(),
                                () -> readLoop(ndpSocket)));
        readers.add(startReader("nosneak-ip-" + binding.javaName(),
                                () -> readLoop(ipSocket)));
    }

    private Thread startReader(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private void readLoop(int fd) {
        try (Arena local = Arena.ofConfined()) {
            MemorySegment localState = local.allocate(Libc.CAPTURE);
            MemorySegment buf = local.allocate(RECEIVE_BUFFER);
            MemorySegment from = local.allocate(Libc.SOCKADDR_LL);
            MemorySegment fromLen = local.allocate(JAVA_INT);

            while (running) {
                fromLen.set(JAVA_INT, 0, (int) Libc.SOCKADDR_LL.byteSize());
                long n;
                try {
                    n = (long) Libc.Handles.RECVFROM.invokeExact(localState, fd, buf,
                            (long) RECEIVE_BUFFER, 0, from, fromLen);
                } catch (Throwable t) {
                    return;
                }
                if (n < 0) {
                    // EAGAIN is the SO_RCVTIMEO tick that makes shutdown possible and
                    // is expected several times a second. Anything else is a real
                    // error, and spinning on it would burn a core silently, so back
                    // off to the same cadence rather than retrying flat out.
                    if (!Libc.isTimeout(Libc.errno(localState))) {
                        try {
                            Thread.sleep(Libc.RECV_TIMEOUT_USEC / 1000);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    continue;
                }
                // The ethertype is NOT in the buffer - the kernel stripped the
                // Ethernet header. It is here, in the sockaddr recvfrom filled in.
                int ethertype = Libc.ntohs(from.get(JAVA_SHORT, Libc.SLL_PROTOCOL));
                int pkttype = from.get(JAVA_BYTE, Libc.SLL_PKTTYPE) & 0xFF;
                int halen = from.get(JAVA_BYTE, Libc.SLL_HALEN) & 0xFF;
                MacAddress frameSource = null;
                if (halen == MacAddress.LENGTH) {
                    byte[] raw = new byte[MacAddress.LENGTH];
                    MemorySegment.copy(from, JAVA_BYTE, Libc.SLL_ADDR, raw, 0, MacAddress.LENGTH);
                    frameSource = new MacAddress(raw);
                }
                // AF_PACKET loops our OWN sends back to every AF_PACKET socket, tagged
                // PACKET_OUTGOING. Learning from those would teach us our own MAC for
                // every address we probe.
                if (pkttype == Libc.PACKET_OUTGOING) {
                    continue;
                }
                byte[] payload = buf.asSlice(0, n).toArray(JAVA_BYTE);
                try {
                    if (ethertype == Libc.ETH_P_ARP) {
                        onArp(payload, frameSource);
                    } else if (ethertype == Libc.ETH_P_IPV6) {
                        onIpv6(payload);
                    } else if (ethertype == Libc.ETH_P_IP) {
                        onIpv4(payload, frameSource);
                    }
                } catch (RuntimeException ignored) {
                    // a malformed frame must never kill the reader
                }
            }
        }
    }

    private void onArp(byte[] payload, MacAddress frameSource) {
        ArpPacket.ArpView arp = ArpPacket.parse(payload, 0, payload.length).orElse(null);
        if (arp == null || arp.sha().isZero()) {
            return;
        }
        InetAddress sender = address(arp.spa());
        if (sender == null) {
            return;
        }
        // The payload SHA is authoritative, but a mismatch against the frame's own
        // source address is spoofing evidence worth surfacing through the cache's
        // conflict counter.
        MacAddress mac = arp.sha();
        cache.observe(sender, mac, arp.isReply() ? ResolveSource.ACTIVE_ARP : ResolveSource.PASSIVE);
        if (frameSource != null && !frameSource.equals(mac)) {
            cache.observe(sender, frameSource, ResolveSource.PASSIVE);
        }
        completeResolve(sender, mac, ResolveSource.ACTIVE_ARP);

        ObservationKind kind = arp.isGratuitous() ? ObservationKind.GRATUITOUS_ARP
                : arp.isReply() ? ObservationKind.ARP_REPLY : ObservationKind.ARP_REQUEST;
        notifyObservers(new ObservedNeighbor(sender, mac, kind, Instant.now()));
    }

    /**
     * Learns an IP-to-MAC binding from ordinary IPv4 traffic, and — when a resolve for
     * that address is in flight — immediately aims a unicast ARP at what it just learned.
     * <p>
     * This is the answer to the broadcast-suppressed host. Its echo reply is unicast
     * straight back to us, so its source MAC arrives here even though the same host will
     * not answer a broadcast ARP. The MAC is taken from {@code sll_addr} rather than
     * from any payload field, because the Ethernet header is the one place a sender
     * cannot omit it.
     * <p>
     * The learned MAC is a HINT, never an answer. It is recorded as {@code PASSIVE}
     * provenance, and the pending resolve still completes only when a real ARP reply
     * arrives on the ARP socket — which is why firing the solicitation from here, rather
     * than completing the future, keeps {@code ResolveSource.ACTIVE_ARP} honest.
     * <p>
     * Firing on learning rather than polling on a timer is what makes this fast: the
     * §4.5 retransmit grid is a full second wide, and an echo reply comes back in
     * single-digit milliseconds.
     */
    private void onIpv4(byte[] payload, MacAddress frameSource) {
        if (frameSource == null || frameSource.isZero() || frameSource.isMulticast()) {
            return;
        }
        Ipv4Header.View ip = Ipv4Header.parse(payload, 0, payload.length).orElse(null);
        if (ip == null) {
            return;
        }
        InetAddress source = address(ip.src4());
        if (source == null || source.isAnyLocalAddress() || !binding.isOnLink(source)
                || binding.isLocalAddress(source)) {
            return;
        }
        cache.observe(source, frameSource, ResolveSource.PASSIVE);
        if (pending.containsKey(source)) {
            sendArp(source, 1);
        }
    }

    private void onIpv6(byte[] payload) {
        Ipv6Header.View ip = Ipv6Header.parse(payload, 0, payload.length).orElse(null);
        if (ip == null || ip.nextHeader() != Ipv6Header.NEXT_HEADER_ICMPV6) {
            return;
        }
        int off = Ipv6Header.LENGTH;
        int len = Math.min(ip.payloadLength(), payload.length - off);
        if (len <= 0) {
            return;
        }
        // RFC 4861 7.1.1: NS and NA whose hop limit is not 255 have crossed a
        // router and MUST be discarded. This is the on-link attack defence.
        if (!Ipv6Header.isValidNeighborDiscovery(ip)) {
            return;
        }

        Icmp6.parseAdvertisement(payload, off, len).ifPresent(na -> {
            if (na.targetMac() == null) {
                return;
            }
            InetAddress target = address(na.targetIp16());
            if (target == null) {
                return;
            }
            cache.observe(target, na.targetMac(), ResolveSource.ACTIVE_NDP);
            completeResolve(target, na.targetMac(), ResolveSource.ACTIVE_NDP);
            notifyObservers(new ObservedNeighbor(target, na.targetMac(),
                                                 ObservationKind.NDP_NA, Instant.now()));
        });

        Icmp6.parseSolicitation(payload, off, len).ifPresent(ns -> {
            if (ns.sourceMac() == null) {
                return;
            }
            InetAddress source = address(ip.src16());
            if (source == null || source.isAnyLocalAddress()) {
                return;   // duplicate address detection uses the unspecified source
            }
            cache.observe(source, ns.sourceMac(), ResolveSource.PASSIVE);
            notifyObservers(new ObservedNeighbor(source, ns.sourceMac(),
                                                 ObservationKind.NDP_NS, Instant.now()));
        });
    }

    private void completeResolve(InetAddress target, MacAddress mac, ResolveSource source) {
        PendingResolve entry = pending.remove(target);
        if (entry != null) {
            entry.completeAll(ResolveResult.resolved(target, mac, source,
                    Duration.between(entry.startedAt, Instant.now())));
        }
    }

    private void notifyObservers(ObservedNeighbor neighbor) {
        if (observers.isEmpty()) {
            return;
        }
        // Never on the reader thread: a slow consumer must not stall capture.
        dispatcher.execute(() -> observers.forEach(o -> {
            try {
                o.accept(neighbor);
            } catch (RuntimeException ignored) {
                // one bad observer must not silence the rest
            }
        }));
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
        Libc.closeQuietly(state, arpSocket);
        Libc.closeQuietly(state, ndpSocket);
        Libc.closeQuietly(state, ipSocket);

        pending.values().forEach(p -> p.completeAll(
                ResolveResult.notResolved(p.target, ResolveOutcome.ERROR, Duration.ZERO)));
        pending.clear();
        observers.clear();
        try {
            arena.close();
        } catch (IllegalStateException e) {
            // a reader still inside a downcall; the fds are closed either way
        }
        // The pinger is BORROWED - never close it here. The scheduler and
        // dispatcher likewise.
    }

    private static InetAddress address(byte[] raw) {
        try {
            return InetAddress.getByAddress(raw);
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    /**
     * One in-flight solicitation, and every caller waiting on it.
     * <p>
     * The waiters share ONE {@link CompletableFuture} rather than each holding their
     * own. With a per-caller list there is a window between the reader thread's
     * {@code completeAll} — which completes the futures it can see and then clears
     * the list — and a concurrent {@code resolve()} that has already taken this entry
     * and is about to add its future to it. That late future would be completed by
     * nobody: the timeout task removes by key and finds the entry already gone, so it
     * never fires. In {@code sweep()} such a future feeds {@code allOf}, which would
     * then never complete and hang the whole sweep rather than fail it.
     * <p>
     * One shared future closes the window, because {@code complete} is idempotent and
     * a caller arriving after completion simply observes the finished result.
     */
    private static final class PendingResolve {
        final InetAddress target;
        final Instant startedAt = Instant.now();
        final AtomicBoolean started = new AtomicBoolean();

        /** Set when a solicitation for THIS target could not be transmitted at all. */
        volatile String sendError;

        private final CompletableFuture<ResolveResult> result = new CompletableFuture<>();

        PendingResolve(InetAddress target) {
            this.target = target;
        }

        /** A copy, so a caller cannot complete the shared future out from under the rest. */
        CompletableFuture<ResolveResult> await() {
            return result.copy();
        }

        void completeAll(ResolveResult outcome) {
            result.complete(outcome);
        }
    }
}
