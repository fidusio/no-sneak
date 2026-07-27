package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.Icmp6;
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

    private LinuxHostDiscovery(NicBinding binding, int arpSocket, int ndpSocket,
                               ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        this.binding = binding;
        this.arpSocket = arpSocket;
        this.ndpSocket = ndpSocket;
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
            try {
                ndp = Libc.socket(bootstrap, Libc.AF_PACKET, Libc.SOCK_DGRAM,
                                  Libc.htons(Libc.ETH_P_IPV6) & 0xFFFF);
            } catch (DiscoveryException e) {
                Libc.closeQuietly(bootstrap, arp);
                throw e;
            }
            backend = new LinuxHostDiscovery(binding, arp, ndp, scheduler, dispatcher);
            backend.bindToInterface(arp, Libc.ETH_P_ARP);
            backend.bindToInterface(ndp, Libc.ETH_P_IPV6);
            Libc.setReceiveTimeout(backend.arena, backend.state, arp);
            Libc.setReceiveTimeout(backend.arena, backend.state, ndp);
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
        Instant started = Instant.now();

        Optional<IpMacCache.Entry> cached = cache.get(target);
        if (cached.isPresent() && cached.get().hasMac()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, cached.get().mac(), ResolveSource.CACHE_HIT,
                    Duration.between(started, Instant.now())));
        }
        if (!binding.isOnLink(target)) {
            // Nothing off-link answers ARP or NDP; that is not a failure to report
            // as a timeout after waiting.
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        PendingResolve entry = pending.computeIfAbsent(target, k -> new PendingResolve(target));
        CompletableFuture<ResolveResult> future = new CompletableFuture<>();
        entry.waiters.add(future);

        if (entry.started.compareAndSet(false, true)) {
            cache.markIncomplete(target);
            solicit(target);
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
            scheduler.schedule(() -> {
                if (pending.containsKey(target)) {
                    solicit(target);
                }
            }, at, TimeUnit.MILLISECONDS);
        }
        scheduler.schedule(() -> {
            PendingResolve dropped = pending.remove(target);
            if (dropped != null) {
                dropped.completeAll(ResolveResult.notResolved(target, ResolveOutcome.TIMEOUT,
                        Duration.between(dropped.startedAt, Instant.now())));
            }
        }, budget, TimeUnit.MILLISECONDS);
    }

    private void solicit(InetAddress target) {
        if (target instanceof Inet4Address) {
            sendArp(target);
        } else {
            sendNeighborSolicitation(target);
        }
    }

    private void sendArp(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return;
        }
        byte[] payload = ArpPacket.request(binding.hardwareAddress(),
                                           source.get().address().getAddress(),
                                           target.getAddress());
        sendPacket(arpSocket, arpSendLock, Libc.ETH_P_ARP,
                   MacAddress.BROADCAST.bytes(), payload);
    }

    /**
     * NDP goes over {@code AF_PACKET} with a hand-built IPv6 header, per the §12.1
     * decision — the socket exists for ARP anyway, and this keeps full-frame raw
     * evidence for NS/NA.
     * <p>
     * The hop limit MUST be 255 (RFC 4861 §7.1.1); the builder pins it so it
     * cannot be got wrong.
     */
    private void sendNeighborSolicitation(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return;
        }
        byte[] src = source.get().address().getAddress();
        byte[] targetRaw = target.getAddress();
        byte[] ns = Icmp6.neighborSolicitation(src, targetRaw, binding.hardwareAddress());
        byte[] dst = Icmp6.solicitedNodeMulticast(targetRaw);
        byte[] header = Ipv6Header.forNeighborDiscovery(src, dst, ns.length);

        byte[] payload = new byte[header.length + ns.length];
        System.arraycopy(header, 0, payload, 0, header.length);
        System.arraycopy(ns, 0, payload, header.length, ns.length);

        sendPacket(ndpSocket, ndpSendLock, Libc.ETH_P_IPV6,
                   Icmp6.solicitedNodeMac(targetRaw).bytes(), payload);
    }

    /**
     * The ONE send path for this backend, serialized per socket — the §12.7 choke
     * point. If global pacing is ever needed, a writer thread replaces the body
     * here and nothing else changes.
     */
    private void sendPacket(int fd, Object lock, int ethertype, byte[] destMac, byte[] payload) {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, payload);
            MemorySegment dest = scratch.allocate(Libc.SOCKADDR_LL);
            Libc.fillSockaddrLl(dest, binding.ifIndex(), ethertype, destMac);
            synchronized (lock) {
                long ignored = (long) Libc.Handles.SENDTO.invokeExact(state, fd, buf,
                        (long) payload.length, 0, dest, (int) Libc.SOCKADDR_LL.byteSize());
            }
        } catch (Throwable ignored) {
            // A failed solicitation surfaces as a resolve timeout, which is the
            // caller-visible outcome either way.
        }
    }

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
        int packetsPerHost = 1 + (options.doIcmp() ? options.pingCount() : 0);

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
        CompletableFuture<ResolveResult> mac = options.doMac()
                ? resolve(target, options.perHostTimeout())
                : CompletableFuture.completedFuture(ResolveResult.notResolved(
                        target, ResolveOutcome.UNSUPPORTED, Duration.ZERO));

        return mac.thenCompose(resolved -> {
            boolean haveMac = resolved.resolved();
            ICMPPing p = pinger;
            // DEGRADES CLEANLY: no pinger means ARP alone still finds every
            // on-link host - a reduced result, not an error.
            CompletableFuture<PingResult> pinged = options.doIcmp() && p != null
                    ? p.ping(target, options.pingCount(), options.perHostTimeout())
                    : CompletableFuture.completedFuture(PingResult.of(target, List.of(), null));

            return pinged.thenAccept(result -> {
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
                    continue;   // EAGAIN tick from SO_RCVTIMEO
                }
                // The ethertype is NOT in the buffer - the kernel stripped the
                // Ethernet header. It is here, in the sockaddr recvfrom filled in.
                int ethertype = Libc.ntohs(from.get(JAVA_SHORT, Libc.SLL_PROTOCOL));
                int halen = from.get(JAVA_BYTE, Libc.SLL_HALEN) & 0xFF;
                MacAddress frameSource = null;
                if (halen == MacAddress.LENGTH) {
                    byte[] raw = new byte[MacAddress.LENGTH];
                    MemorySegment.copy(from, JAVA_BYTE, Libc.SLL_ADDR, raw, 0, MacAddress.LENGTH);
                    frameSource = new MacAddress(raw);
                }
                byte[] payload = buf.asSlice(0, n).toArray(JAVA_BYTE);
                try {
                    if (ethertype == Libc.ETH_P_ARP) {
                        onArp(payload, frameSource);
                    } else if (ethertype == Libc.ETH_P_IPV6) {
                        onIpv6(payload);
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

    private static final class PendingResolve {
        final InetAddress target;
        final Instant startedAt = Instant.now();
        final AtomicBoolean started = new AtomicBoolean();
        final CopyOnWriteArrayList<CompletableFuture<ResolveResult>> waiters =
                new CopyOnWriteArrayList<>();

        PendingResolve(InetAddress target) {
            this.target = target;
        }

        void completeAll(ResolveResult result) {
            waiters.forEach(w -> w.complete(result));
            waiters.clear();
        }
    }
}
