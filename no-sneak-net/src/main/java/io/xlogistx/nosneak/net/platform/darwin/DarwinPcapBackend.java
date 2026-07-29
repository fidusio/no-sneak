package io.xlogistx.nosneak.net.platform.darwin;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.EthernetFrame;
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
import io.xlogistx.nosneak.net.pcap.PcapHandle;
import io.xlogistx.nosneak.net.util.IpMacCache;
import io.xlogistx.nosneak.net.util.RateLimiter;

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

/**
 * ARP, NDP and passive observation on macOS, over libpcap.
 *
 * <h2>Why pcap rather than the §7.3 kernel neighbour table</h2>
 *
 * §2.2 ruled out BPF because {@code /dev/bpf*} is "{@code ioctl}-configured — variadic,
 * hitting the Darwin arm64 {@code firstVariadicArg} hazard", and routed macOS to the
 * kernel neighbour table via {@code sysctl} instead. **libpcap IS the BPF wrapper**: the
 * {@code ioctl} calls happen inside it, in C, where variadic conventions are the
 * compiler's problem rather than FFM's. The hazard that motivated the detour does not
 * exist through this door.
 * <p>
 * That also retires the §7.3 {@code [VERIFY]} gate. The whole indirect design of §7.4 —
 * provoke the kernel, poll {@code rt_msghdr} records, walk trailing sockaddrs through a
 * {@code ROUNDUP} rule that has diverged between Darwin and the BSDs — existed only
 * because macOS had no way to see the wire. It does now, so this backend solicits
 * actively and reads the answers off the segment, exactly as Linux and Windows do, and
 * nothing ever parses {@code rt_msghdr}.
 *
 * <h2>Shape</h2>
 *
 * TWO objects, like Linux, not one like Windows. {@link DarwinIcmpPing} keeps ICMP on its
 * unprivileged datagram sockets where the KERNEL ROUTES — so off-link echo works for
 * free. A pcap ping would bypass routing and drag in the whole next-hop and gateway-MAC
 * problem §8.7 solves for Windows, on a platform that does not have it. This class is
 * therefore layer 2 only.
 * <p>
 * <b>Privilege changes.</b> {@code /dev/bpf*} is mode 0600, so opening this needs root,
 * where macOS ICMP alone never did. {@code openIcmpOnly()} stays unprivileged, which is
 * what keeps the degraded path usable.
 *
 * <h2>Capabilities this restores</h2>
 *
 * {@code passiveObservation} and {@code rawEvidence} were hardcoded {@code false} on
 * macOS. Neither was a statement about the operating system; both were consequences of the
 * neighbour-table design, and capture makes them true.
 * <p>
 * {@code ttlAvailable} does NOT change, and the reason is worth stating: TTL reaches
 * callers through {@link PingProbe}, which {@link DarwinIcmpPing} fills from a datagram
 * socket that strips the IP header. This backend sees TTL on every captured frame but has
 * no way to hand it over — the pinger owns ICMP and its own identifier. Wiring it would
 * mean correlating captured echo replies against the pinger's in-flight probes across the
 * two objects. Worth doing; not done, and not claimed.
 *
 * <p><b>VERIFIED ON HARDWARE.</b> 2026-07-29, Apple Silicon (arm64), macOS 26.5, JDK 25,
 * on a live 10.0.0.0/24 over both a wired NIC (en7) and Wi-Fi (en0): active ARP resolved
 * the gateway in 15 ms; a {@code /25} sweep found 19 hosts with MACs on both interfaces —
 * so Wi-Fi injection is NOT refused here — passive {@code observe} caught 11 ARP requests,
 * and self-address resolve short-circuited to {@code LOCAL_INTERFACE}. The bring-up did
 * surface two live-only bugs, both outside this class: libpcap loads from the dyld shared
 * cache by soname, not an on-disk path (see {@link io.xlogistx.nosneak.net.pcap.PcapPlatform}),
 * and one non-Ethernet interface used to abort the whole factory open (see
 * {@link io.xlogistx.nosneak.net.common.HostDiscoveryFactory}). IPv6 all-nodes multicast
 * echo ({@code ff02::1}) is unroutable on this segment — macOS {@code ping6} fails the same
 * way — so {@code discoverIpv6Segment} returns only cached neighbours, which is the
 * documented under-report, not a fault.
 */
public final class DarwinPcapBackend implements HostDiscovery {

    /** Includes {@code ip} deliberately: passive IPv4 learning is what finds silent hosts. */
    private static final String BPF_FILTER = "arp or icmp or icmp6 or ip";

    private static final Duration RETRANSMIT = Duration.ofSeconds(1);
    private static final int SOLICIT_ATTEMPTS = 3;

    private final NicBinding binding;
    private final PcapHandle handle;
    private final IpMacCache cache = IpMacCache.withDefaults(256);
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final ConcurrentHashMap<InetAddress, PendingResolve> pending = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Consumer<ObservedNeighbor>> observers =
            new CopyOnWriteArrayList<>();

    private final boolean canInject;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private volatile Thread reader;

    /** Set once by the factory, before publication (§3.2). Borrowed, never closed here. */
    private volatile ICMPPing pinger;

    private DarwinPcapBackend(NicBinding binding, PcapHandle handle,
                              ScheduledExecutorService scheduler, ExecutorService dispatcher,
                              boolean canInject) {
        this.binding = binding;
        this.handle = handle;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
        this.canInject = canInject;
    }

    /**
     * Opens the device matched to this binding, installs the BPF filter, probes whether
     * the adapter accepts injection, and starts the reader thread.
     * <p>
     * Needs root. A clear failure naming {@code /dev/bpf} beats an obscure one, because
     * "permission denied" on macOS almost always means exactly that.
     */
    public static DarwinPcapBackend open(NicBinding binding,
                                         ScheduledExecutorService scheduler,
                                         ExecutorService dispatcher,
                                         boolean promiscuous) throws DiscoveryException {
        PcapHandle handle;
        try {
            handle = PcapHandle.open(binding.backendDeviceName(), promiscuous);
        } catch (DiscoveryException e) {
            throw new DiscoveryException(
                    "Could not open " + binding.backendDeviceName() + " for capture on macOS. "
                    + "/dev/bpf* is mode 0600, so layer-2 discovery requires root — ICMP alone "
                    + "does not, and remains available through openIcmpOnly(). Cause: "
                    + e.getMessage(), e);
        }
        try {
            handle.setFilter(BPF_FILTER);
        } catch (DiscoveryException e) {
            handle.close();
            throw e;
        }

        boolean canInject = binding.supportsLayer2() && probeInjection(binding, handle);

        DarwinPcapBackend backend =
                new DarwinPcapBackend(binding, handle, scheduler, dispatcher, canInject);
        backend.startReader();
        return backend;
    }

    /**
     * Sends one broadcast ARP for our OWN address — what duplicate address detection
     * does, so it is unremarkable on the wire — purely to learn whether the driver
     * accepts injected frames. A failure marks the binding capture-only rather than
     * failing the open, which is §8.6's rule and applies just as well to a Mac's Wi-Fi
     * adapter as to a PC's.
     */
    private static boolean probeInjection(NicBinding binding, PcapHandle handle) {
        Optional<NicBinding.LocalAddress> self = binding.ipv4().stream().findFirst();
        if (self.isEmpty()) {
            return false;
        }
        byte[] own = self.get().address().getAddress();
        byte[] arp = ArpPacket.request(binding.hardwareAddress(), own, own);
        return handle.send(EthernetFrame.build(MacAddress.BROADCAST, binding.hardwareAddress(),
                                               EthernetFrame.ETHERTYPE_ARP, arp));
    }

    // ---- HostDiscovery ----

    @Override
    public NicBinding binding() {
        return binding;
    }

    /**
     * Computed from what actually opened, never written as literals — §13.10.1's lesson
     * that a capability record built from constants cannot degrade honestly.
     */
    @Override
    public DiscoveryCapabilities capabilities() {
        ICMPPing p = pinger;
        boolean l2 = canInject && binding.supportsLayer2();
        return new DiscoveryCapabilities(
                p != null && p.capabilities().icmpV4(),
                p != null && p.capabilities().icmpV6(),
                l2,      // activeArp
                l2,      // activeNdp
                true,    // passiveObservation - capture, which is what pcap is
                true,    // rawEvidence - full frames, unlike the datagram ICMP socket
                // ttlAvailable follows the PINGER, and is therefore false here. Windows
                // can report true because its backend IS the pinger and reads TTL off
                // the frames it captures; on macOS ICMP belongs to DarwinIcmpPing, whose
                // datagram socket strips the IP header, so every PingProbe carries
                // TTL_UNAVAILABLE no matter what this capture can see. Claiming true
                // would advertise a distance the sweep then reports as -1.
                p != null && p.capabilities().ttlAvailable(),
                p != null && p.capabilities().offLinkIcmp(),
                DiscoveryCapabilities.Backend.MACOS_NATIVE);
    }

    @Override
    public Optional<ICMPPing> icmpPing() {
        return Optional.ofNullable(pinger);
    }

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
     * @param provoke whether to emit the ICMP echo that makes the target reveal its MAC.
     *                {@code sweep()} passes false because it already pings concurrently.
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
        // Our own address: nothing answers an ARP request for it, because the only host
        // that owns it is the one asking.
        if (binding.isLocalAddress(target) && binding.supportsLayer2()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, binding.hardwareAddress(), ResolveSource.LOCAL_INTERFACE,
                    Duration.between(started, Instant.now())));
        }
        if (!capabilities().activeArp()) {
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }
        if (!binding.isOnLink(target)) {
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        PendingResolve entry = pending.computeIfAbsent(target, k -> new PendingResolve(target));
        CompletableFuture<ResolveResult> future = entry.await();

        if (entry.started.compareAndSet(false, true)) {
            cache.markIncomplete(target);
            if (provoke) {
                provokeReply(target, Math.max(1, timeout.toMillis()));
            }
            solicit(target, 0);
            scheduleRetries(target, timeout);
        }
        return future;
    }

    /**
     * Sends one ICMP echo and discards the result, so the target's REPLY arrives and
     * {@link #onIpv4} can read its MAC off the Ethernet header.
     * <p>
     * Broadcast ARP is not universally delivered — access points buffer it against the
     * DTIM interval and commonly suppress it — so a station can be reachable by unicast
     * while never answering a solicitation. The echo's reply is unicast, which is the way
     * in. §7.4 already specified provocation for macOS; the difference is that it then had
     * to poll the kernel's table for the answer, whereas this watches the wire directly.
     * <p>
     * No recursion: {@link DarwinIcmpPing} routes through the kernel and never calls back
     * into {@code resolve()}.
     */
    private void provokeReply(InetAddress target, long budgetMillis) {
        ICMPPing p = pinger;
        if (p == null || !(target instanceof Inet4Address) || unicastHint(target).isPresent()) {
            return;
        }
        try {
            p.ping(target, 1, Duration.ofMillis(Math.min(budgetMillis, 1000)));
        } catch (RuntimeException ignored) {
            // Best effort; the broadcast retries continue regardless.
        }
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
                dropped.completeAll(ResolveResult.notResolved(target, ResolveOutcome.TIMEOUT,
                        Duration.between(dropped.startedAt, Instant.now())));
            }
        }, budget, TimeUnit.MILLISECONDS);
    }

    private void solicit(InetAddress target, int attempt) {
        if (target instanceof Inet4Address) {
            sendArp(target, attempt);
        } else {
            sendNeighborSolicitation(target);
        }
    }

    /**
     * Sends an ARP request, unicast to a known MAC when we have one and broadcast
     * otherwise — and BOTH on attempt 0 when a hint exists, since neither alone is safe:
     * unicast to a stale MAC reaches a host that has moved, broadcast is the case that
     * fails against a suppressing AP. Later attempts are unicast only.
     * <p>
     * pcap injects at layer 2 and builds nothing, so the whole Ethernet frame is
     * assembled here — unlike the Linux path, where {@code AF_PACKET}/{@code SOCK_DGRAM}
     * has the kernel prepend it.
     */
    private void sendArp(InetAddress target, int attempt) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return;
        }
        byte[] arp = ArpPacket.request(binding.hardwareAddress(),
                                       source.get().address().getAddress(),
                                       target.getAddress());
        Optional<MacAddress> hint = unicastHint(target);
        hint.ifPresent(mac -> handle.send(EthernetFrame.build(
                mac, binding.hardwareAddress(), EthernetFrame.ETHERTYPE_ARP, arp)));
        if (hint.isEmpty() || attempt == 0) {
            handle.send(EthernetFrame.build(MacAddress.BROADCAST, binding.hardwareAddress(),
                                            EthernetFrame.ETHERTYPE_ARP, arp));
        }
    }

    /**
     * A MAC to aim a unicast ARP at, from our own cache only. The kernel's neighbour
     * table is deliberately NOT consulted: it can only report what the kernel has already
     * resolved, and the kernel resolves a cold neighbour by broadcast — the very thing
     * being suppressed. Passive learning on the captured IPv4 stream replaces it (§13.13).
     */
    private Optional<MacAddress> unicastHint(InetAddress target) {
        return cache.get(target)
                    .filter(IpMacCache.Entry::hasMac)
                    .map(IpMacCache.Entry::mac)
                    .filter(mac -> !mac.isBroadcast() && !mac.isMulticast() && !mac.isZero());
    }

    /** Hop limit 255 is mandatory (RFC 4861 §7.1.1); the builder pins it. */
    private void sendNeighborSolicitation(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return;
        }
        byte[] src = source.get().address().getAddress();
        byte[] raw = target.getAddress();
        byte[] ns = Icmp6.neighborSolicitation(src, raw, binding.hardwareAddress());
        byte[] ip = Ipv6Header.forNeighborDiscovery(src, Icmp6.solicitedNodeMulticast(raw),
                                                    ns.length);
        byte[] payload = new byte[ip.length + ns.length];
        System.arraycopy(ip, 0, payload, 0, ip.length);
        System.arraycopy(ns, 0, payload, ip.length, ns.length);
        handle.send(EthernetFrame.build(Icmp6.solicitedNodeMac(raw), binding.hardwareAddress(),
                                        EthernetFrame.ETHERTYPE_IPV6, payload));
    }

    @Override
    public Subscription observe(Consumer<ObservedNeighbor> onNeighbor) {
        observers.add(onNeighbor);
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
        RateLimiter pacer = RateLimiter.perSecond(options.maxPacketsPerSecond());
        // Two ARP frames per host: a hinted target gets unicast AND broadcast on the
        // first attempt. Reserving the worst case keeps the emitted rate at or under the
        // cap, the only direction a safety limit may err in.
        int packetsPerHost = (options.doMac() ? 2 : 0)
                + (options.doIcmp() ? options.pingCount() : 0);

        List<CompletableFuture<Void>> all = new ArrayList<>(targets.size());
        for (InetAddress target : targets) {
            all.add(CompletableFuture.completedFuture(null).thenComposeAsync(ignored -> {
                try {
                    window.acquire();
                    RateLimiter.acquire(pacer, packetsPerHost);
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
        // NEVER probe the local network or directed broadcast: an echo to a directed
        // broadcast is answered by every host at once.
        if (binding.isNetworkOrBroadcast(target)) {
            return CompletableFuture.completedFuture(null);
        }
        // BOTH probes start now, not resolve-then-ping. The echo REPLY carries the MAC,
        // and sequencing them means it always lands after the resolve has given up
        // (§13.13). Both are bounded by perHostTimeout, so this is also faster.
        CompletableFuture<ResolveResult> mac = options.doMac()
                ? resolve(target, options.perHostTimeout(), false)
                : CompletableFuture.completedFuture(ResolveResult.notResolved(
                        target, ResolveOutcome.UNSUPPORTED, Duration.ZERO));

        ICMPPing p = pinger;
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

    private void startReader() {
        // A dedicated PLATFORM thread, never a pool thread: this loop runs until
        // shutdown and would permanently consume one (§4.4).
        Thread t = new Thread(this::readLoop, "nosneak-pcap-" + binding.javaName());
        t.setDaemon(true);
        reader = t;
        t.start();
    }

    private void readLoop() {
        while (running) {
            byte[] frame;
            try {
                frame = handle.nextPacket();
            } catch (DiscoveryException e) {
                if (running && !handle.isClosed()) {
                    running = false;
                }
                return;
            }
            if (frame == null) {
                continue;   // timeout tick: re-check running and loop
            }
            try {
                dispatch(frame);
            } catch (RuntimeException ignored) {
                // A malformed frame must never kill the reader.
            }
        }
    }

    private void dispatch(byte[] frame) {
        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElse(null);
        if (eth == null) {
            return;
        }
        // Our own injected frames come back on the capture. Learning from them would
        // record our MAC against every address we probe.
        if (binding.hardwareAddress() != null && binding.hardwareAddress().equals(eth.src())) {
            return;
        }
        if (eth.isArp()) {
            onArp(eth, frame);
        } else if (eth.isIpv4()) {
            onIpv4(eth, frame);
        } else if (eth.isIpv6()) {
            onIpv6(eth, frame);
        }
    }

    private void onArp(EthernetFrame.View eth, byte[] frame) {
        ArpPacket.ArpView arp =
                ArpPacket.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (arp == null || arp.sha().isZero()) {
            return;
        }
        InetAddress sender = address(arp.spa());
        if (sender == null) {
            return;
        }
        cache.observe(sender, arp.sha(),
                      arp.isReply() ? ResolveSource.ACTIVE_ARP : ResolveSource.PASSIVE);
        completeResolve(sender, arp.sha(), ResolveSource.ACTIVE_ARP);

        ObservationKind kind = arp.isGratuitous() ? ObservationKind.GRATUITOUS_ARP
                : arp.isReply() ? ObservationKind.ARP_REPLY : ObservationKind.ARP_REQUEST;
        notifyObservers(new ObservedNeighbor(sender, arp.sha(), kind, Instant.now()));
    }

    /**
     * Learns an IP-to-MAC binding from ordinary IPv4 traffic and, when a resolve for that
     * address is in flight, aims a unicast ARP at what it just learned.
     * <p>
     * This is what makes a broadcast-suppressed host resolvable: its echo reply is unicast
     * straight back to us, so its MAC arrives here even though it will not answer a
     * broadcast solicitation. The MAC comes from the Ethernet header, the one field a
     * sender cannot omit. It is a HINT — the pending resolve still completes only on a
     * real ARP reply, so {@code ResolveSource.ACTIVE_ARP} stays honest.
     */
    private void onIpv4(EthernetFrame.View eth, byte[] frame) {
        MacAddress src = eth.src();
        if (src == null || src.isZero() || src.isMulticast()) {
            return;
        }
        Ipv4Header.View ip =
                Ipv4Header.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (ip == null) {
            return;
        }
        InetAddress sender = address(ip.src4());
        if (sender == null || sender.isAnyLocalAddress() || !binding.isOnLink(sender)
                || binding.isLocalAddress(sender)) {
            return;
        }
        cache.observe(sender, src, ResolveSource.PASSIVE);
        if (pending.containsKey(sender)) {
            sendArp(sender, 1);
        }
    }

    private void onIpv6(EthernetFrame.View eth, byte[] frame) {
        Ipv6Header.View ip =
                Ipv6Header.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (ip == null || ip.nextHeader() != Ipv6Header.NEXT_HEADER_ICMPV6) {
            return;
        }
        int off = eth.payloadOffset() + Ipv6Header.LENGTH;
        int len = Math.min(ip.payloadLength(), frame.length - off);
        if (len <= 0 || !Ipv6Header.isValidNeighborDiscovery(ip)) {
            // RFC 4861 7.1.1: NS/NA whose hop limit is not 255 crossed a router and are
            // discarded. This is the on-link attack defence.
            return;
        }

        Icmp6.parseAdvertisement(frame, off, len).ifPresent(na -> {
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

        Icmp6.parseSolicitation(frame, off, len).ifPresent(ns -> {
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

    /**
     * Idempotent.
     * <p>
     * THE READER IS JOINED BEFORE THE HANDLE CLOSES. §13.7 learned this the hard way on
     * Windows: the capture buffers live in a shared arena, and closing it while the reader
     * sits inside {@code pcap_next_ex} throws "Session is acquired by 1 clients" and leaks
     * the mapping. {@code PcapHandle.READ_TIMEOUT_MS} bounds how long the join can take.
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        running = false;
        Thread t = reader;
        if (t != null) {
            try {
                t.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        handle.close();

        pending.values().forEach(p -> p.completeAll(
                ResolveResult.notResolved(p.target, ResolveOutcome.ERROR, Duration.ZERO)));
        pending.clear();
        observers.clear();
        // The pinger is BORROWED - never closed here. Nor are the executors (§4.3).
    }

    private static InetAddress address(byte[] raw) {
        try {
            return InetAddress.getByAddress(raw);
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    /**
     * One in-flight solicitation and everyone waiting on it, sharing ONE future.
     * <p>
     * A per-caller list leaves a window between the reader's {@code completeAll} and a
     * concurrent {@code resolve()} that has already taken this entry — that late future is
     * completed by nobody, and in {@code sweep()} it would hang {@code allOf} forever
     * rather than fail. {@code complete} is idempotent, so one shared future closes it.
     */
    private static final class PendingResolve {
        final InetAddress target;
        final Instant startedAt = Instant.now();
        final AtomicBoolean started = new AtomicBoolean();
        private final CompletableFuture<ResolveResult> result = new CompletableFuture<>();

        PendingResolve(InetAddress target) {
            this.target = target;
        }

        /** A copy, so a caller cannot complete the shared future for everyone else. */
        CompletableFuture<ResolveResult> await() {
            return result.copy();
        }

        void completeAll(ResolveResult outcome) {
            result.complete(outcome);
        }
    }
}
