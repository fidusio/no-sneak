package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.codecs.*;
import io.xlogistx.nosneak.net.common.*;
import io.xlogistx.nosneak.net.pcap.PcapHandle;
import io.xlogistx.nosneak.net.util.Identifiers;
import io.xlogistx.nosneak.net.util.IpMacCache;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * The Windows backend. Implements {@link HostDiscovery} AND {@link ICMPPing} on
 * ONE object, because pcap injects at L2 and bypasses routing: an echo request
 * needs a device handle, a source MAC and IP, and the destination's MAC — which
 * means it needs ARP, which is the other interface. Splitting the two roles would
 * mean a second pcap handle on the same adapter, a second capture thread, and a
 * second cache that disagrees with the first.
 * <p>
 * ON-LINK ONLY. Injection bypasses OS routing, so an off-link destination would
 * need the default gateway's MAC, hence its IP, hence an {@code iphlpapi}
 * binding. {@code offLinkIcmp} is false and off-link targets complete with
 * {@link PingError#NETWORK_UNREACHABLE}.
 */
public final class WindowsPcapBackend implements HostDiscovery, ICMPPing {

    /**
     * Broader than it looks necessary, and simpler than what it replaced.
     * <p>
     * {@code "arp or icmp or icmp6"} captured exactly what this backend answers with
     * and nothing it could LEARN from — so a host that ignores broadcast ARP had no
     * way of telling us where it lived, and needed Windows' neighbour table to be
     * findable at all (§13.16). Since {@code icmp} is a subset of {@code ip} and
     * {@code icmp6} of {@code ip6}, widening to every IP frame is one clause shorter
     * AND gives {@link #learnSender} something to work with: every frame names its
     * sender's MAC in the Ethernet header, whatever it carries.
     * <p>
     * This is the Linux {@code ETH_P_IP} learner's coverage (§13.13), reached through
     * the one handle this backend already owns rather than a second socket.
     * <p>
     * The cost is capture volume, and the risk that matters is not CPU but DROPS: a
     * full pcap buffer loses frames, and a lost ARP reply is a resolve that times out.
     * Non-promiscuous capture bounds this — we see broadcast, multicast, and traffic
     * addressed to us, not the whole segment.
     */
    private static final String BPF_FILTER = "arp or ip or ip6";
    private static final Duration ARP_RETRANSMIT = Duration.ofSeconds(1);
    private static final int ARP_ATTEMPTS = 3;

    private final NicBinding binding;
    private final PcapHandle handle;
    private final IpMacCache cache;
    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;

    private final int identifier = Identifiers.nextIdentifier();
    private final Identifiers.SequenceAllocator sequences = Identifiers.newSequenceAllocator();

    private final ConcurrentHashMap<InetAddress, PendingResolve> pendingResolves =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, PendingProbe> pendingProbes = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Consumer<ObservedNeighbor>> observers =
            new CopyOnWriteArrayList<>();

    private final boolean canInject;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private volatile Thread reader;

    /** Set once by the factory; may include this instance (§8.6). */
    private volatile List<WindowsPcapBackend> pingPeers = List.of();

    private WindowsPcapBackend(NicBinding binding, PcapHandle handle, IpMacCache cache,
                               ScheduledExecutorService scheduler, ExecutorService dispatcher,
                               boolean canInject) {
        this.binding = binding;
        this.handle = handle;
        this.cache = cache;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
        this.canInject = canInject;
    }

    /**
     * Opens the device matched to this binding, installs the BPF filter, probes
     * whether the adapter accepts injection, and starts the reader thread.
     *
     * @param promiscuous only when passive observation is wanted; it raises capture
     *                    volume substantially and is detectable on the segment
     */
    public static WindowsPcapBackend open(NicBinding binding,
                                          ScheduledExecutorService scheduler,
                                          ExecutorService dispatcher,
                                          boolean promiscuous) throws DiscoveryException {
        PcapHandle handle = PcapHandle.open(binding.backendDeviceName(), promiscuous);
        try {
            handle.setFilter(BPF_FILTER);
        } catch (DiscoveryException e) {
            handle.close();
            throw e;
        }

        // Probe injection once (§8.6): pcap_sendpacket is driver-dependent and
        // commonly fails on wireless adapters, which capture fine but cannot send.
        // A failure marks the binding capture-only rather than failing the open.
        boolean canInject = binding.supportsLayer2() && probeInjection(binding, handle);

        WindowsPcapBackend backend =
                new WindowsPcapBackend(binding, handle, IpMacCache.withDefaults(256),
                                       scheduler, dispatcher, canInject);
        backend.startReader();
        return backend;
    }

    /**
     * Sends a broadcast ARP request for our OWN address — the same thing duplicate
     * address detection does, so it is unremarkable on the wire — purely to learn
     * whether the driver accepts injected frames.
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

    /**
     * Injects the peers this instance may ping through (§8.6). Set once, by the
     * factory, before the object is published.
     */
    public void setPingPeers(List<WindowsPcapBackend> peers) {
        this.pingPeers = List.copyOf(peers);
    }

    // ---- HostDiscovery ----

    @Override
    public NicBinding binding() {
        return binding;
    }

    @Override
    public DiscoveryCapabilities capabilities() {
        boolean l2 = canInject && binding.supportsLayer2();
        return new DiscoveryCapabilities(
                l2,      // icmpV4  - crafted over pcap, so it needs injection
                l2,      // icmpV6
                l2,      // activeArp
                l2,      // activeNdp
                true,    // passiveObservation - capture works even when injection does not
                true,    // rawEvidence - pcap gives whole frames
                true,    // ttlAvailable - the IPv4 header is right there
                // Off-link needs the gateway's MAC, hence its IP, hence iphlpapi.
                // With GetBestRoute2 bound this backend routes; without it, on-link only.
                l2 && Iphlpapi.isAvailable(),
                DiscoveryCapabilities.Backend.WINDOWS_PCAP);
    }

    /** This object is its own pinger (§8.6). */
    @Override
    public Optional<ICMPPing> icmpPing() {
        return Optional.of(this);
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
        // Our own address: no host on the segment answers an ARP request for it, since
        // the only owner is the one asking. Without this the call burns the whole
        // timeout for a MAC held since construction.
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
            // Nothing off-link can answer ARP, and we cannot route to it either.
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        // Deduplicate: a second caller joins the first caller's future rather than
        // emitting a second solicitation (spec section 9.2).
        PendingResolve pending = pendingResolves.computeIfAbsent(target,
                k -> new PendingResolve(target, started));
        CompletableFuture<ResolveResult> future = pending.await();

        if (pending.started.compareAndSet(false, true)) {
            cache.markIncomplete(target);
            solicit(target, 0);
            scheduleResolveRetries(pending, target, timeout);
        }
        return future;
    }

    /**
     * Sends one solicitation. For IPv4, BROADCAST on attempt 0 and UNICAST to a MAC
     * hint whenever one exists.
     * <p>
     * Broadcast alone is not sufficient in practice. Wi-Fi access points buffer
     * broadcast against the DTIM interval and commonly suppress or proxy it, so a
     * station can be fully reachable by unicast while never seeing a broadcast ARP.
     * Measured on this transport (§13.16): a host answered 0 of 3 broadcast requests
     * and 3 of 3 unicast requests to the same MAC, seconds apart, while the gateway
     * answered 3 of 3 both ways on the same handle — so the frames were fine and the
     * host was suppressing.
     * <p>
     * Both frames go out on attempt 0 when a hint exists, because neither alone is
     * safe: unicast to a stale MAC reaches a host that has moved, and broadcast alone
     * is the case that fails here. Later attempts are unicast only. Note {@code sweep()}
     * with its default one-second per-host budget gets ONLY attempt 0, so covering both
     * paths there is what makes a swept host resolvable at all.
     * <p>
     * IPv6 is unchanged: a neighbour solicitation already goes to the solicited-node
     * multicast address rather than a broadcast, and multicast NS is not what was
     * measured failing.
     */
    private void solicit(InetAddress target, int attempt) {
        if (target instanceof Inet4Address) {
            byte[] arp = ArpPacket.request(binding.hardwareAddress(),
                    binding.sourceFor(target).orElseThrow().address().getAddress(),
                    target.getAddress());
            Optional<MacAddress> hint = unicastHint(target);
            hint.ifPresent(mac -> handle.send(
                    EthernetFrame.build(mac, binding.hardwareAddress(),
                                        EthernetFrame.ETHERTYPE_ARP, arp)));
            if (hint.isEmpty() || attempt == 0) {
                handle.send(EthernetFrame.build(MacAddress.BROADCAST, binding.hardwareAddress(),
                                                EthernetFrame.ETHERTYPE_ARP, arp));
            }
        } else {
            byte[] src = binding.sourceFor(target).orElseThrow().address().getAddress();
            byte[] ns = Icmp6.neighborSolicitation(src, target.getAddress(),
                                                   binding.hardwareAddress());
            byte[] dst = Icmp6.solicitedNodeMulticast(target.getAddress());
            // Hop limit 255 is mandatory here (RFC 4861 7.1.1) - the builder pins it.
            byte[] ip = Ipv6Header.forNeighborDiscovery(src, dst, ns.length);
            byte[] payload = concat(ip, ns);
            handle.send(EthernetFrame.build(Icmp6.solicitedNodeMac(target.getAddress()),
                                            binding.hardwareAddress(),
                                            EthernetFrame.ETHERTYPE_IPV6, payload));
        }
    }

    /**
     * A MAC to aim a unicast ARP request at.
     * <p>
     * OUR OWN OBSERVATION FIRST. {@link IpMacCache} holds what this process saw on
     * the wire, which is the better source whenever it has anything: it carries real
     * provenance and it is current. A {@code STALE} entry is accepted deliberately —
     * staleness is exactly the state in which a neighbour wants revalidating, and it
     * still carries the only MAC that makes a unicast probe possible. {@code INCOMPLETE}
     * entries carry none and are skipped, which also stops this reading back the
     * placeholder {@code resolve()} just wrote via {@code markIncomplete}.
     * <p>
     * WINDOWS' NEIGHBOUR TABLE SECOND, and only because this backend has nothing
     * better. Linux learns MACs off ordinary IPv4 traffic on a dedicated socket
     * (§13.13) and so deleted its kernel-table reader; the single pcap handle here
     * filters {@code "arp or icmp or icmp6"} and learns nothing from general traffic,
     * so for a host that has never ARPed within earshot the cache is empty and
     * {@code GetIpNetEntry2} is the difference between resolving and timing out.
     * <p>
     * The fallback is NOT written back into the cache: the cache means "seen on the
     * wire by us", and Windows' belief is not that. It only addresses the frame — the
     * reply still has to arrive here before anything is reported.
     */
    private Optional<MacAddress> unicastHint(InetAddress target) {
        Optional<MacAddress> observed = cache.get(target)
                .filter(IpMacCache.Entry::hasMac)
                .map(IpMacCache.Entry::mac)
                .filter(WindowsPcapBackend::usableAsHint);
        if (observed.isPresent()) {
            return observed;
        }
        return Iphlpapi.neighborMac(target, binding.ifIndex())
                       .filter(WindowsPcapBackend::usableAsHint);
    }

    /** A hint has to be a single host's address; the others cannot be unicast to. */
    private static boolean usableAsHint(MacAddress mac) {
        return !mac.isBroadcast() && !mac.isMulticast() && !mac.isZero();
    }

    /** RFC 4861 timing, and the same for ARP: up to 3 attempts, 1s apart. */
    private void scheduleResolveRetries(PendingResolve pending, InetAddress target,
                                        Duration timeout) {
        long budgetMs = Math.max(1, timeout.toMillis());
        for (int attempt = 1; attempt < ARP_ATTEMPTS; attempt++) {
            long at = attempt * ARP_RETRANSMIT.toMillis();
            if (at >= budgetMs) {
                break;
            }
            int retry = attempt;   // the loop variable is not effectively final
            scheduler.schedule(() -> {
                if (pendingResolves.containsKey(target)) {
                    solicit(target, retry);
                }
            }, at, TimeUnit.MILLISECONDS);
        }
        scheduler.schedule(() -> {
            PendingResolve dropped = pendingResolves.remove(target);
            if (dropped != null) {
                dropped.completeAll(ResolveResult.notResolved(target, ResolveOutcome.TIMEOUT,
                        Duration.between(dropped.startedAt, Instant.now())));
            }
        }, budgetMs, TimeUnit.MILLISECONDS);
    }

    @Override
    public Subscription observe(Consumer<ObservedNeighbor> onNeighbor) {
        observers.add(onNeighbor);
        return () -> observers.remove(onNeighbor);
    }

    @Override
    public CompletableFuture<SweepSummary> sweep(CidrRange range, SweepOptions options,
                                                 Consumer<HostRecord> onHost) {
        if (range.hostCount().compareTo(java.math.BigInteger.valueOf(options.maxHosts())) > 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException(
                    "Range " + range + " holds " + range.hostCount() + " addresses, above maxHosts "
                    + options.maxHosts() + "; use discoverIpv6Segment for v6 segments"));
        }
        List<InetAddress> targets = range.hosts().toList();
        return sweepTargets(targets, options, onHost);
    }

    @Override
    public CompletableFuture<SweepSummary> discoverIpv6Segment(SweepOptions options,
                                                               Consumer<HostRecord> onHost) {
        // Windows stacks generally do not answer multicast echo, so the active
        // half under-reports badly here; report what has been learned instead.
        List<HostRecord> known = new ArrayList<>();
        for (IpMacCache.Entry e : cache.snapshot()) {
            if (e.ip() instanceof Inet6Address && e.hasMac()) {
                known.add(new HostRecord(e.ip(), Optional.of(e.mac()), false, Optional.empty(),
                                         PingProbe.TTL_UNAVAILABLE, Optional.empty(),
                                         e.provenance(), e.lastSeen()));
            }
        }
        known.forEach(r -> dispatcher.execute(() -> onHost.accept(r)));
        return CompletableFuture.completedFuture(new SweepSummary(
                known.size(), known.size(), known.size(), 0, Duration.ZERO));
    }

    private CompletableFuture<SweepSummary> sweepTargets(List<InetAddress> targets,
                                                         SweepOptions options,
                                                         Consumer<HostRecord> onHost) {
        Instant started = Instant.now();
        AtomicInteger alive = new AtomicInteger();
        AtomicInteger macs = new AtomicInteger();
        AtomicInteger icmp = new AtomicInteger();
        java.util.concurrent.Semaphore window =
                new java.util.concurrent.Semaphore(options.maxInFlight());
        // maxInFlight bounds how many probes are OUTSTANDING; the rate limiter
        // bounds how fast they leave. They are different constraints (spec 3.5).
        io.xlogistx.nosneak.net.util.RateLimiter pacer =
                io.xlogistx.nosneak.net.util.RateLimiter.perSecond(options.maxPacketsPerSecond());
        int packetsPerHost = 1 + (options.doIcmp() ? options.pingCount() : 0);

        List<CompletableFuture<Void>> all = new ArrayList<>(targets.size());
        for (InetAddress target : targets) {
            CompletableFuture<Void> one = CompletableFuture
                    .completedFuture(null)
                    .thenComposeAsync(ignored -> {
                        try {
                            window.acquire();
                            io.xlogistx.nosneak.net.util.RateLimiter.acquire(
                                    pacer, packetsPerHost);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return CompletableFuture.completedFuture(null);
                        }
                        return sweepOne(target, options, onHost, alive, macs, icmp)
                                .whenComplete((r, t) -> window.release());
                    }, dispatcher);
            all.add(one);
        }
        return CompletableFuture.allOf(all.toArray(CompletableFuture[]::new))
                .thenApply(ignored -> new SweepSummary(targets.size(), alive.get(), macs.get(),
                        icmp.get(), Duration.between(started, Instant.now())));
    }

    private CompletableFuture<Void> sweepOne(InetAddress target, SweepOptions options,
                                             Consumer<HostRecord> onHost, AtomicInteger alive,
                                             AtomicInteger macs, AtomicInteger icmp) {
        // NEVER probe the local network or directed-broadcast address: an echo to
        // a directed broadcast is answered by every host at once, which is
        // amplification and reads as an attack on a security appliance.
        if (binding.isNetworkOrBroadcast(target)) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<ResolveResult> mac = options.doMac()
                ? resolve(target, options.perHostTimeout())
                : CompletableFuture.completedFuture(
                        ResolveResult.notResolved(target, ResolveOutcome.UNSUPPORTED, Duration.ZERO));

        return mac.thenCompose(resolved -> {
            boolean haveMac = resolved.resolved();
            if (!haveMac && !options.doIcmp()) {
                return CompletableFuture.completedFuture(null);
            }
            CompletableFuture<PingResult> pinged = options.doIcmp() && haveMac
                    ? ping(target, options.pingCount(), options.perHostTimeout())
                    : CompletableFuture.completedFuture(
                            PingResult.of(target, List.of(), null));

            return pinged.thenAccept(result -> {
                // observedOnWire, not reachable: our own address answers from local
                // configuration without a packet, so it is alive but did not answer
                // ICMP, and it has no RTT to report. Publishing avgRtt() there would
                // print 0.000 ms, which reads as a real measurement.
                boolean answeredIcmp = result.observedOnWire();
                boolean up = haveMac || answeredIcmp;
                if (!up) {
                    return;
                }
                alive.incrementAndGet();
                if (haveMac) {
                    macs.incrementAndGet();
                }
                if (answeredIcmp) {
                    icmp.incrementAndGet();
                }
                int ttl = result.probes().stream().filter(PingProbe::hasTtl)
                                .mapToInt(PingProbe::ttlOrHopLimit).findFirst()
                                .orElse(PingProbe.TTL_UNAVAILABLE);
                HostRecord record = new HostRecord(
                        target, resolved.mac(), answeredIcmp,
                        result.measured() ? Optional.of(result.avgRtt()) : Optional.empty(),
                        ttl, ttl > 0 ? TtlDistance.hopCount(ttl) : Optional.empty(),
                        haveMac ? resolved.source() : null, Instant.now());
                dispatcher.execute(() -> onHost.accept(record));
            });
        });
    }

    // ---- ICMPPing ----

    @Override
    public CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout) {
        if (count < 1) {
            throw new IllegalArgumentException("count must be >= 1, got " + count);
        }

        // OUR OWN ADDRESS: answer from local configuration and send nothing.
        //
        // A pcap ping cannot work here and no retry would help. The frame would carry
        // our own MAC as both source and destination: the switch will not send it back
        // out the port it arrived on, and the NIC does not loop transmitted frames into
        // its own receive path, so the reply we are waiting for is generated by an IP
        // stack we bypassed. Before this, every probe timed out and the tool reported
        // 100% loss for a host that is up by definition.
        //
        // NetworkInterface already told us everything the wire would have: the address
        // is configured and the interface was up at open(). This is resolve()'s
        // LOCAL_INTERFACE short-circuit applied to liveness, and it is deliberately
        // NOT done on Linux or macOS, where the kernel routes a self-ping over
        // loopback and returns a real measurement worth more than this.
        if (ownAddress(target, localBindings())) {
            return CompletableFuture.completedFuture(localPing(target, count));
        }

        Route route = routeFor(target);
        if (route == null) {
            return CompletableFuture.completedFuture(failedPing(target, count,
                    PingError.NETWORK_UNREACHABLE));
        }
        if (route.via() != this) {
            return route.via().ping(target, count, timeout);
        }
        if (!capabilities().icmpV4()) {
            return CompletableFuture.completedFuture(failedPing(target, count, PingError.IO));
        }

        // Resolve the L2 NEXT HOP, which is the target itself when on-link and the
        // gateway when not. The IP header still carries the real destination.
        return resolve(route.l2Target(), timeout).thenCompose(resolved -> {
            if (!resolved.resolved()) {
                return CompletableFuture.completedFuture(failedPing(target, count,
                        ResolveOutcome.TIMEOUT == resolved.outcome()
                                ? PingError.HOST_UNREACHABLE
                                : PingError.NETWORK_UNREACHABLE));
            }
            return emitProbes(target, resolved.mac().orElseThrow(), count, timeout);
        });
    }

    /**
     * Where to hand the frame, and through which backend.
     *
     * @param l2Target whose MAC goes in the Ethernet destination — the target when
     *                 on-link, otherwise the gateway. NOT the IP header's destination
     */
    private record Route(WindowsPcapBackend via, InetAddress l2Target) {
    }

    /**
     * Every address this HOST owns, not just this interface's.
     * <p>
     * One pinger serves all the NICs the factory opened, so the second adapter's
     * address is ours too — pinging {@code 192.168.56.1} from the binding that holds
     * {@code 10.0.0.61} is still a self-ping.
     */
    private List<NicBinding> localBindings() {
        List<NicBinding> all = new ArrayList<>(pingPeers.size() + 1);
        all.add(binding);
        for (WindowsPcapBackend peer : pingPeers) {
            if (peer != this) {
                all.add(peer.binding);
            }
        }
        return all;
    }

    /**
     * Whether {@code target} is this host talking to itself.
     * <p>
     * Loopback is tested on the ADDRESS, not against a binding: {@code 127.0.0.0/8}
     * and {@code ::1} live on an interface that {@code usableInterfaces()} filters
     * out, so there is no binding to match and {@code ping 127.0.0.1} used to fail
     * with {@code NETWORK_UNREACHABLE}.
     * <p>
     * The bindings are the snapshot taken at {@code open()} rather than a live
     * {@code NetworkInterface} lookup, deliberately: they are what the rest of this
     * backend routes and resolves against, and a fresher answer here than there
     * would make {@code ping} and {@code resolve} disagree about the same address.
     * {@code reopen()} is how a changed address is picked up.
     */
    static boolean ownAddress(InetAddress target, List<NicBinding> bindings) {
        if (target == null) {
            return false;
        }
        if (target.isLoopbackAddress()) {
            return true;
        }
        for (NicBinding local : bindings) {
            if (local.isLocalAddress(target)) {
                return true;
            }
        }
        return false;
    }

    /** {@code count} probes that were never sent, and say so (see {@link PingProbe#localInterface}). */
    private PingResult localPing(InetAddress target, int count) {
        List<PingProbe> probes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            probes.add(PingProbe.localInterface(sequences.next()));
        }
        return PingResult.of(target, probes, null);
    }

    /**
     * On-link first, then the routing table.
     * <p>
     * The on-link scan across bindings is a subnet test, not route selection
     * (§8.6). For anything beyond the local subnets it asks Windows itself, via
     * {@code GetBestRoute2}, which router it would use — reimplementing metrics and
     * longest-prefix here would be a worse copy of what the OS already knows.
     * <p>
     * Returns null when nothing can carry the packet: no on-link binding, no route,
     * or a gateway that is itself not on-link for any injectable interface.
     */
    private Route routeFor(InetAddress target) {
        if (binding.isOnLink(target) && canInject) {
            return new Route(this, target);
        }
        for (WindowsPcapBackend peer : pingPeers) {
            if (peer.canInject && peer.binding.isOnLink(target)) {
                return new Route(peer, target);
            }
        }
        InetAddress gateway = Iphlpapi.nextHopFor(target).orElse(null);
        if (gateway == null) {
            return null;
        }
        if (binding.isOnLink(gateway) && canInject) {
            return new Route(this, gateway);
        }
        for (WindowsPcapBackend peer : pingPeers) {
            if (peer.canInject && peer.binding.isOnLink(gateway)) {
                return new Route(peer, gateway);
            }
        }
        return null;
    }

    private CompletableFuture<PingResult> emitProbes(InetAddress target, MacAddress destMac,
                                                     int count, Duration timeout) {
        PendingCall call = new PendingCall(target, count);
        boolean v4 = target instanceof Inet4Address;
        // sourceFor(target) is empty for an OFF-LINK target - it has no address in
        // our subnet - so fall back to this interface's own address of that family.
        byte[] src = binding.sourceFor(target)
                .or(() -> (v4 ? binding.ipv4() : binding.ipv6()).stream().findFirst())
                .orElseThrow(() -> new IllegalStateException(
                        "Interface " + binding.javaName() + " has no "
                        + (v4 ? "IPv4" : "IPv6") + " address to send from"))
                .address().getAddress();

        // Probes are PIPELINED: all count requests go out immediately with
        // distinct sequence numbers, so worst-case wall time is one timeout.
        for (int i = 0; i < count; i++) {
            int seq = sequences.next();
            long key = Identifiers.correlationKey(identifier, seq);
            PendingProbe probe = new PendingProbe(call, seq, System.nanoTime());
            pendingProbes.put(key, probe);

            byte[] frame = v4
                    ? buildIcmpV4Frame(src, target.getAddress(), destMac, seq)
                    : buildIcmpV6Frame(src, target.getAddress(), destMac, seq);
            if (!handle.send(frame)) {
                pendingProbes.remove(key);
                call.settle(PingProbe.failed(seq, PingError.IO));
                continue;
            }
            ScheduledFuture<?> expiry = scheduler.schedule(() -> {
                if (pendingProbes.remove(key) != null) {
                    call.settle(PingProbe.failed(seq, PingError.TIMEOUT));
                }
            }, Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS);
            probe.expiry = expiry;
        }
        return call.future;
    }

    private byte[] buildIcmpV4Frame(byte[] src, byte[] dst, MacAddress destMac, int seq) {
        byte[] icmp = Icmp4Echo.request(identifier, seq, timestampPayload());
        byte[] ip = Ipv4Header.forIcmp(src, dst, seq & 0xFFFF, icmp.length);
        return EthernetFrame.build(destMac, binding.hardwareAddress(),
                                   EthernetFrame.ETHERTYPE_IPV4, concat(ip, icmp));
    }

    private byte[] buildIcmpV6Frame(byte[] src, byte[] dst, MacAddress destMac, int seq) {
        byte[] icmp = Icmp6.echoRequest(src, dst, identifier, seq, timestampPayload());
        byte[] ip = Ipv6Header.build(src, dst, Ipv6Header.NEXT_HEADER_ICMPV6, 64, icmp.length);
        return EthernetFrame.build(destMac, binding.hardwareAddress(),
                                   EthernetFrame.ETHERTYPE_IPV6, concat(ip, icmp));
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

    private PingResult failedPing(InetAddress target, int count, PingError error) {
        List<PingProbe> probes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            probes.add(PingProbe.failed(i, error));
        }
        return PingResult.of(target, probes, error);
    }

    // ---- capture ----

    private void startReader() {
        Thread t = new Thread(this::readLoop, "nosneak-pcap-" + binding.javaName());
        t.setDaemon(true);
        // A dedicated PLATFORM thread, never a pool thread: this loop runs until
        // shutdown and would permanently consume one (spec section 4.4).
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

    /** Demultiplexes by ethertype — the single capture serves both roles (§8.6). */
    private void dispatch(byte[] frame) {
        EthernetFrame.View eth = EthernetFrame.parse(frame, 0, frame.length).orElse(null);
        if (eth == null) {
            return;
        }
        if (eth.isArp()) {
            onArp(eth, frame);
        } else if (eth.isIpv4()) {
            onIpv4(frame, eth);
        } else if (eth.isIpv6()) {
            onIpv6(frame, eth);
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
        ResolveSource source = arp.isReply() ? ResolveSource.ACTIVE_ARP : ResolveSource.PASSIVE;
        cache.observe(sender, arp.sha(), source);
        completeResolve(sender, arp.sha(), ResolveSource.ACTIVE_ARP);

        ObservationKind kind = arp.isGratuitous() ? ObservationKind.GRATUITOUS_ARP
                : arp.isReply() ? ObservationKind.ARP_REPLY : ObservationKind.ARP_REQUEST;
        notifyObservers(new ObservedNeighbor(sender, arp.sha(), kind, Instant.now()));
    }

    private void onIpv4(byte[] frame, EthernetFrame.View eth) {
        Ipv4Header.View ip =
                Ipv4Header.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (ip == null) {
            return;
        }
        // BEFORE the ICMP test: every IPv4 frame names its sender's MAC in the
        // Ethernet header, whatever it carries, and that is the hint a host which
        // ignores broadcast ARP will never give us any other way (§13.16).
        learnSender(address(ip.src4()), eth.src());
        if (!ip.isIcmp()) {
            return;
        }
        int icmpOffset = eth.payloadOffset() + ip.headerLength();
        int icmpLength = Math.min(ip.payloadLength(),
                                  frame.length - icmpOffset);
        if (icmpLength <= 0) {
            return;
        }
        Icmp4Echo.parseReply(frame, icmpOffset, icmpLength).ifPresent(echo -> {
            if (echo.id() != identifier) {
                return;   // another process's ICMP; the identifier is the only filter
            }
            completeProbe(echo.id(), echo.seq(), ip.ttl(), frame);
        });
    }

    private void onIpv6(byte[] frame, EthernetFrame.View eth) {
        Ipv6Header.View ip =
                Ipv6Header.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (ip == null || ip.nextHeader() != Ipv6Header.NEXT_HEADER_ICMPV6) {
            return;
        }
        int off = eth.payloadOffset() + Ipv6Header.LENGTH;
        int len = Math.min(ip.payloadLength(), frame.length - off);
        if (len <= 0) {
            return;
        }

        Icmp6.parseAdvertisement(frame, off, len).ifPresent(na -> {
            // RFC 4861 7.1.1: an NA whose hop limit is not 255 has crossed a
            // router and must be discarded, whatever it claims.
            if (!Ipv6Header.isValidNeighborDiscovery(ip) || na.targetMac() == null) {
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

        // A neighbour solicitation carries the sender's own link-layer address, and
        // NS is multicast so it reaches this port without promiscuous mode. Linux has
        // always learned from these; not doing so was the IPv6 half of the §13.16 gap.
        Icmp6.parseSolicitation(frame, off, len).ifPresent(ns -> {
            if (!Ipv6Header.isValidNeighborDiscovery(ip) || ns.sourceMac() == null) {
                return;
            }
            InetAddress source = address(ip.src16());
            if (source == null || source.isAnyLocalAddress()) {
                return;   // duplicate address detection solicits from the unspecified address
            }
            cache.observe(source, ns.sourceMac(), ResolveSource.PASSIVE);
            notifyObservers(new ObservedNeighbor(source, ns.sourceMac(),
                                                 ObservationKind.NDP_NS, Instant.now()));
        });

        Icmp6.parseEchoReply(frame, off, len).ifPresent(echo -> {
            if (echo.id() == identifier) {
                completeProbe(echo.id(), echo.seq(), PingProbe.TTL_UNAVAILABLE, frame);
            }
        });
    }

    /**
     * Records "this IP is at this MAC, seen by us" and, when a resolve is already
     * waiting on that host, fires the unicast solicitation immediately rather than
     * waiting for the next retransmission — which is what turns a passive sighting
     * into a resolve that completes inside the caller's budget.
     * <p>
     * Provenance is {@code PASSIVE}: this is our own observation, unlike the
     * {@code GetIpNetEntry2} hint, which stays out of the cache entirely because it
     * is Windows' belief rather than something we saw.
     */
    private void learnSender(InetAddress source, MacAddress frameSource) {
        if (!learnable(binding, source, frameSource)) {
            return;
        }
        cache.observe(source, frameSource, ResolveSource.PASSIVE);
        if (pendingResolves.containsKey(source)) {
            solicit(source, 1);   // attempt >= 1: unicast only, we now have a hint
        }
    }

    /**
     * Whether a frame's sender may be cached as a neighbour.
     * <p>
     * The guards are what keep passive learning from producing a WRONG entry, which
     * matters more here than a missed one: {@code resolve()} serves the cache, so a
     * bad entry is reported as a {@code CACHE_HIT} rather than merely wasting a frame.
     * <ul>
     *   <li>A multicast source MAC is invalid in a sent frame; it also covers
     *       broadcast, whose first-octet bit is the same one.</li>
     *   <li>An OFF-LINK source is the decisive one: its frames arrive bearing the
     *       ROUTER's MAC, so caching that would claim a remote host lives at the
     *       gateway's address. ARP is link-local by definition — only on-link
     *       senders own the MAC that carried them.</li>
     *   <li>Our own address never belongs to a neighbour, and 0.0.0.0 belongs to
     *       nobody (DHCP discover).</li>
     * </ul>
     */
    static boolean learnable(NicBinding binding, InetAddress source, MacAddress frameSource) {
        return frameSource != null
               && !frameSource.isZero()
               && !frameSource.isMulticast()
               && source != null
               && !source.isAnyLocalAddress()
               && !source.isMulticastAddress()
               && binding.isOnLink(source)
               && !binding.isLocalAddress(source);
    }

    private void completeResolve(InetAddress target, MacAddress mac, ResolveSource source) {
        PendingResolve pending = pendingResolves.remove(target);
        if (pending != null) {
            pending.completeAll(ResolveResult.resolved(target, mac, source,
                    Duration.between(pending.startedAt, Instant.now())));
        }
    }

    private void completeProbe(int id, int seq, int ttl, byte[] frame) {
        PendingProbe probe = pendingProbes.remove(Identifiers.correlationKey(id, seq));
        if (probe == null) {
            return;
        }
        if (probe.expiry != null) {
            probe.expiry.cancel(false);
        }
        Duration rtt = Duration.ofNanos(System.nanoTime() - probe.sentAtNanos);
        probe.call.settle(new PingProbe(seq, true, rtt, ttl, frame, false, false, Optional.empty()));
    }

    private void notifyObservers(ObservedNeighbor neighbor) {
        if (observers.isEmpty()) {
            return;
        }
        // Never on the reader thread: a slow consumer would stall capture, and on
        // this backend one thread serves ARP, NDP and ICMP at once (spec 4.3).
        dispatcher.execute(() -> observers.forEach(o -> {
            try {
                o.accept(neighbor);
            } catch (RuntimeException ignored) {
                // one bad observer must not silence the rest
            }
        }));
    }

    // ---- lifecycle ----

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;   // idempotent: on Windows both roles are this one object
        }
        // ORDER MATTERS. Stop and JOIN the reader before closing the handle: its
        // capture buffers come from a shared arena, and closing that arena while
        // the reader sits inside pcap_next_ex throws "Session is acquired by 1
        // clients" and leaks the mapping. The positive read timeout bounds the
        // join at one tick.
        running = false;
        Thread t = reader;
        if (t != null) {
            try {
                t.join(20L * PcapHandle.READ_TIMEOUT_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        handle.close();

        // Pending futures complete NORMALLY with an error result, never
        // exceptionally - that would contradict the ping contract.
        pendingResolves.values().forEach(p -> p.completeAll(
                ResolveResult.notResolved(p.target, ResolveOutcome.ERROR, Duration.ZERO)));
        pendingResolves.clear();
        pendingProbes.forEach((key, probe) -> {
            if (probe.expiry != null) {
                probe.expiry.cancel(false);
            }
            probe.call.settle(PingProbe.failed(probe.sequence, PingError.IO));
        });
        pendingProbes.clear();
        observers.clear();
        // The scheduler and dispatcher are BORROWED - never shut them down here.
    }

    // ---- helpers ----

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static InetAddress address(byte[] raw) {
        try {
            return InetAddress.getByAddress(raw);
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    /**
     * Waiters on one in-flight solicitation, so a duplicate resolve joins rather than
     * re-sends.
     * <p>
     * They share ONE {@link CompletableFuture}. A per-caller list leaves a window
     * between the reader thread's {@code completeAll} — which completes the futures it
     * can see, then clears the list — and a concurrent {@code resolve()} that has
     * already taken this entry and is about to add its own future to it. That late
     * future is completed by nobody, because the timeout task removes by key and finds
     * the entry gone. In {@code sweep()} it feeds {@code allOf}, so the sweep hangs
     * instead of failing. One shared future closes the window: {@code complete} is
     * idempotent, and a caller arriving after completion observes the finished result.
     */
    private static final class PendingResolve {
        final InetAddress target;
        final Instant startedAt;
        final AtomicBoolean started = new AtomicBoolean();
        private final CompletableFuture<ResolveResult> result = new CompletableFuture<>();

        PendingResolve(InetAddress target, Instant startedAt) {
            this.target = target;
            this.startedAt = startedAt;
        }

        /** A copy, so a caller cannot complete the shared future for everyone else. */
        CompletableFuture<ResolveResult> await() {
            return result.copy();
        }

        void completeAll(ResolveResult outcome) {
            result.complete(outcome);
        }
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

    /** Collects the probes of one ping() call and completes when all have settled. */
    private static final class PendingCall {
        final CompletableFuture<PingResult> future = new CompletableFuture<>();
        final InetAddress target;
        final int expected;
        final List<PingProbe> settled = java.util.Collections.synchronizedList(new ArrayList<>());

        PendingCall(InetAddress target, int expected) {
            this.target = target;
            this.expected = expected;
        }

        void settle(PingProbe probe) {
            boolean done;
            synchronized (settled) {
                settled.add(probe);
                done = settled.size() >= expected;
            }
            if (done) {
                List<PingProbe> ordered;
                synchronized (settled) {
                    ordered = new ArrayList<>(settled);
                }
                ordered.sort(java.util.Comparator.comparingInt(PingProbe::sequence));
                future.complete(PingResult.of(target, ordered, null));
            }
        }
    }
}
