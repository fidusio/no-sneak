package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.codecs.*;
import io.xlogistx.nosneak.net.common.*;
import io.xlogistx.nosneak.net.pcap.InjectionProbe;
import io.xlogistx.nosneak.net.pcap.PcapHandle;
import io.xlogistx.nosneak.net.util.Identifiers;
import io.xlogistx.nosneak.net.util.IpMacCache;
import io.xlogistx.nosneak.net.util.PendingCall;
import io.xlogistx.nosneak.net.util.PendingResolve;
import io.xlogistx.nosneak.net.util.PassiveLearning;
import io.xlogistx.nosneak.net.util.SweepDriver;
import io.xlogistx.nosneak.net.util.SweepTargets;
import org.zoxweb.shared.util.RateController;

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
    private final ConcurrentHashMap<Long, PendingCall.Probe> pendingProbes = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Consumer<ObservedNeighbor>> observers =
            new CopyOnWriteArrayList<>();

    /** Why the driver refused the open()-time injection probe, or null when it injects. */
    private final String injectionFailure;

    /** Injection is a driver property: one accepted probe at open() answers it for both families. */
    private boolean canInject() {
        return injectionFailure == null && readerFailure == null;
    }
    /** Why the reader thread died, or null while it lives (§13.23-B). */
    private volatile String readerFailure;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private volatile Thread reader;

    /** Set once by the factory; may include this instance (§8.6). */
    private volatile List<WindowsPcapBackend> pingPeers = List.of();

    private WindowsPcapBackend(NicBinding binding, PcapHandle handle, IpMacCache cache,
                               ScheduledExecutorService scheduler, ExecutorService dispatcher,
                               String injectionFailure) {
        this.binding = binding;
        this.handle = handle;
        this.cache = cache;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
        this.injectionFailure = injectionFailure;
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
        // Every construction stage is guarded, not just the filter: a RuntimeException
        // from the injection probe or the reader start used to leak the pcap_t and its
        // shared arena (§13.7's leak, at a different line — §13.23-B, M8).
        WindowsPcapBackend backend = null;
        try {
            handle.setFilter(PcapHandle.DISCOVERY_FILTER);
            // Probe injection once (§8.6): pcap_sendpacket is driver-dependent and
            // commonly fails on wireless adapters, which capture fine but cannot send.
            // A failure marks the binding capture-only rather than failing the open.
            String injectionFailure = probeInjection(binding, handle);
            backend = new WindowsPcapBackend(binding, handle, IpMacCache.withDefaults(256),
                                             scheduler, dispatcher, injectionFailure);
            backend.startReader();
            return backend;
        } catch (DiscoveryException | RuntimeException e) {
            if (backend != null) {
                backend.close();
            } else {
                handle.close();
            }
            throw e;
        }
    }

    /**
     * Injects one frame for our OWN address — an ARP request when the binding has IPv4,
     * a Neighbor Solicitation when it has only IPv6 ({@link InjectionProbe}) — purely to
     * learn whether the driver accepts injected frames.
     *
     * @return null when the driver accepted it; otherwise why not, which {@code resolve()}
     *         reports as the detail behind {@code UNSUPPORTED}
     */
    private static String probeInjection(NicBinding binding, PcapHandle handle) {
        byte[] frame = InjectionProbe.frameFor(binding);
        if (frame == null) {
            return "no hardware address or no IP address on " + binding.javaName()
                    + " to originate an injection probe from";
        }
        return handle.trySend(frame);
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
        return capabilitiesOf(injectionFailure == null, readerFailure == null, binding,
                              Iphlpapi.isAvailable());
    }

    /**
     * PURE, so it can be pinned without a handle ({@code WindowsCapabilitiesTest}).
     * <p>
     * Injection is a driver property; the family is an address property (§13.23-B, M7):
     * {@code activeArp}/{@code icmpV4} need injection AND an IPv4 address, {@code activeNdp}/
     * {@code icmpV6} injection AND an IPv6 address. Everything the reader serves reports
     * false once the reader has died — the one way this record changes after publication.
     *
     * @param canInject         the open()-time probe was accepted
     * @param readerAlive       the capture thread is still running
     * @param iphlpapiAvailable {@code GetBestRoute2} is bound, so off-link targets route
     */
    static DiscoveryCapabilities capabilitiesOf(boolean canInject, boolean readerAlive,
                                                NicBinding binding, boolean iphlpapiAvailable) {
        boolean l2 = readerAlive && canInject && binding.supportsLayer2();
        boolean v4 = l2 && !binding.ipv4().isEmpty();
        boolean v6 = l2 && !binding.ipv6().isEmpty();
        return new DiscoveryCapabilities(
                v4,      // icmpV4  - crafted over pcap, so it needs injection and a v4 source
                v6,      // icmpV6
                v4,      // activeArp
                v6,      // activeNdp
                readerAlive,   // passiveObservation - NON-promiscuous capture, even without injection
                readerAlive,   // rawEvidence - whole frames reach completeProbe
                readerAlive,   // ttlAvailable - the IPv4 header is right there
                // Off-link needs the gateway's MAC, hence its IP, hence iphlpapi.
                // With GetBestRoute2 bound this backend routes; without it, on-link only.
                l2 && iphlpapiAvailable,
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

        // Our own address FIRST, before the cache: no host on the segment answers an ARP
        // request for it, since the only owner is the one asking — and nothing another
        // host says about our address (a spoofer, or our own captured probe before
        // §13.23) may ever answer for it.
        if (binding.isLocalAddress(target) && binding.supportsLayer2()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, binding.hardwareAddress(), ResolveSource.LOCAL_INTERFACE,
                    Duration.between(started, Instant.now())));
        }
        Optional<IpMacCache.Entry> cached = cache.get(target);
        if (cached.isPresent() && cached.get().hasMac()) {
            return CompletableFuture.completedFuture(ResolveResult.resolved(
                    target, cached.get().mac(), ResolveSource.CACHE_HIT,
                    Duration.between(started, Instant.now())));
        }
        // A dead reader cannot see a reply: say so now, with its cause, rather than
        // injecting and reporting TIMEOUT at full budget (§13.23-B, S14).
        String dead = readerFailure;
        if (dead != null) {
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.ERROR, Duration.between(started, Instant.now()), dead));
        }
        boolean v4 = target instanceof Inet4Address;
        if (v4 ? !capabilities().activeArp() : !capabilities().activeNdp()) {
            // Refused injection carries the driver's words; a missing family does not.
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now()),
                    injectionFailure));
        }
        if (!binding.isOnLink(target)) {
            // Nothing off-link can answer ARP, and we cannot route to it either.
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        // Deduplicate: a second caller joins the first caller's future rather than
        // emitting a second solicitation (spec section 9.2).
        PendingResolve pending = pendingResolves.computeIfAbsent(target,
                k -> new PendingResolve(target, started, dispatcher));
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
        String refused = target instanceof Inet4Address
                ? sendArp(target, attempt)
                : sendNeighborSolicitation(target);
        if (refused != null) {
            // Per resolve, never per backend: the entry that owns this solicitation is the
            // only one entitled to report its failure (§13.23-B).
            PendingResolve entry = pendingResolves.get(target);
            if (entry != null) {
                entry.recordSendError(refused);
            }
        }
    }

    /** @return null when at least one frame was accepted; otherwise why none was */
    private String sendArp(InetAddress target, int attempt) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return "no local IPv4 address on " + binding.javaName()
                    + " to use as the ARP sender address";
        }
        byte[] arp = ArpPacket.request(binding.hardwareAddress(),
                                       source.get().address().getAddress(), target.getAddress());
        Optional<MacAddress> hint = unicastHint(target);
        // Either frame reaching the wire is enough for the solicitation to count as
        // sent — the point of sending both is that they fail independently.
        String unicast = hint.map(mac -> handle.trySend(EthernetFrame.build(
                mac, binding.hardwareAddress(), EthernetFrame.ETHERTYPE_ARP, arp))).orElse(null);
        boolean accepted = hint.isPresent() && unicast == null;
        String broadcast = null;
        if (hint.isEmpty() || attempt == 0) {
            broadcast = handle.trySend(EthernetFrame.build(MacAddress.BROADCAST,
                    binding.hardwareAddress(), EthernetFrame.ETHERTYPE_ARP, arp));
            accepted |= broadcast == null;
        }
        return accepted ? null : (broadcast != null ? broadcast : unicast);
    }

    /** @return null when the frame was accepted; otherwise why not */
    private String sendNeighborSolicitation(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return "no local IPv6 address on " + binding.javaName()
                    + " to source a Neighbor Solicitation from";
        }
        byte[] src = source.get().address().getAddress();
        byte[] ns = Icmp6.neighborSolicitation(src, target.getAddress(),
                                               binding.hardwareAddress());
        byte[] dst = Icmp6.solicitedNodeMulticast(target.getAddress());
        // Hop limit 255 is mandatory here (RFC 4861 7.1.1) - the builder pins it.
        byte[] ip = Ipv6Header.forNeighborDiscovery(src, dst, ns.length);
        byte[] payload = concat(ip, ns);
        return handle.trySend(EthernetFrame.build(Icmp6.solicitedNodeMac(target.getAddress()),
                                                  binding.hardwareAddress(),
                                                  EthernetFrame.ETHERTYPE_IPV6, payload));
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
     * WINDOWS' NEIGHBOUR TABLE SECOND. The cache has learned from every IP frame the
     * capture sees since §13.17 (the Linux {@code ETH_P_IP} learner's coverage, through
     * {@link PcapHandle#DISCOVERY_FILTER}), so this fallback now covers only a QUIET
     * host — one Windows has talked to but that has said nothing within earshot of
     * this handle. For that host {@code GetIpNetEntry2} is still the difference between
     * resolving and timing out.
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
                // Identity, not key: a retry armed for THIS resolve must never solicit
                // on behalf of a later resolve of the same address.
                if (pendingResolves.get(target) == pending) {
                    solicit(target, retry);
                }
            }, at, TimeUnit.MILLISECONDS);
        }
        scheduler.schedule(() -> {
            // Claim THIS entry (remove(key, value)), so a deadline that fires late cannot
            // tear down a newer resolve for the same target (§13.23-B).
            if (pendingResolves.remove(target, pending)) {
                pending.completeAll(pending.expire(Instant.now()));
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
        // SweepTargets withholds the interface's own network/broadcast addresses AND the
        // range's own edges when the range is off-link or wider than the interface's
        // prefix (§13.23-C); the summary's total is the probeable count.
        List<InetAddress> targets = SweepTargets.probeable(binding, range);
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
        int packetsPerHost = 1 + (options.doIcmp() ? options.pingCount() : 0);
        // Admission is event-driven (SweepDriver, §13.22): the window and the pacer are
        // honoured without ever parking a pool thread, because the per-host timeouts
        // run on that same pool.
        RateController pacer = SweepDriver.pacer(options.maxPacketsPerSecond(), packetsPerHost);
        return SweepDriver.run(targets.iterator(), options.maxInFlight(), pacer, scheduler,
                               dispatcher,
                               target -> sweepOne(target, options, onHost, alive, macs, icmp))
                .thenApply(ignored -> new SweepSummary(targets.size(), alive.get(), macs.get(),
                        icmp.get(), Duration.between(started, Instant.now())));
    }

    private CompletableFuture<Void> sweepOne(InetAddress target, SweepOptions options,
                                             Consumer<HostRecord> onHost, AtomicInteger alive,
                                             AtomicInteger macs, AtomicInteger icmp) {
        // Network and directed-broadcast addresses were already withheld by
        // SweepTargets.probeable in sweep(); every target here may be probed.
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

            // HostRecord.fromProbes is the one record constructor every backend uses:
            // icmpAlive from observedOnWire(), RTT only when measured() (§13.18, §13.23-C).
            return pinged.thenAccept(result ->
                HostRecord.fromProbes(target, resolved, result, Instant.now()).ifPresent(record -> {
                    alive.incrementAndGet();
                    if (record.mac().isPresent()) {
                        macs.incrementAndGet();
                    }
                    if (record.icmpAlive()) {
                        icmp.incrementAndGet();
                    }
                    dispatcher.execute(() -> onHost.accept(record));
                }));
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
        String dead = readerFailure;
        if (dead != null) {
            return CompletableFuture.completedFuture(failedPing(target, count, PingError.IO, dead));
        }
        boolean v4 = target instanceof Inet4Address;
        if (v4 ? !capabilities().icmpV4() : !capabilities().icmpV6()) {
            return CompletableFuture.completedFuture(
                    failedPing(target, count, PingError.IO, injectionFailure));
        }

        // Resolve the L2 NEXT HOP, which is the target itself when on-link and the
        // gateway when not. The IP header still carries the real destination.
        return resolve(route.l2Target(), timeout).thenCompose(resolved -> {
            if (!resolved.resolved()) {
                // TIMEOUT: the wire was asked and nobody answered. ERROR: nothing could be
                // asked (injection refused, reader dead) — an IO failure carrying the text.
                // Anything else is a routing/capability refusal.
                PingError error = switch (resolved.outcome()) {
                    case TIMEOUT -> PingError.HOST_UNREACHABLE;
                    case ERROR -> PingError.IO;
                    default -> PingError.NETWORK_UNREACHABLE;
                };
                return CompletableFuture.completedFuture(
                        failedPing(target, count, error, resolved.detail().orElse(null)));
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
        if (binding.isOnLink(target) && canInject()) {
            return new Route(this, target);
        }
        for (WindowsPcapBackend peer : pingPeers) {
            if (peer.canInject() && peer.binding.isOnLink(target)) {
                return new Route(peer, target);
            }
        }
        InetAddress gateway = Iphlpapi.nextHopFor(target).orElse(null);
        if (gateway == null) {
            return null;
        }
        if (binding.isOnLink(gateway) && canInject()) {
            return new Route(this, gateway);
        }
        for (WindowsPcapBackend peer : pingPeers) {
            if (peer.canInject() && peer.binding.isOnLink(gateway)) {
                return new Route(peer, gateway);
            }
        }
        return null;
    }

    private CompletableFuture<PingResult> emitProbes(InetAddress target, MacAddress destMac,
                                                     int count, Duration timeout) {
        PendingCall call = new PendingCall(target, count, dispatcher);
        boolean v4 = target instanceof Inet4Address;
        // sourceFor prefers the address whose prefix contains the target, then the
        // family's first routable address, so it is non-empty for an OFF-LINK target
        // too; it is empty only when this interface has no address of that family.
        byte[] src = binding.sourceFor(target)
                .orElseThrow(() -> new IllegalStateException(
                        "Interface " + binding.javaName() + " has no "
                        + (v4 ? "IPv4" : "IPv6") + " address to send from"))
                .address().getAddress();

        // Probes are PIPELINED: all count requests go out immediately with
        // distinct sequence numbers, so worst-case wall time is one timeout.
        try {
            for (int i = 0; i < count; i++) {
                int seq = sequences.next();
                long key = Identifiers.correlationKey(identifier, seq);
                PendingCall.Probe probe = call.newProbe(seq, System.nanoTime());
                pendingProbes.put(key, probe);

                byte[] frame = v4
                        ? buildIcmpV4Frame(src, target.getAddress(), destMac, seq)
                        : buildIcmpV6Frame(src, target.getAddress(), destMac, seq);
                String refused = handle.trySend(frame);
                if (refused != null) {
                    pendingProbes.remove(key, probe);
                    call.setDetail(refused);
                    probe.fail(PingError.IO);
                    continue;
                }
                probe.expiry = scheduler.schedule(() -> {
                    if (pendingProbes.remove(key, probe)) {
                        probe.fail(PingError.TIMEOUT);
                    }
                }, Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS);
            }
        } catch (RuntimeException e) {
            // A probe registered but never sent (or never given a deadline) would leave
            // the call incomplete forever (§13.23-E). Drop its map entry so a wrapped
            // sequence cannot find it, then close every open slot with the cause.
            pendingProbes.values().removeIf(p -> p.call == call && !p.isSettled());
            call.failRemaining(PingError.IO, "ping aborted before every probe was sent: " + e);
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
        return failedPing(target, count, error, null);
    }

    private PingResult failedPing(InetAddress target, int count, PingError error, String detail) {
        List<PingProbe> probes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            probes.add(PingProbe.failed(i, error));
        }
        return PingResult.of(target, probes, error, detail);
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
                    // Any DiscoveryException from nextPacket is fatal by construction
                    // (PCAP_ERROR: the adapter went away, or the driver gave up). A
                    // reader that dies silently leaves every caller to time out at full
                    // budget; instead fail what is pending and degrade capabilities.
                    failReader("pcap_next_ex on " + binding.backendDeviceName() + ": "
                               + e.getMessage());
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
        // Our own injected frames come back on the capture (the injection probe at
        // open(), every solicitation, every echo). Nothing in them is a peer, and
        // completeProbe only ever needs REPLIES, which carry the peer's MAC.
        if (binding.hardwareAddress() != null && binding.hardwareAddress().equals(eth.src())) {
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
        if (arp == null) {
            return;
        }
        InetAddress sender = address(arp.spa());
        // The same guard as every other learner (§13.23): rejects a null or 0.0.0.0
        // sender (RFC 5227 probes), a zero or multicast SHA, our own address or MAC,
        // and an off-link sender whose frame carries the router's MAC.
        if (!PassiveLearning.learnable(binding, sender, arp.sha())) {
            return;
        }
        // ONE provenance for both the cache and the completion: ACTIVE_ARP only for a
        // reply to our own solicitation; a request or gratuitous announcement may
        // still satisfy a pending resolve (§4.2) but is reported as what it was.
        ResolveSource source = PassiveLearning.arpProvenance(arp, pendingResolves.containsKey(sender));
        cache.observe(sender, arp.sha(), source);
        completeResolve(sender, arp.sha(), source);
        notifyObservers(new ObservedNeighbor(sender, arp.sha(), PassiveLearning.arpKind(arp),
                                             Instant.now()));
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
        if (ip == null) {
            return;
        }
        // BEFORE the next-header test and BEFORE the hop-255 gate: ANY IPv6 frame names
        // its sender's MAC in the Ethernet header — an mDNS announcement, an echo reply
        // at hop limit 64, a TCP segment. The hop-255 rule is RFC 4861's rule for ND
        // MESSAGES and does not apply to a frame-header claim; the on-link guard is the
        // defence here, as it is for IPv4 (§13.13, §13.23).
        learnSender(address(ip.src16()), eth.src());
        if (ip.nextHeader() != Ipv6Header.NEXT_HEADER_ICMPV6) {
            return;
        }
        int off = eth.payloadOffset() + Ipv6Header.LENGTH;
        int len = Math.min(ip.payloadLength(), frame.length - off);
        if (len <= 0) {
            return;
        }
        // RFC 4861 7.1.1: an NS/NA whose hop limit is not 255 has crossed a router and
        // must be discarded, whatever it claims. Proves the SENDER is on-link — not that
        // the address it advertises is, which is what the guard below checks.
        boolean nd = Ipv6Header.isValidNeighborDiscovery(ip);

        Icmp6.parseAdvertisement(frame, off, len).ifPresent(na -> {
            InetAddress target = address(na.targetIp16());
            if (!nd || !PassiveLearning.learnable(binding, target, na.targetMac())) {
                return;
            }
            ResolveSource source =
                    PassiveLearning.ndpProvenance(na, pendingResolves.containsKey(target));
            cache.observe(target, na.targetMac(), source);
            completeResolve(target, na.targetMac(), source);
            notifyObservers(new ObservedNeighbor(target, na.targetMac(),
                                                 ObservationKind.NDP_NA, Instant.now()));
        });

        // A neighbour solicitation carries the sender's own link-layer address, and
        // NS is multicast so it reaches this port without promiscuous mode. Linux has
        // always learned from these; not doing so was the IPv6 half of the §13.16 gap.
        // The guard also rejects the unspecified source duplicate address detection uses.
        Icmp6.parseSolicitation(frame, off, len).ifPresent(ns -> {
            InetAddress source = address(ip.src16());
            if (!nd || !PassiveLearning.learnable(binding, source, ns.sourceMac())) {
                return;
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
        // The guard lives in util.PassiveLearning, shared by every backend and every
        // learner (§13.23); its rules are what keep a passive sighting from becoming
        // a WRONG answer rather than a missing one.
        if (!PassiveLearning.learnable(binding, source, frameSource)) {
            return;
        }
        cache.observe(source, frameSource, ResolveSource.PASSIVE);
        if (pendingResolves.containsKey(source)) {
            solicit(source, 1);   // attempt >= 1: unicast only, we now have a hint
        }
    }

    private void completeResolve(InetAddress target, MacAddress mac, ResolveSource source) {
        PendingResolve pending = pendingResolves.remove(target);
        if (pending != null) {
            pending.completeAll(ResolveResult.resolved(target, mac, source,
                    Duration.between(pending.startedAt, Instant.now())));
        }
    }

    private void completeProbe(int id, int seq, int ttl, byte[] frame) {
        PendingCall.Probe probe = pendingProbes.remove(Identifiers.correlationKey(id, seq));
        if (probe == null) {
            return;
        }
        Duration rtt = Duration.ofNanos(System.nanoTime() - probe.sentAtNanos);
        probe.settle(new PingProbe(seq, true, rtt, ttl, frame, false, false, Optional.empty()));
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
        failPending("closed");
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
     * Fails every outstanding resolve and probe with {@code why}, claiming each entry
     * with {@code remove(key, value)} first so a timeout task firing concurrently cannot
     * settle the same probe twice (§13.23-B). Used by {@code close()} and by a reader
     * that dies.
     */
    /**
     * The reader is dead: record why, stop, and fail everything that was waiting on it.
     * Runs on the dying reader thread — the same thread that completes futures today.
     */
    private void failReader(String why) {
        readerFailure = why;
        running = false;
        failPending(why);
    }

    private void failPending(String why) {
        pendingResolves.forEach((target, pending) -> {
            if (pendingResolves.remove(target, pending)) {
                pending.completeAll(pending.abort(why));
            }
        });
        pendingProbes.forEach((key, probe) -> {
            if (pendingProbes.remove(key, probe)) {
                probe.call.setDetail(why);
                probe.fail(PingError.IO);
            }
        });
    }
}
