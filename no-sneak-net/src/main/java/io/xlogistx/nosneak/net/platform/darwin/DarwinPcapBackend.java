package io.xlogistx.nosneak.net.platform.darwin;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.EthernetFrame;
import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.codecs.Ipv4Header;
import io.xlogistx.nosneak.net.codecs.Ipv6Header;
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
import io.xlogistx.nosneak.net.pcap.InjectionProbe;
import io.xlogistx.nosneak.net.pcap.PcapHandle;
import io.xlogistx.nosneak.net.util.IpMacCache;
import io.xlogistx.nosneak.net.util.PendingResolve;
import io.xlogistx.nosneak.net.util.PassiveLearning;
import io.xlogistx.nosneak.net.util.SweepDriver;
import io.xlogistx.nosneak.net.util.SweepTargets;
import org.zoxweb.shared.util.RateController;

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

    /** Why the driver refused the open()-time injection probe, or null when it injects. */
    private final String injectionFailure;
    /** Why the reader thread died, or null while it lives (§13.23-B). */
    private volatile String readerFailure;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean running = true;
    private volatile Thread reader;

    /** Set once by the factory, before publication (§3.2). Borrowed, never closed here. */
    private volatile ICMPPing pinger;

    private DarwinPcapBackend(NicBinding binding, PcapHandle handle,
                              ScheduledExecutorService scheduler, ExecutorService dispatcher,
                              String injectionFailure) {
        this.binding = binding;
        this.handle = handle;
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
        this.injectionFailure = injectionFailure;
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
                    openFailureMessage(binding.backendDeviceName(), e.getMessage()), e);
        }
        // Every construction stage is guarded, not just the filter: a RuntimeException
        // from the injection probe or the reader start used to leak the pcap_t and its
        // shared arena (§13.23-B, M8).
        DarwinPcapBackend backend = null;
        try {
            handle.setFilter(PcapHandle.DISCOVERY_FILTER);
            String injectionFailure = probeInjection(binding, handle);
            backend = new DarwinPcapBackend(binding, handle, scheduler, dispatcher,
                                            injectionFailure);
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
     * Blames privilege only when the cause plausibly is privilege (§13.23-B, M5). §13.20
     * records a wrong diagnosis from the old always-root wording: "you are root and the
     * message says you need root". A device that is down, or a datalink this backend
     * cannot speak, now leads with pcap's own text and the device name.
     */
    static String openFailureMessage(String device, String pcapText) {
        String text = pcapText == null ? "(no detail)" : pcapText;
        String lead = "Could not open " + device + " for capture on macOS: " + text;
        String lower = text.toLowerCase(java.util.Locale.ROOT);
        boolean privilege = lower.contains("permission denied")
                || lower.contains("operation not permitted")
                || lower.contains("cannot open bpf device");
        if (!privilege) {
            return lead;
        }
        return lead + ". /dev/bpf* is mode 0600, so layer-2 discovery requires root — ICMP "
                + "alone does not, and remains available through openIcmpOnly().";
    }

    /**
     * Injects one frame for our OWN address — an ARP request when the binding has IPv4,
     * a Neighbor Solicitation when it has only IPv6 ({@link InjectionProbe}) — purely to
     * learn whether the driver accepts injected frames. A refusal marks the binding
     * capture-only rather than failing the open, which is §8.6's rule and applies just
     * as well to a Mac's Wi-Fi adapter as to a PC's.
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
        return capabilitiesOf(injectionFailure == null, readerFailure == null, binding,
                              p == null ? null : p.capabilities());
    }

    /**
     * PURE, so it can be pinned without a handle ({@code DarwinCapabilitiesTest}).
     * <p>
     * Injection is a driver property; the family is an address property (§13.23-B, M7).
     * Everything that reaches a caller through the PINGER follows the pinger's record —
     * including {@code rawEvidence}: {@code PingProbe.rawReply} is the only delivery path
     * for bytes, and {@code DarwinIcmpPing} fills it empty, so the old literal {@code true}
     * here promised evidence nothing ever carried (M4). {@code ttlAvailable} likewise: the
     * datagram ICMP socket strips the IP header, so claiming it would advertise a
     * distance the sweep then reports as -1. Passive observation is NON-promiscuous
     * capture — broadcast, multicast, and traffic addressed to us — and reports false once
     * the reader has died.
     *
     * @param pinger the attached pinger's capabilities, or null before one is attached
     */
    static DiscoveryCapabilities capabilitiesOf(boolean canInject, boolean readerAlive,
                                                NicBinding binding, DiscoveryCapabilities pinger) {
        boolean l2 = readerAlive && canInject && binding.supportsLayer2();
        return new DiscoveryCapabilities(
                pinger != null && pinger.icmpV4(),
                pinger != null && pinger.icmpV6(),
                l2 && !binding.ipv4().isEmpty(),   // activeArp
                l2 && !binding.ipv6().isEmpty(),   // activeNdp
                readerAlive,                        // passiveObservation - non-promiscuous capture
                pinger != null && pinger.rawEvidence(),
                pinger != null && pinger.ttlAvailable(),
                pinger != null && pinger.offLinkIcmp(),
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

        // Our own address FIRST, before the cache: nothing answers an ARP request for
        // it, because the only host that owns it is the one asking — and nothing another
        // host claims about our address may ever answer for it (§13.23).
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
            return CompletableFuture.completedFuture(ResolveResult.notResolved(
                    target, ResolveOutcome.UNSUPPORTED, Duration.between(started, Instant.now())));
        }

        PendingResolve entry = pending.computeIfAbsent(target,
                                                       k -> new PendingResolve(target, dispatcher));
        CompletableFuture<ResolveResult> future = entry.await();

        if (entry.started.compareAndSet(false, true)) {
            cache.markIncomplete(target);
            if (provoke) {
                provokeReply(target, Math.max(1, timeout.toMillis()));
            }
            solicit(target, 0);
            scheduleRetries(entry, target, timeout);
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
        // No hint check here: resolve() already returned CACHE_HIT for any target with
        // a cached MAC, so by this point there is never a hint to consult (§13.21 S5).
        if (p == null || !(target instanceof Inet4Address)) {
            return;
        }
        try {
            p.ping(target, 1, Duration.ofMillis(Math.min(budgetMillis, 1000)));
        } catch (RuntimeException ignored) {
            // Best effort; the broadcast retries continue regardless.
        }
    }

    /** ARP 3 attempts 1s apart; NDP the same, which is RFC 4861's RETRANS_TIMER. */
    private void scheduleRetries(PendingResolve entry, InetAddress target, Duration timeout) {
        long budget = Math.max(1, timeout.toMillis());
        for (int attempt = 1; attempt < SOLICIT_ATTEMPTS; attempt++) {
            long at = attempt * RETRANSMIT.toMillis();
            if (at >= budget) {
                break;
            }
            int retry = attempt;
            scheduler.schedule(() -> {
                // Identity, not key: a retry armed for THIS resolve never solicits for a
                // later resolve of the same address.
                if (pending.get(target) == entry) {
                    solicit(target, retry);
                }
            }, at, TimeUnit.MILLISECONDS);
        }
        scheduler.schedule(() -> {
            // Claim THIS entry, so a late deadline cannot tear down a newer resolve.
            if (pending.remove(target, entry)) {
                entry.completeAll(entry.expire(Instant.now()));
            }
        }, budget, TimeUnit.MILLISECONDS);
    }

    private void solicit(InetAddress target, int attempt) {
        String refused = target instanceof Inet4Address
                ? sendArp(target, attempt)
                : sendNeighborSolicitation(target);
        if (refused != null) {
            // Per resolve, never per backend (§13.23-B): the deadline reports ERROR with
            // this text instead of a TIMEOUT for a frame that never left the host.
            PendingResolve entry = pending.get(target);
            if (entry != null) {
                entry.recordSendError(refused);
            }
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
    /** @return null when at least one frame was accepted; otherwise why none was */
    private String sendArp(InetAddress target, int attempt) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return "no local IPv4 address on " + binding.javaName()
                    + " to use as the ARP sender address";
        }
        byte[] arp = ArpPacket.request(binding.hardwareAddress(),
                                       source.get().address().getAddress(),
                                       target.getAddress());
        Optional<MacAddress> hint = unicastHint(target);
        // Either frame reaching the wire is enough — the two fail independently.
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

    /**
     * Hop limit 255 is mandatory (RFC 4861 §7.1.1); the builder pins it.
     *
     * @return null when the frame was accepted; otherwise why not
     */
    private String sendNeighborSolicitation(InetAddress target) {
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            return "no local IPv6 address on " + binding.javaName()
                    + " to source a Neighbor Solicitation from";
        }
        byte[] src = source.get().address().getAddress();
        byte[] raw = target.getAddress();
        byte[] ns = Icmp6.neighborSolicitation(src, raw, binding.hardwareAddress());
        byte[] ip = Ipv6Header.forNeighborDiscovery(src, Icmp6.solicitedNodeMulticast(raw),
                                                    ns.length);
        byte[] payload = new byte[ip.length + ns.length];
        System.arraycopy(ip, 0, payload, 0, ip.length);
        System.arraycopy(ns, 0, payload, ip.length, ns.length);
        return handle.trySend(EthernetFrame.build(Icmp6.solicitedNodeMac(raw),
                                                  binding.hardwareAddress(),
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
        // SweepTargets withholds the interface's own network/broadcast addresses AND the
        // range's own edges when the range is off-link or wider than the interface's
        // prefix (§13.23-C); the summary's total is the probeable count.
        List<InetAddress> targets = SweepTargets.probeable(binding, range);
        AtomicInteger alive = new AtomicInteger();
        AtomicInteger macs = new AtomicInteger();
        AtomicInteger icmp = new AtomicInteger();
        // Two ARP frames per host: a hinted target gets unicast AND broadcast on the
        // first attempt. Reserving the worst case keeps the emitted rate at or under the
        // cap, the only direction a safety limit may err in.
        int packetsPerHost = (options.doMac() ? 2 : 0)
                + (options.doIcmp() ? options.pingCount() : 0);
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

        // HostRecord.fromProbes is the one record constructor every backend uses:
        // icmpAlive from observedOnWire(), RTT only when measured() (§13.18, §13.23-C).
        return mac.thenAcceptBoth(pinged, (resolved, result) ->
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
                    // Any DiscoveryException from nextPacket is fatal by construction. A
                    // reader that dies silently leaves every caller to time out at full
                    // budget; fail what is pending and degrade capabilities instead.
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
        ResolveSource source = PassiveLearning.arpProvenance(arp, pending.containsKey(sender));
        cache.observe(sender, arp.sha(), source);
        completeResolve(sender, arp.sha(), source);
        notifyObservers(new ObservedNeighbor(sender, arp.sha(), PassiveLearning.arpKind(arp),
                                             Instant.now()));
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
        Ipv4Header.View ip =
                Ipv4Header.parse(frame, eth.payloadOffset(), eth.payloadLength()).orElse(null);
        if (ip == null) {
            return;
        }
        learnSender(address(ip.src4()), eth.src());
    }

    /**
     * Records "this IP is at this MAC, seen by us" — family-agnostic — and, when a
     * resolve is already waiting on that host, fires the unicast solicitation now
     * rather than at the next retransmission. The guard is {@link PassiveLearning}'s,
     * shared by every backend (§13.23).
     */
    private void learnSender(InetAddress source, MacAddress frameSource) {
        if (!PassiveLearning.learnable(binding, source, frameSource)) {
            return;
        }
        cache.observe(source, frameSource, ResolveSource.PASSIVE);
        if (source instanceof Inet4Address && pending.containsKey(source)) {
            sendArp(source, 1);
        }
    }

    private void onIpv6(EthernetFrame.View eth, byte[] frame) {
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
        if (len <= 0 || !Ipv6Header.isValidNeighborDiscovery(ip)) {
            // RFC 4861 7.1.1: NS/NA whose hop limit is not 255 crossed a router and are
            // discarded. Proves the SENDER is on-link — not that the address it
            // advertises is, which is what the guard below checks.
            return;
        }

        Icmp6.parseAdvertisement(frame, off, len).ifPresent(na -> {
            InetAddress target = address(na.targetIp16());
            if (!PassiveLearning.learnable(binding, target, na.targetMac())) {
                return;
            }
            ResolveSource source = PassiveLearning.ndpProvenance(na, pending.containsKey(target));
            cache.observe(target, na.targetMac(), source);
            completeResolve(target, na.targetMac(), source);
            notifyObservers(new ObservedNeighbor(target, na.targetMac(),
                                                 ObservationKind.NDP_NA, Instant.now()));
        });

        Icmp6.parseSolicitation(frame, off, len).ifPresent(ns -> {
            InetAddress source = address(ip.src16());
            // The guard also rejects the unspecified source duplicate address detection uses.
            if (!PassiveLearning.learnable(binding, source, ns.sourceMac())) {
                return;
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

        failPending("closed");
        observers.clear();
        // The pinger is BORROWED - never closed here. Nor are the executors (§4.3).
    }

    /**
     * Fails every outstanding resolve with {@code why}, claiming each entry with
     * {@code remove(key, value)} so a deadline firing concurrently cannot complete it a
     * second time (§13.23-B). Used by {@code close()} and by a reader that dies.
     */
    /** The reader is dead: record why, stop, fail everything waiting on it (§13.23-B). */
    private void failReader(String why) {
        readerFailure = why;
        running = false;
        failPending(why);
    }

    private void failPending(String why) {
        pending.forEach((target, entry) -> {
            if (pending.remove(target, entry)) {
                entry.completeAll(entry.abort(why));
            }
        });
    }

    private static InetAddress address(byte[] raw) {
        try {
            return InetAddress.getByAddress(raw);
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

}
