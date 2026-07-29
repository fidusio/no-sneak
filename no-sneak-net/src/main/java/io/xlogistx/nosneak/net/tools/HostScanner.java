package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.HostDiscoveryFactory;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.ICMPPing;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservedNeighbor;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.Subscription;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;

import org.zoxweb.server.task.TaskUtil;

import java.io.Closeable;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/**
 * A long-lived, reusable host-discovery session: open it once, then run as many
 * pings, resolves and sweeps through it as you like, concurrently, until you
 * close it.
 * <p>
 * This is the embedding surface — {@link HostScan} is just a command line over
 * it, and applications drive the same object. Note the shape that implies: callers
 * are ordinary code that runs a scan and keeps the result, and a GUI displays that
 * result afterwards; nothing is expected to drive this from an event thread. It
 * exists because the
 * factory hands back wiring, not a workflow: {@link HostDiscoveryFactory#open}
 * costs a pcap handle or a raw socket plus two reader threads <em>per
 * interface</em>, so opening and closing it around every single ping — which is
 * what a one-shot CLI does — is both slow and, on Windows, a visible churn of
 * Npcap handles.
 * <p>
 * <b>Nothing here blocks the calling thread</b> except {@link #open}, {@link #reopen}
 * and {@link #close}. Every operation returns a {@link CompletableFuture}, and even
 * hostname lookup is pushed onto the dispatcher rather than run on the caller.
 * <p>
 * <b>A returned future completes on a backend READER thread</b>, so anything chained
 * onto it runs there unless you ask otherwise. Keep that work short — take the result,
 * hand it off, return — and push anything slower onto an executor of your own with the
 * {@code *Async} forms. This bites harder on Linux than anywhere else: its ICMP readers
 * are two threads for the WHOLE JVM (§4.4), not one per NIC as on Windows, so a
 * continuation that blocks stalls reception for every concurrent ping and for the ICMP
 * half of every running sweep — which then report timeouts this session inflicted on
 * itself. <b>Do not render from a continuation.</b> Give the result to whatever owns the
 * display and let it draw on its own thread, which for Swing means
 * {@code SwingUtilities.invokeLater} on that side rather than UI work on this one.
 * <p>
 * Sweep results are the exception and are already safe: {@code onHost} is dispatched on
 * a dispatcher thread, never on a reader thread.
 * <p>
 * Whether this class should hop returned futures onto the dispatcher itself is an
 * <b>open decision</b> (§13.15) — a change that did exactly that was written and then
 * reverted. Until it is settled, the contract is the paragraph above: the reader thread
 * is where a continuation lands, and callers are what keep it moving.
 * <p>
 * <b>It never fails to open.</b> A machine without Npcap, or a Linux box without
 * root, still yields an object you can question rather than an exception; ask
 * {@link #mode()} and {@link #diagnostic()} and disable the controls that cannot
 * work. How degraded that mode is varies by platform, and Linux is the harsh case —
 * without root it is {@link Mode#UNAVAILABLE}, ping included, because its ICMP is
 * {@code SOCK_RAW}. Do not assume a session can ping just because it opened. An
 * operation the current mode cannot perform completes exceptionally with a
 * {@link DiscoveryException} that says why, rather than silently returning nothing.
 * Note the distinction the whole subsystem rests on: an unreachable <em>host</em> is
 * a normal result ({@code received == 0}), not an exception. Only an unusable
 * <em>backend</em> is exceptional.
 * <p>
 * <b>It does not own the executors and does not shut them down.</b> By default it
 * runs on zoxweb's process-wide pools, shared with the rest of no-sneak; closing a
 * scanner releases sockets, handles and reader threads and leaves the pools alone.
 * Only an application that owns the whole process may call {@code TaskUtil.close()},
 * which is why {@link HostScan} does and this class does not.
 * <p>
 * Thread-safe. {@link #close()} is idempotent.
 */
public final class HostScanner implements Closeable {

    /** Probes per ping when the caller does not say. Matches ping(8) habit, not the sweep default of 1. */
    public static final int DEFAULT_PING_COUNT = 4;
    public static final Duration DEFAULT_PING_TIMEOUT = Duration.ofSeconds(2);
    /** Covers the backends' internal ARP/NDP retransmission schedule with room to spare. */
    public static final Duration DEFAULT_RESOLVE_TIMEOUT = Duration.ofSeconds(3);

    /**
     * How much of the subsystem actually came up. Constant until {@link #reopen()}.
     */
    public enum Mode {
        /** Layer 2 and ICMP: resolve, sweep, observe and ping all work. */
        FULL,
        /**
         * ICMP only — the layer-2 backend would not open. Ping works because the
         * kernel routes it; resolve, sweep and observe do not, since ARP and NDP
         * have no kernel path. This is the unprivileged <b>macOS</b> shape, where
         * ICMP is an unprivileged {@code SOCK_DGRAM} socket.
         * <p>
         * <b>Not reachable on Linux by dropping privilege.</b> Linux ICMP is
         * {@code SOCK_RAW} and wants {@code CAP_NET_RAW} exactly like
         * {@code AF_PACKET}, so whatever denies layer 2 denies ping in the same
         * breath and an unprivileged Linux box lands in {@link #UNAVAILABLE}, not
         * here. Reaching this mode on Linux means layer 2 failed for some reason
         * OTHER than privilege.
         */
        ICMP_ONLY,
        /** Nothing opened. Every operation fails with the reason in {@link #diagnostic()}. */
        UNAVAILABLE;

        public boolean canPing() {
            return this != UNAVAILABLE;
        }

        /** ARP, NDP, sweep and passive observation. */
        public boolean canLayer2() {
            return this == FULL;
        }
    }

    /**
     * Everything {@link #reopen()} swaps at once. Immutable, so an operation reads
     * one consistent snapshot and cannot see a half-replaced session.
     */
    private record Session(Mode mode,
                           HostDiscoveryFactory.Discovery discovery,
                           ICMPPing pinger,
                           String diagnostic) {

        List<HostDiscovery> interfaces() {
            return discovery == null ? List.of() : discovery.perInterface();
        }

        void close() {
            if (discovery != null) {
                discovery.close();   // closes the pinger it owns, including the Windows same-object case
            } else if (pinger != null) {
                pinger.close();
            }
        }
    }

    private final ScheduledExecutorService scheduler;
    private final ExecutorService dispatcher;
    /** Guards the open/reopen/close transitions only; operations never take it. */
    private final ReentrantLock lifecycle = new ReentrantLock();

    private volatile Session session;
    private volatile boolean closed;

    private HostScanner(ScheduledExecutorService scheduler, ExecutorService dispatcher,
                        Session session) {
        this.scheduler = scheduler;
        this.dispatcher = dispatcher;
        this.session = session;
    }

    /**
     * Opens on zoxweb's process-wide pools — the normal entry point.
     * <p>
     * BORROWED EXECUTORS: {@link #close()} will not shut them down.
     */
    public static HostScanner open() {
        return open(TaskUtil.defaultTaskScheduler(), TaskUtil.defaultTaskProcessor());
    }

    /**
     * Opens on caller-supplied pools.
     *
     * @param scheduler  arms per-probe and per-solicitation timeouts; must be a
     *                   {@link ScheduledExecutorService}, since a plain executor
     *                   cannot arm a timeout
     * @param dispatcher runs user callbacks and hostname lookups, never a reader thread
     */
    public static HostScanner open(ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        Objects.requireNonNull(scheduler, "scheduler");
        Objects.requireNonNull(dispatcher, "dispatcher");
        return new HostScanner(scheduler, dispatcher, openSession(scheduler, dispatcher));
    }

    /**
     * Test seam: a scanner in a known mode, with no backend and no wire.
     * <p>
     * Runs on its own daemon pool rather than the zoxweb pools, so a test that
     * builds one does not start the process-wide non-daemon threads and leave the
     * surefire fork hanging.
     */
    static HostScanner offline(Mode mode, String diagnostic) {
        ScheduledExecutorService pool = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
                r -> {
                    Thread t = new Thread(r, "hostscanner-offline");
                    t.setDaemon(true);
                    return t;
                });
        return new HostScanner(pool, pool, new Session(mode, null, null, diagnostic));
    }

    /**
     * Tries full wiring, falls back to ICMP, and reports rather than throws.
     * <p>
     * The fallback is not a nicety: ICMP does not need layer 2 wherever the kernel
     * routes, so demanding the full wiring would make ping fail on a platform where
     * it works perfectly — a Mac where {@code /dev/bpf*} is root-only but ICMP is an
     * unprivileged {@code SOCK_DGRAM} socket.
     * <p>
     * <b>It cannot rescue an unprivileged Linux box</b>, and the diagnostic must not
     * imply otherwise. Linux ICMP is {@code SOCK_RAW}, so the second attempt fails on
     * the same {@code EPERM} as the first and the session is {@link Mode#UNAVAILABLE}.
     * The attempt is still made rather than skipped, because the failure is what puts
     * BOTH errnos in {@link #diagnostic()} — one saying layer 2 was refused and the
     * other saying ICMP was too, which is what tells an operator this is privilege
     * and not a missing NIC.
     */
    private static Session openSession(ScheduledExecutorService scheduler, ExecutorService dispatcher) {
        String layer2Failure;
        try {
            List<NetworkInterface> nics = HostDiscoveryFactory.usableInterfaces();
            if (nics.isEmpty()) {
                layer2Failure = "no usable interfaces (up, addressed, non-loopback)";
            } else {
                HostDiscoveryFactory.Discovery discovery =
                        HostDiscoveryFactory.open(nics, scheduler, dispatcher);
                return new Session(Mode.FULL, discovery, discovery.ping(),
                                   "layer 2 and ICMP over " + discovery.perInterface().size()
                                   + " interface(s)");
            }
        } catch (DiscoveryException | RuntimeException e) {
            layer2Failure = message(e);
        }
        try {
            ICMPPing pinger = HostDiscoveryFactory.openIcmpOnly(scheduler, dispatcher);
            return new Session(Mode.ICMP_ONLY, null, pinger,
                               "ICMP only - the layer-2 backend did not open: " + layer2Failure);
        } catch (DiscoveryException | RuntimeException e) {
            return new Session(Mode.UNAVAILABLE, null, null,
                               "no backend opened. Layer 2: " + layer2Failure
                               + ". ICMP: " + message(e));
        }
    }

    private static String message(Throwable t) {
        return t.getMessage() == null ? t.toString() : t.getMessage();
    }

    // ---------------------------------------------------------------- state

    /** What this session can do. Constant until {@link #reopen()}. */
    public Mode mode() {
        return session.mode();
    }

    /**
     * One line naming what opened and, when degraded, exactly what did not and why.
     * Show it in the UI: "ICMP only" without the reason is a support ticket.
     */
    public String diagnostic() {
        return closed ? "closed" : session.diagnostic();
    }

    public boolean isClosed() {
        return closed;
    }

    /**
     * The per-interface layer-2 backends, empty unless {@link Mode#FULL}.
     * <p>
     * BORROWED: these are closed by {@link #close()}. Do not close one yourself —
     * on Windows the pinger is one of these objects, so closing it kills ICMP for
     * the whole session.
     */
    public List<HostDiscovery> interfaces() {
        return session.interfaces();
    }

    /** The bound interfaces as plain values — the natural feed for a NIC picker. */
    public List<NicBinding> bindings() {
        return session.interfaces().stream().map(HostDiscovery::binding).toList();
    }

    /** The shared pinger, empty only when {@link Mode#UNAVAILABLE}. Borrowed, as above. */
    public Optional<ICMPPing> pinger() {
        return Optional.ofNullable(session.pinger());
    }

    /** The pinger's capabilities; per-interface capabilities live on {@link #interfaces()}. */
    public Optional<DiscoveryCapabilities> capabilities() {
        return pinger().map(ICMPPing::capabilities);
    }

    public Optional<HostDiscovery> interfaceNamed(String javaName) {
        return session.interfaces().stream()
                      .filter(h -> h.binding().javaName().equals(javaName))
                      .findFirst();
    }

    /** The first bound interface that has {@code target} on-link. */
    public Optional<HostDiscovery> interfaceFor(InetAddress target) {
        return session.interfaces().stream()
                      .filter(h -> h.binding().isOnLink(target))
                      .findFirst();
    }

    // ----------------------------------------------------------------- ping

    /** {@link #DEFAULT_PING_COUNT} probes at {@link #DEFAULT_PING_TIMEOUT}. */
    public CompletableFuture<PingResult> ping(String target) {
        return ping(target, DEFAULT_PING_COUNT, DEFAULT_PING_TIMEOUT);
    }

    /**
     * Pings a hostname or literal address. DNS runs on the dispatcher, so this
     * returns immediately even for a name that takes seconds to look up.
     *
     * @param count   echo requests, pipelined — wall time is one timeout, not count timeouts
     * @param timeout PER PROBE, not a deadline for the whole call
     */
    public CompletableFuture<PingResult> ping(String target, int count, Duration timeout) {
        return lookup(target).thenCompose(ip -> ping(ip, count, timeout));
    }

    /**
     * Pings a resolved address.
     * <p>
     * Completes normally with {@code received == 0} for a host that is simply down —
     * exceptionally only when this session has no pinger at all.
     */
    public CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout) {
        Objects.requireNonNull(target, "target");
        Session current = session;
        if (closed || current.pinger() == null) {
            return failed("Cannot ping: " + diagnostic());
        }
        try {
            return current.pinger().ping(target, count, timeout);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Pings several targets at once, results in argument order.
     * <p>
     * Every target is in flight simultaneously, so this costs one round of wall
     * time rather than N. The future completes when all of them have — a single
     * unresolvable hostname fails the whole batch, so look names up yourself if you
     * need partial results.
     */
    public CompletableFuture<List<PingResult>> pingAll(Collection<String> targets,
                                                       int count, Duration timeout) {
        return all(targets.stream().map(t -> ping(t, count, timeout)).toList());
    }

    // -------------------------------------------------------------- resolve

    public CompletableFuture<ResolveResult> resolve(String target) {
        return resolve(target, DEFAULT_RESOLVE_TIMEOUT);
    }

    /** ARP/NDP for a hostname or literal address; DNS runs on the dispatcher. */
    public CompletableFuture<ResolveResult> resolve(String target, Duration timeout) {
        return lookup(target).thenCompose(ip -> resolve(ip, timeout));
    }

    /**
     * ARP (IPv4) or NDP (IPv6) for a resolved address, through whichever bound
     * interface has it on-link.
     * <p>
     * Fails with a category error for an off-link target rather than a timeout:
     * ARP and NDP are link-local by definition, so there is no such thing as the
     * MAC of a host beyond the segment — what you would get is the router's.
     */
    public CompletableFuture<ResolveResult> resolve(InetAddress target, Duration timeout) {
        Objects.requireNonNull(target, "target");
        if (closed || !mode().canLayer2()) {
            return failed("Cannot resolve: " + diagnostic());
        }
        Optional<HostDiscovery> via = interfaceFor(target);
        if (via.isEmpty()) {
            return failed(target.getHostAddress() + " is not on any local subnet. ARP and NDP "
                          + "are link-local protocols by definition - there is no such thing as "
                          + "the MAC of a host beyond the local segment; what you would get is "
                          + "the router's.");
        }
        try {
            return via.get().resolve(target, timeout);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /** Resolves several targets concurrently, results in argument order. */
    public CompletableFuture<List<ResolveResult>> resolveAll(Collection<String> targets,
                                                             Duration timeout) {
        return all(targets.stream().map(t -> resolve(t, timeout)).toList());
    }

    // ---------------------------------------------------------------- sweep

    public CompletableFuture<SweepSummary> sweep(String cidr, SweepOptions options,
                                                 Consumer<HostRecord> onHost) {
        CidrRange range;
        try {
            range = CidrRange.parse(cidr);
        } catch (RuntimeException e) {
            return failed("Not a CIDR range: '" + cidr + "' (" + message(e) + ")");
        }
        return sweep(range, options, onHost);
    }

    /**
     * Sweeps a range through whichever bound interface has it on-link, falling back
     * to the first interface for an off-link range — where ARP cannot apply and the
     * result is whatever ICMP finds.
     * <p>
     * Records stream to {@code onHost} on a dispatcher thread as they arrive; the
     * future carries the totals. Concurrent sweeps are allowed and each is paced
     * separately, so N sweeps emit up to N times {@link SweepOptions#maxPacketsPerSecond()}.
     */
    public CompletableFuture<SweepSummary> sweep(CidrRange range, SweepOptions options,
                                                 Consumer<HostRecord> onHost) {
        Objects.requireNonNull(range, "range");
        if (closed || !mode().canLayer2()) {
            return failed("Cannot sweep: " + diagnostic());
        }
        HostDiscovery via = interfaceFor(range.networkAddress())
                .orElseGet(() -> session.interfaces().get(0));
        return sweepVia(via, range, options, onHost);
    }

    /** Sweeps through a named interface — for a UI that lets the operator pick the NIC. */
    public CompletableFuture<SweepSummary> sweepVia(String javaName, CidrRange range,
                                                    SweepOptions options,
                                                    Consumer<HostRecord> onHost) {
        if (closed || !mode().canLayer2()) {
            return failed("Cannot sweep: " + diagnostic());
        }
        Optional<HostDiscovery> via = interfaceNamed(javaName);
        if (via.isEmpty()) {
            return failed("No such bound interface: '" + javaName + "'. Bound: "
                          + bindings().stream().map(NicBinding::javaName).toList());
        }
        return sweepVia(via.get(), range, options, onHost);
    }

    private CompletableFuture<SweepSummary> sweepVia(HostDiscovery via, CidrRange range,
                                                     SweepOptions options,
                                                     Consumer<HostRecord> onHost) {
        try {
            return via.sweep(range, options, onHost);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Sweeps several ranges ONE AFTER ANOTHER, results in argument order.
     * <p>
     * Sequential on purpose: {@link SweepOptions#maxPacketsPerSecond()} bounds a
     * single sweep, so running ranges concurrently would multiply the rate on the
     * segment — which is the thing pacing exists to prevent.
     */
    public CompletableFuture<List<SweepSummary>> sweepAll(List<String> cidrs, SweepOptions options,
                                                          Consumer<HostRecord> onHost) {
        CompletableFuture<List<SweepSummary>> chain =
                CompletableFuture.completedFuture(new ArrayList<>());
        for (String cidr : cidrs) {
            chain = chain.thenCompose(acc -> sweep(cidr, options, onHost).thenApply(summary -> {
                acc.add(summary);
                return acc;
            }));
        }
        return chain.thenApply(List::copyOf);
    }

    /**
     * IPv6 neighbours on one bound segment, via all-nodes multicast echo plus
     * anything already learned passively. CIDR expansion is meaningless for a /64,
     * which is why this is a separate operation from {@link #sweep}.
     */
    public CompletableFuture<SweepSummary> discoverIpv6Segment(String javaName,
                                                               SweepOptions options,
                                                               Consumer<HostRecord> onHost) {
        if (closed || !mode().canLayer2()) {
            return failed("Cannot discover: " + diagnostic());
        }
        Optional<HostDiscovery> via = interfaceNamed(javaName);
        if (via.isEmpty()) {
            return failed("No such bound interface: '" + javaName + "'. Bound: "
                          + bindings().stream().map(NicBinding::javaName).toList());
        }
        try {
            return via.get().discoverIpv6Segment(options, onHost);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    // -------------------------------------------------------------- observe

    /**
     * Watches every bound interface for neighbours announcing themselves, and
     * returns one handle that unsubscribes from all of them.
     * <p>
     * Fires for broadcast ARP, gratuitous ARP and multicast NS/NA — not for unicast
     * replies between two third parties, which never reach this port without a
     * mirror. On a backend with no passive support this registers and never fires;
     * check {@link DiscoveryCapabilities#passiveObservation()} first.
     */
    public Subscription observe(Consumer<ObservedNeighbor> onNeighbor) {
        Objects.requireNonNull(onNeighbor, "onNeighbor");
        List<Subscription> subs = new ArrayList<>();
        for (HostDiscovery h : session.interfaces()) {
            subs.add(h.observe(onNeighbor));
        }
        return () -> {
            for (Subscription s : subs) {
                try {
                    s.close();
                } catch (RuntimeException ignored) {
                    // unsubscribing the rest matters more than this one failure
                }
            }
        };
    }

    // ------------------------------------------------------------ lifecycle

    /**
     * Tears the session down and opens a fresh one — after a NIC comes up, an
     * address changes, or Npcap is installed while the application is running.
     * <p>
     * BLOCKS and closes native handles; do not call it from a UI thread, and expect
     * every {@link #interfaces()} reference held across the call to be dead. Has no
     * effect once {@link #close()} has been called.
     */
    public void reopen() {
        lifecycle.lock();
        try {
            if (closed) {
                return;
            }
            Session old = session;
            session = openSession(scheduler, dispatcher);
            old.close();
        } finally {
            lifecycle.unlock();
        }
    }

    /**
     * Releases sockets, pcap handles and reader threads. Idempotent.
     * <p>
     * Leaves the scheduler and dispatcher running — they are shared with the rest
     * of the application.
     */
    @Override
    public void close() {
        lifecycle.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            session.close();
        } finally {
            lifecycle.unlock();
        }
    }

    // ---------------------------------------------------------------- plumbing

    /**
     * Hostname to address, off the calling thread. {@code getByName}, not
     * {@code ofLiteral}: a user-facing target field should accept a name, whereas
     * {@code ofLiteral} refuses DNS — which is right for CIDR parsing and anywhere
     * near the cache, and wrong here.
     */
    public CompletableFuture<InetAddress> lookup(String target) {
        Objects.requireNonNull(target, "target");
        return CompletableFuture.supplyAsync(() -> {
            try {
                return InetAddress.getByName(target);
            } catch (UnknownHostException e) {
                throw new CompletionException(
                        new DiscoveryException("Cannot resolve host '" + target + "'", e));
            }
        }, dispatcher);
    }

    private static <T> CompletableFuture<T> failed(String message) {
        return CompletableFuture.failedFuture(new DiscoveryException(message));
    }

    private static <T> CompletableFuture<List<T>> all(List<CompletableFuture<T>> futures) {
        return CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new))
                                .thenApply(ignored -> futures.stream()
                                                             .map(CompletableFuture::join)
                                                             .toList());
    }
}
