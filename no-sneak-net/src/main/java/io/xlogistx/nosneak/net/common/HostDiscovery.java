package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.util.IpMacCache;

import java.io.Closeable;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * ARP/NDP resolution, passive observation, and sweep, over exactly ONE network
 * interface.
 * <p>
 * Unlike {@link ICMPPing}, the binding here is real: L2 frames carry an ifindex
 * and this interface's own MAC and IP, and nothing routes that for you.
 * <p>
 * Created via {@link HostDiscoveryFactory}. Thread-safe; backends serialize
 * native sends per source, and reads are serviced by dedicated reader threads.
 */
public interface HostDiscovery extends Closeable {

    /** The interface this instance is bound to. */
    NicBinding binding();

    /** What this backend can actually do on this interface. */
    DiscoveryCapabilities capabilities();

    /**
     * The pinger wired to this instance, if any. {@link #sweep} uses it to enrich
     * results with ICMP liveness; empty means sweep runs on ARP/NDP alone.
     * <p>
     * SET ONCE, BY THE FACTORY, BEFORE THIS OBJECT IS PUBLISHED. It is a deferred
     * constructor argument rather than mutable state, so
     * {@link #capabilities()} is stable by the time any caller holds a reference.
     * <p>
     * BORROWED, NOT OWNED: {@link #close()} must NOT close it. One pinger serves
     * every {@code HostDiscovery} in the JVM, so closing the eth0 instance would
     * otherwise kill ICMP for eth1 and eth2.
     */
    Optional<ICMPPing> icmpPing();

    /**
     * SPI — NOT for callers. {@link HostDiscoveryFactory} calls this exactly once,
     * during wiring, before this object is published to anyone.
     * <p>
     * The default is a no-op, which is correct for a backend that IS its own
     * pinger: on Windows the {@code HostDiscovery} and the {@link ICMPPing} are
     * the same object, so there is nothing to attach. Backends whose pinger is a
     * separate object override this with a set-once assignment.
     * <p>
     * Calling it after construction defeats the guarantee that
     * {@link #capabilities()} is stable for the lifetime of the object.
     */
    default void attachPinger(ICMPPing pinger) {
        // no-op: this backend is its own pinger
    }

    /**
     * Resolves a target IP to a MAC. Checks the cache first; on a miss performs an
     * active ARP (IPv4) or NDP (IPv6) solicitation with retransmission, updates
     * the cache, and completes with the resolved entry or empty on timeout.
     * <p>
     * A successful resolve is proof the host is alive, independently of ICMP.
     */
    CompletableFuture<ResolveResult> resolve(InetAddress target, Duration timeout);

    /**
     * Sweeps a CIDR block. Fans out {@link #resolve} across the range — and ping
     * through {@link #icmpPing()} WHEN ONE IS WIRED — with a bounded in-flight
     * window and a packet-rate cap. Results stream to {@code onHost} as they
     * arrive; the returned future completes when the whole range has been swept
     * or timed out.
     * <p>
     * For ON-LINK targets, ARP/NDP is the liveness oracle: a host that answers ARP
     * is alive whether or not it answers ICMP, and
     * {@link HostRecord#icmpAlive()} is a separate fact from "this host exists".
     * <p>
     * DEGRADES CLEANLY: with {@link #icmpPing()} empty, or
     * {@link SweepOptions#doIcmp()} false, every record carries
     * {@code icmpAlive == false} and an empty RTT, and the sweep still finds every
     * on-link host via ARP/NDP. Do not skip hosts and do not fail — the absence of
     * a pinger is a reduced result, not an error.
     * <p>
     * Rejects IPv6 ranges whose host count exceeds {@link SweepOptions#maxHosts()};
     * use {@link #discoverIpv6Segment} for v6 segments instead.
     * <p>
     * PACING IS PER-SWEEP. {@link SweepOptions#maxPacketsPerSecond()} bounds THIS
     * call; N concurrent sweeps through one shared pinger emit up to N times that
     * rate.
     */
    CompletableFuture<SweepSummary> sweep(CidrRange range,
                                          SweepOptions options,
                                          Consumer<HostRecord> onHost);

    /**
     * Discovers IPv6 neighbours on the bound segment by echoing to the all-nodes
     * link-local multicast address {@code ff02::1} and collecting responders, plus
     * any neighbours already learned passively.
     * <p>
     * This exists because CIDR expansion is meaningless for a /64. Some stacks —
     * notably Windows — do not answer multicast echo by default, so it
     * under-reports; combine it with {@link #observe} where available.
     * <p>
     * NEEDS THE PINGER FOR ITS ACTIVE HALF. The multicast echo goes out through
     * {@link #icmpPing()}; with none wired, this still returns cached and
     * passively-learned neighbours and never sends anything.
     * <p>
     * {@code ff02::1} IS LINK-LOCAL, SO IT MUST CARRY A SCOPE. An unbound pinger
     * cannot guess which segment "the all-nodes address" means — build the
     * destination as a scoped {@link java.net.Inet6Address} from
     * {@link NicBinding#ifIndex()} before handing it to ping. Passing a bare
     * {@code ff02::1} either fails outright or, worse, leaves via whichever
     * interface the kernel picks and reports another segment's hosts as this
     * binding's neighbours.
     */
    CompletableFuture<SweepSummary> discoverIpv6Segment(SweepOptions options,
                                                        Consumer<HostRecord> onHost);

    /**
     * Registers a passive observer.
     * <p>
     * SCOPE, precisely: on a switched network this fires for BROADCAST ARP
     * requests and gratuitous ARP, and for multicast NS/NA. It does NOT fire for
     * unicast ARP replies exchanged between two third parties — those frames never
     * reach this port absent a mirror or SPAN configuration. Seeing any
     * third-party traffic at all requires promiscuous mode.
     * <p>
     * On backends without passive support (macOS) registration succeeds but never
     * fires; check {@link DiscoveryCapabilities#passiveObservation()} first.
     *
     * @return a handle; close it to unsubscribe
     */
    Subscription observe(Consumer<ObservedNeighbor> onNeighbor);

    /**
     * The live IP-to-MAC cache for THIS binding. Each instance owns its own:
     * {@link java.net.Inet6Address#equals} compares the sixteen address bytes and
     * ignores the scope id, so {@code fe80::1%eth0} and {@code fe80::1%eth1} would
     * collide in a shared cache.
     */
    IpMacCache cache();

    /**
     * Releases sockets, handles and arenas, and completes pending futures NORMALLY
     * with an error result rather than exceptionally.
     * <p>
     * Does NOT close {@link #icmpPing()} — see that method. On Windows the pinger
     * and this object are the same instance, so close tears down both roles at
     * once and must be idempotent.
     */
    @Override
    void close();
}
