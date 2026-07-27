package io.xlogistx.nosneak.net.common;

import java.io.Closeable;
import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * ICMP and ICMPv6 echo. L3 liveness only.
 * <p>
 * NOT bound to a network interface. On Linux and macOS the kernel routes each
 * request and selects the source address, and a raw ICMP socket receives every
 * ICMP packet delivered to the host regardless of which wire it arrived on — so
 * a {@code binding()} accessor here would be a fiction, and there deliberately
 * is not one. One instance serves the whole JVM.
 * <p>
 * WINDOWS DIFFERS. pcap injects at L2 and bypasses routing, so the Windows
 * implementation is constructed over one or more {@link HostDiscovery} instances
 * and emulates on-link routing across them. There, the {@code ICMPPing} and the
 * {@code HostDiscovery} are the SAME OBJECT — one pcap handle, one device, one
 * reader thread.
 * <p>
 * Created via {@link HostDiscoveryFactory}. Thread-safe: concurrent
 * {@link #ping} calls share one socket pair and one sequence allocator.
 */
public interface ICMPPing extends Closeable {

    /** What this pinger can actually do. Constant after construction. */
    DiscoveryCapabilities capabilities();

    /**
     * Sends {@code count} echo requests and completes when every one has replied
     * or timed out.
     * <p>
     * Probes are PIPELINED: all {@code count} requests are emitted immediately
     * with distinct sequence numbers, so worst-case wall time is one
     * {@code timeout} rather than {@code count} of them. This is deliberately not
     * {@code ping(8)} pacing.
     * <p>
     * Never completes exceptionally for an unreachable host — that returns a
     * result with {@code received == 0}.
     * <p>
     * LINK-LOCAL IPv6 REQUIRES A SCOPE. {@code fe80::} targets cannot be routed
     * by the kernel without a scope id; it is taken from the
     * {@link java.net.Inet6Address} the caller passes. An unscoped link-local
     * target completes with {@link PingError#NETWORK_UNREACHABLE}.
     *
     * @param count   number of echo requests; must be at least 1
     * @param timeout PER-PROBE timeout, not a deadline for the whole call
     */
    CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout);

    /**
     * Releases sockets and reader threads. Pending futures complete NORMALLY with
     * {@link PingError#IO}, never exceptionally — completing exceptionally would
     * contradict the "never throws for an unreachable host" contract above.
     */
    @Override
    void close();
}
