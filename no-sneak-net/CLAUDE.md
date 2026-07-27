# Host Discovery Subsystem — Implementation Spec **v2**

**Maven module:** `no-sneak-net`
**Root namespace:** `io.xlogistx.nosneak.net` — holds no types itself. Everything lives in a
named subpackage:

| Package | Contents | Exported |
|---|---|---|
| `…net.common` | the public API — both interfaces, every record, enum, and value type | yes |
| `…net.util` | `IpMacCache` — stateful, non-API helper types | yes |
| `…net.codecs` | shared codecs: ARP, ICMPv4/v6 echo, NS/NA, IPv6 header, checksums (§5) | yes |
| `…net.platform.linux` | libc via FFM (§6) | **no** |
| `…net.platform.darwin` | libc via FFM (§7) | **no** |
| `…net.platform.windows` | Npcap `wpcap.dll` + `iphlpapi` via FFM (§8) | **no** |
| `…net.tools` | `HostScan`, the CLI front end (§14) | yes |

Matches the house layout — `io-xlogistx` uses the same `common` convention. This spec was
originally written against `io.xlogistx.mgw.netdiscovery`; that name is superseded and must
not reappear in code, module descriptors, or launch flags.
**Runtime:** OpenJDK 25 (FFM stable API). Source targets JDK 25.
**Architectures:** 64-bit only — `x86-64` and `aarch64`/`arm64`. 32-bit is out of scope and unsupported by the platform (FFM has no 32-bit linker implementation; `Linker.nativeLinker()` throws `UnsupportedOperationException`, and the Windows x86-32 port was removed in JDK 24 / JEP 479).
**Deployment:** ARM aarch64 Ubuntu 20.04 appliance, **running as root** (primary). Dev/secondary: macOS (Intel + Apple Silicon), Windows 10/11 (x86-64 + arm64).
**Dependencies:** the house libraries only — `zoxweb-core` (for `TaskUtil`'s shared thread pools, §4.3), plus `xlogistx-common` and `xlogistx-core`. No networking or packet library of any kind: no Netty, no pcap4j, no Guava. Native access is FFM (`java.lang.foreign`) alone — Linux and macOS bind `libc`, Windows binds Npcap's `wpcap.dll`. Exact coordinates in §10.3.

> The original spec said *zero* third-party Java libraries. That was revised deliberately: starting private timer and dispatch pools per instance is worse than reusing the pools the rest of no-sneak already runs on. The rule is now **house libraries yes, everything else no** — the point of the constraint was never to avoid dependencies as such, it was that nothing outside the JDK gets to touch the wire.

This document is handed to Claude Code as the authoritative build spec. Sections marked **[IMPLEMENT]** are where code generation happens; sections marked **[REFERENCE]** are ABI/constant tables that must be reproduced exactly. Sections marked **[VERIFY]** contain layouts that must be confirmed by a native probe before code is written — do not generate from memory.

> **Changes from the v1 draft** are summarized in Appendix A. The backend split, the `ping` signature, the Linux privilege model, and several ABI details all changed.

---

## 1. Scope & non-goals

### In scope (v1)

- IPv4 host liveness via ICMP echo, with a caller-specified probe count.
- IPv6 host liveness via ICMPv6 echo.
- IPv4 → MAC resolution and active discovery via ARP.
- IPv6 → MAC resolution and active discovery via NDP (Neighbor Solicitation / Advertisement, RFC 4861).
- A thread-safe IP↔MAC cache with aging, provenance, and passive learning where the backend supports it.
- Subnet sweep (parallel L2 resolution + ICMP across a CIDR range), with **ARP/NDP as the liveness oracle for on-link targets** and ICMP as enrichment.
- IPv6 segment discovery via all-nodes multicast, as a distinct operation from CIDR sweep.
- **Two** public interfaces — `ICMPPing` (L3, host-scoped) and `HostDiscovery` (L2, per-interface) — with three platform implementations selected at runtime (§2.0).

### Explicit non-goals (v1)

- No TCP/UDP port scanning here — that belongs to the existing Tier-1 probe engine. This subsystem answers "is this host alive, what is its MAC, and how far away is it."
- No integration into the NIO `Selector`. These sockets are native FDs / pcap handles serviced by dedicated blocking reader threads (§4.4).
- **No `recvmsg`/cmsg in v1.** The `CMSG_FIRSTHDR`/`CMSG_NXTHDR`/`CMSG_DATA` accessors are preprocessor macros, not exported symbols, so FFM cannot bind them; using control messages means reimplementing control-buffer alignment arithmetic in Java, with layouts that differ between Linux and Darwin. The cost of skipping it is IPv6 hop limit and macOS IPv4 TTL — see §3.7 `ttlAvailable`.
- ~~**No off-link ICMP on Windows in v1.**~~ — **SUPERSEDED, off-link now works everywhere.** The `iphlpapi` binding this ruled out turned out to be one function (`GetBestRoute2`) and one struct field, so Windows now asks the OS for the next hop and sends to the gateway's MAC. Linux and macOS always routed through the kernel. See §8.7.
- No GraalVM/native-image support. Dynamic FFM binding is incompatible with closed-world AOT — a platform constraint, not a preference.

---

## 2. Architecture overview

**Two public interfaces, not one.** ICMP and L2 have different scopes and the API says so:

```
   ┌──────────────────────────┐          ┌────────────────────────────────┐
   │        ICMPPing          │◀────────▶│         HostDiscovery          │
   │  L3, HOST-scoped         │ optional │  L2, INTERFACE-scoped          │
   │  one per JVM             │ collab.  │  one per NIC                   │
   │  ping() only             │          │  resolve/sweep/observe/cache   │
   └────────────┬─────────────┘          └───────────────┬────────────────┘
                │                                        │
    ┌───────────┴───────────┐              ┌─────────────┴─────────────┐
    │ kernel routes; no NIC │              │ needs ifIndex, own MAC,   │
    │ needed (Linux, macOS) │              │ own IP — always per-NIC   │
    └───────────────────────┘              └───────────────────────────┘

        ┌────────────────────┬──────────────────────┬─────────────────────┐
        │  platform.linux    │   platform.darwin    │  platform.windows   │
┌───────▼────────────┐ ┌─────▼────────────────┐ ┌───▼──────────────────┐
│ LinuxNativeBackend │ │  MacOsNativeBackend  │ │  WindowsPcapBackend  │
│ libc via FFM, root │ │  libc via FFM        │ │  wpcap.dll via FFM   │
│ TWO objects        │ │  TWO objects         │ │  ONE object, BOTH    │
│                    │ │                      │ │  interfaces          │
│ • SOCK_RAW  ICMP   │ │ • SOCK_DGRAM ICMP    │ │ • pcap_open_live     │
│ • SOCK_RAW  ICMPv6 │ │ • SOCK_DGRAM ICMPv6  │ │ • pcap_sendpacket    │
│ • AF_PACKET ARP    │ │ • sysctl(PF_ROUTE)   │ │ • pcap_next_ex loop  │
│ • AF_PACKET NDP    │ │   neighbor table read│ │ • BPF filter         │
│ • AF_PACKET passive│ │ • NO passive observe │ │ • passive via promisc│
└───────┬────────────┘ └─────┬────────────────┘ └───┬──────────────────┘
        │                    │                      │
        └────────────────────┼──────────────────────┘
                             │
                ┌────────────▼────────────┐
                │       IpMacCache        │  pure Java, ONE PER BINDING
                │ ConcurrentHashMap based │  (not shared across NICs, §9.1)
                └─────────────────────────┘
```

Shared, platform-independent code (used by **all three** backends):

- Packet codecs: ARP frame, ICMPv4 echo, ICMPv6 echo, ICMPv6 NS/NA — build + parse.
- Internet checksum (RFC 1071) and ICMPv6 pseudo-header checksum.
- `IpMacCache`.
- All public API types.
- The in-flight correlation map and timeout scheduler (§4.2, §4.3).

Platform-specific code lives **only** inside the three `platform.*` packages, behind the two interfaces.

### 2.0 Why two interfaces

The single-interface v2 draft claimed every instance was "bound to exactly one network interface." That is true of ARP/NDP and false of ICMP, and the fiction cost real correctness:

- **ICMP on Linux/macOS is not interface-bound.** `sendto` on a raw or dgram ICMP socket consults the routing table — the kernel picks the egress NIC and the source address. Receive is worse: a raw ICMP socket gets a copy of **every** ICMP packet delivered to the host, whatever wire it arrived on. So `binding()` on a pinger would name eth0 while the packet left via eth1.
- **ARP/NDP genuinely is interface-bound.** `AF_PACKET` sends carry an `sll_ifindex`, and the frame needs that interface's own MAC and IPv4 as the ARP sender fields. Nothing routes this for you.
- **The resource profiles differ by an order of magnitude.** ICMP is two reader threads and two fds for the whole JVM. L2 is two reader threads and two fds *per NIC*. Fusing them made a 4-NIC appliance pay 16 threads instead of 6.

So: `ICMPPing` is host-scoped and has **no** `binding()`. `HostDiscovery` is per-NIC and keeps one. `HostDiscovery` optionally holds an `ICMPPing` (§3.8) and uses it to enrich `sweep()`; without one it sweeps on ARP/NDP alone, which is the liveness oracle anyway.

> **Windows is the exception and it is deliberate.** pcap injects at L2 and bypasses routing, so a Windows ping needs a device *and* the destination's MAC — meaning it needs ARP. There, `WindowsPcapBackend` implements **both** interfaces on one object, because it is physically one `pcap_t`, one device, and one `pcap_next_ex` reader. See §8.6.

### 2.1 Capability matrix

|                     | Linux (root)              | macOS                     | Windows (Npcap)           |
|---------------------|---------------------------|---------------------------|---------------------------|
| Binding             | libc (FFM)                | libc (FFM)                | `wpcap.dll` (FFM)         |
| Object model        | 2 objects (§2.0)          | 2 objects (§2.0)          | **1 object, 2 interfaces** (§8.6) |
| ICMPv4              | `SOCK_RAW`/`IPPROTO_ICMP` | `SOCK_DGRAM`/`IPPROTO_ICMP` | crafted over pcap       |
| ICMPv6              | `SOCK_RAW`/`IPPROTO_ICMPV6` | `SOCK_DGRAM`/`IPPROTO_ICMPV6` | crafted over pcap   |
| ARP                 | `AF_PACKET` + `SOCK_DGRAM`, crafted | kernel neighbor table via `sysctl` | crafted L2 frame |
| NDP                 | `AF_PACKET`, crafted NS   | kernel neighbor table via `sysctl` | crafted NS         |
| Passive observation | yes                       | **no**                    | yes (promisc)             |
| TTL available       | **yes** (IPv4 only)       | no                        | **yes**                   |
| Raw evidence        | yes                       | no                        | yes                       |
| Off-link ICMP       | yes (kernel routes)       | yes (kernel routes)       | yes (`GetBestRoute2`, §8.7) |
| Privilege           | root                      | none                      | Npcap install             |

`DiscoveryCapabilities` (§3.7) is the runtime expression of this table. On the appliance every row is `true`; macOS is honestly degraded and the API must say so rather than silently returning empty results.

### 2.2 Why the split is drawn three ways

- **Linux** runs as root on the appliance, so `SOCK_RAW` is unconditionally available. Raw IPv4 sockets deliver the full IP header on receive, which yields TTL and raw evidence with no extra binding surface — this is the platform where distance and fingerprinting evidence actually matter, so it gets the privileged path.
- **macOS** has no `AF_PACKET`. Active L2 there would mean BPF (`/dev/bpf*`), which is root-owned, exclusive-open, and `ioctl`-configured — variadic, hitting the Darwin arm64 `firstVariadicArg` hazard. Instead macOS reads the **kernel's own neighbor table** via `sysctl(3)`, which is non-variadic, unprivileged, and pure libc. Active resolution becomes indirect: provoke the kernel into resolving, then read the table (§7.4).
- **Windows** has no OS-level L2 injection and no equivalent unprivileged ICMP facility reachable without a second binding. Npcap is the only route, and it is the only external dependency in the whole subsystem.

Consequences of dropping macOS from the pcap backend: only **one** `pcap_pkthdr` layout is live (Windows LLP64), and the `sockaddr` family table reduces to two columns. The most dangerous part of the v1 draft largely disappears.

### 2.3 Architecture-independence

Every struct layout in this document is selected on **`os.name` only, never `os.arch`.** Both supported architectures are LP64 (LLP64 on Windows) with identical alignment for every type in play:

|                              | Linux x86-64 vs aarch64 | macOS x86-64 vs arm64 | Windows x86-64 vs arm64 |
|------------------------------|-------------------------|-----------------------|-------------------------|
| Constants                    | identical               | identical             | identical               |
| `sockaddr_in` / `sockaddr_in6` | identical (16 / 28)   | identical (16 / 28)   | identical (16 / 28)     |
| `sockaddr_ll`                | identical (20)          | n/a                   | n/a                     |
| `timeval`                    | identical (16)          | identical (16)        | identical (8)           |
| `pcap_pkthdr`                | n/a                     | n/a                   | identical (16)          |
| Variadic ABI hazard          | avoided (no ioctl/fcntl)| avoided (`sysctl` non-variadic) | n/a           |
| Arch-specific code           | **none**                | **none** (pending §7.3 probe) | **none**        |

`HostDiscoveryFactory.open()` fails fast on any `os.arch` outside `{amd64, x86_64, aarch64, arm64}` with a clear `DiscoveryException`, rather than letting an `UnsupportedOperationException` surface from the first downcall setup.

---

## 3. Public API  **[IMPLEMENT]**

All public types live in package `io.xlogistx.nosneak.net.common`. **One public top-level type per file** — the code blocks below group related types for readability only.

### 3.1 `ICMPPing` — L3 liveness, host-scoped

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.HostDiscoveryFactory;
import io.xlogistx.nosneak.net.common.PingResult;

import java.io.Closeable;
import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * ICMP/ICMPv6 echo. NOT bound to a network interface: on Linux and macOS the
 * kernel routes each request and selects the source address, and one instance
 * serves the whole JVM. There is deliberately no binding() accessor — see §2.0.
 *
 * Created via {@link HostDiscoveryFactory}. Thread-safe; concurrent ping()
 * calls share one socket pair and one sequence allocator (§4.2).
 *
 * WINDOWS DIFFERS. pcap injects at L2 and bypasses routing, so the Windows
 * implementation is constructed over one or more HostDiscovery instances and
 * emulates on-link routing across them (§8.6). It is the SAME OBJECT as the
 * HostDiscovery it was built from.
 */
public interface ICMPPing extends Closeable {

    /** What this pinger can actually do (see §3.7). Constant after construction. */
    DiscoveryCapabilities capabilities();

    /**
     * ICMP/ICMPv6 echo. Sends {@code count} probes and completes when every
     * probe has replied or timed out.
     *
     * Probes are PIPELINED: all {@code count} requests are emitted immediately
     * with distinct sequence numbers, so worst-case wall time is one
     * {@code timeout}, not {@code count} timeouts. This is deliberately not
     * ping(8) pacing semantics.
     *
     * Never completes exceptionally for an unreachable host — returns a result
     * with {@code received == 0}.
     *
     * LINK-LOCAL IPv6 REQUIRES A SCOPE. fe80:: targets cannot be routed by the
     * kernel without sin6_scope_id. Take it from the Inet6Address the caller
     * passed (Inet6Address.getScopeId() / getScopedInterface()); reject with
     * PingError.NETWORK_UNREACHABLE when the target is link-local and unscoped.
     *
     * @param count   number of echo requests; must be >= 1
     * @param timeout PER-PROBE timeout, not a deadline for the whole call
     */
    CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout);
}
```

> **Multi-homed caveat, must be in the javadoc.** A shared pinger routes by the kernel table while a `HostDiscovery` is pinned to an ifindex. On a multi-homed host you can sweep a range bound to eth0 while the ICMP leaves via eth1, and `HostRecord` then fuses an eth0 ARP result with an eth1 ICMP result as though they described one path. `icmpAlive` is therefore a **host-scoped** fact, not an interface-scoped one. On the single-homed appliance this cannot arise. Pinning ICMP per NIC would mean `SO_BINDTODEVICE` (`SOL_SOCKET`, 25) and one socket pair per NIC — not v1.

### 3.2 `HostDiscovery` — L2 identity, interface-scoped

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.*;

import java.io.Closeable;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * ARP/NDP resolution, passive observation, and sweep, over exactly ONE network
 * interface. L2 frames carry an ifindex and this interface's own MAC and IP, so
 * unlike ICMPPing the binding here is real.
 *
 * Implementations are created via {@link HostDiscoveryFactory}.
 *
 * Thread-safety: all methods are safe for concurrent use. Backends serialize
 * native sends per source (§4.4, §12.7); reads are serviced by dedicated
 * reader threads.
 */
public interface HostDiscovery extends Closeable {

    /** The interface this instance is bound to. */
    NicBinding binding();

    /** What this backend can actually do on this interface (see §3.7). */
    DiscoveryCapabilities capabilities();

    /**
     * The pinger wired to this instance, if any. Used by sweep() to enrich
     * results with ICMP liveness; empty means sweep() runs on ARP/NDP alone.
     *
     * SET ONCE, BY THE FACTORY, BEFORE THIS OBJECT IS PUBLISHED (§3.8). It is a
     * deferred constructor argument, not mutable state: capabilities() must be
     * stable by the time a caller holds the reference.
     *
     * BORROWED, NOT OWNED: close() must NOT close it. One pinger serves every
     * HostDiscovery in the JVM, so closing the eth0 instance would otherwise
     * kill ICMP for eth1 and eth2.
     */
    Optional<ICMPPing> icmpPing();

    /**
     * Resolve target IP to a MAC. Checks the cache first; on miss, performs an
     * active ARP (IPv4) or NDP (IPv6) solicitation with retransmission (§4.5),
     * updates the cache, and completes with the resolved entry or empty on
     * timeout.
     *
     * A successful resolve is proof the host is alive, independent of ICMP.
     */
    CompletableFuture<ResolveResult> resolve(InetAddress target, Duration timeout);

    /**
     * Sweep a CIDR block. Fans out resolve() across the range — and ping()
     * through icmpPing() WHEN ONE IS WIRED — with a bounded in-flight window
     * and a packet-rate cap. Results stream to onHost as they arrive; the
     * returned future completes when the whole range has been swept or timed
     * out.
     *
     * For ON-LINK targets, ARP/NDP is the liveness oracle: a host that answers
     * ARP is alive whether or not it answers ICMP. HostRecord.icmpAlive is a
     * separate fact from "this host exists".
     *
     * DEGRADES CLEANLY: with icmpPing() empty, or SweepOptions.doIcmp false,
     * every HostRecord carries icmpAlive == false and an empty rtt, and the
     * sweep still finds every on-link host via ARP/NDP. Do not skip hosts and
     * do not fail — absence of a pinger is a reduced result, not an error.
     *
     * Rejects IPv6 ranges whose host count exceeds SweepOptions.maxHosts;
     * use discoverIpv6Segment() for v6 segments instead.
     *
     * PACING IS PER-SWEEP. SweepOptions.maxPacketsPerSecond bounds THIS call.
     * N concurrent sweeps through one shared ICMPPing emit up to N times that
     * rate; enforce a global cap in the pinger if that matters on the segment.
     */
    CompletableFuture<SweepSummary> sweep(CidrRange range,
                                          SweepOptions options,
                                          Consumer<HostRecord> onHost);

    /**
     * Discover IPv6 neighbours on the bound segment by echoing to the all-nodes
     * link-local multicast address ff02::1 and collecting responders, plus any
     * neighbours already learned passively.
     *
     * This exists because CIDR expansion is meaningless for a /64. Note that
     * some stacks (notably Windows) do not answer multicast echo by default, so
     * this under-reports; combine with observe() where available.
     *
     * NEEDS THE PINGER FOR ITS ACTIVE HALF. The multicast echo goes out through
     * icmpPing(); with none wired, this method still returns cached and
     * passively-learned neighbours and never sends anything. It does not fail —
     * same degradation rule as sweep().
     *
     * ff02::1 IS LINK-LOCAL, SO IT MUST CARRY A SCOPE. An unbound pinger cannot
     * guess which segment "the all-nodes address" means. Build the destination
     * as a scoped Inet6Address from binding().ifIndex() (ff02::1%<ifIndex>)
     * before handing it to ping() — the pinger reads the scope off the address
     * (§3.1). Passing a bare ff02::1 is the bug this paragraph exists to
     * prevent: it either fails with NETWORK_UNREACHABLE or, worse, leaves via
     * whichever interface the kernel picks and reports another segment's hosts
     * as this binding's neighbours.
     */
    CompletableFuture<SweepSummary> discoverIpv6Segment(SweepOptions options,
                                                        Consumer<HostRecord> onHost);

    /**
     * Register a passive observer.
     *
     * SCOPE, precisely: on a switched network this fires for BROADCAST ARP
     * requests and gratuitous ARP, and for multicast NS/NA. It does NOT fire for
     * unicast ARP replies exchanged between two third parties — those frames
     * never reach this port absent a mirror/SPAN configuration. Seeing any
     * third-party traffic at all requires promiscuous mode (§6.6, §8.4).
     *
     * On backends without passive support (macOS), registration succeeds but
     * never fires; check capabilities().passiveObservation() first.
     *
     * Returns a handle; close it to unsubscribe.
     */
    Subscription observe(Consumer<ObservedNeighbor> onNeighbor);

    /**
     * The live IP↔MAC cache for THIS binding. Each HostDiscovery instance owns
     * its own cache — see §9.1 on link-local scope collisions.
     */
    IpMacCache cache();
}
```

### 3.3 Ping result types

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.PingError;
import io.xlogistx.nosneak.net.common.PingProbe;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Aggregate result of a ping() call.
 *
 * NOTE: contains an array-bearing component list. Records give reference
 * identity for arrays, so PingResult and PingProbe are NOT value-comparable.
 * Do not use them as map keys or in set membership tests.
 */
public record PingResult(
        InetAddress target,
        int sent,
        int received,
        List<PingProbe> probes,
        Duration minRtt,          // Duration.ZERO when received == 0
        Duration avgRtt,
        Duration maxRtt,
        Duration stdDevRtt,       // population stddev over replied probes
        Optional<PingError> error) {

    public PingResult {
        probes = List.copyOf(probes);
    }

    public boolean reachable() {
        return received > 0;
    }

    public double lossPercent() {
        return sent == 0 ? 0.0 : 100.0 * (sent - received) / sent;
    }

    /**
     * THE ONLY construction path. Computes every aggregate from the probe list.
     *
     * Probes flagged neighborResolutionPending are EXCLUDED from min/avg/max/
     * stdDev when probes.size() > 1, because their RTT includes the ARP/NDP
     * round trip and is not a measurement of the target (§4.6). They still
     * count toward sent/received.
     */
    public static PingResult of(InetAddress target, List<PingProbe> probes, PingError err) { ...}
}
```

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.PingError;

/**
 * One echo request/reply pair.
 *
 * Named PingProbe, not Probe: it belongs to the PingResult/PingError family, and
 * no-sneak-core already owns "probe" for the Tier-1 TCP/UDP service-identification
 * engine (ProbeDefinition, ProbeSession, ProbeResult). Different layer, same word —
 * do not reintroduce the bare name.
 */
public record PingProbe(
        int sequence,
        boolean replied,
        java.time.Duration rtt,          // null when !replied
        int ttlOrHopLimit,               // -1 when capabilities().ttlAvailable() is false
        byte[] rawReply,                 // empty when !replied or rawEvidence is false
        boolean neighborResolutionPending, // true if L2 resolution was in flight at send
        java.util.Optional<PingError> error) {
}
```

```java
package io.xlogistx.nosneak.net.common;

public enum PingError {
    TIMEOUT,
    HOST_UNREACHABLE,     // EHOSTUNREACH — kernel ARP/ND failed; strong "down on this segment"
    NETWORK_UNREACHABLE,  // ENETUNREACH — no route
    PERMISSION,           // EACCES / EPERM
    INTERFACE_DOWN,
    IO
}
```

> `HOST_UNREACHABLE` is categorically stronger evidence than `TIMEOUT` and must not be collapsed into it. It means the kernel exhausted its own neighbor solicitation retries.

### 3.4 Resolution and record types

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveSource;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;

/** Result of an ARP/NDP resolution. */
public record ResolveResult(
        InetAddress target,
        Optional<MacAddress> mac,
        ResolveOutcome outcome,
        ResolveSource source,    // meaningful only when outcome == RESOLVED
        Duration elapsed) {
}
```

```java
package io.xlogistx.nosneak.net.common;

/** WHERE a MAC came from. This is provenance and is what IpMacCache stores. */
public enum ResolveSource {
    ACTIVE_ARP,     // we sent an ARP request and got a reply
    ACTIVE_NDP,     // we sent an NS and got an NA
    PASSIVE,        // observed on the segment, unsolicited
    KERNEL_TABLE,   // read out of the OS neighbor table (macOS backend)
    CACHE_HIT,      // served from IpMacCache without touching the wire
    LOCAL_INTERFACE // the target IS one of the binding's own addresses (§13.12)
}
```

> `LOCAL_INTERFACE` exists because nothing on the segment answers an ARP request for our own address — the only host that owns it is the one asking — so without it `resolve(ownAddress)` burns the full timeout and reports `TIMEOUT` for a MAC held since construction. It is not a wire observation and must not be read as one.

```java
package io.xlogistx.nosneak.net.common;

/** WHAT HAPPENED. An outcome is not a source — keep these enums separate. */
public enum ResolveOutcome { RESOLVED, TIMEOUT, UNSUPPORTED, ERROR }
```

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ResolveSource;

/**
 * A discovered host (emitted by sweep, discoverIpv6Segment, and resolve).
 *
 * icmpAlive and mac.isPresent() are INDEPENDENT facts. A host that answers ARP
 * but not ICMP is alive and must be reported. Downstream consumers should treat
 * (mac.isPresent() || icmpAlive) as "host exists".
 */
public record HostRecord(
        java.net.InetAddress ip,
        java.util.Optional<MacAddress> mac,
        boolean icmpAlive,
        java.util.Optional<java.time.Duration> rtt,  // empty if not pinged or no reply
        int ttlOrHopLimit,                           // -1 if unavailable
        java.util.Optional<Integer> hopCount,        // derived, see §5.5
        ResolveSource macSource,
        java.time.Instant observedAt) {
}
```

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ObservationKind;

/** Passive observation of a neighbour on the segment. */
public record ObservedNeighbor(
        java.net.InetAddress ip,
        MacAddress mac,
        ObservationKind kind,
        java.time.Instant seenAt) {
}
```

```java
package io.xlogistx.nosneak.net.common;

public enum ObservationKind { ARP_REQUEST, ARP_REPLY, GRATUITOUS_ARP, NDP_NS, NDP_NA }
```

```java
package io.xlogistx.nosneak.net.common;

public record SweepSummary(
        int total,
        int alive,             // mac resolved OR icmp alive
        int macsResolved,
        int icmpAlive,
        java.time.Duration elapsed) {
}
```

### 3.5 Value types

```java
package io.xlogistx.nosneak.net.common;

import java.util.Arrays;
import java.util.HexFormat;

/** Immutable 48-bit MAC. */
public final class MacAddress {
    private final byte[] bytes; // length 6, defensively copied

    public MacAddress(byte[] b) {
        if (b == null || b.length != 6) throw new IllegalArgumentException("MAC must be 6 bytes");
        this.bytes = b.clone();
    }
    /** Accept aa:bb:cc:dd:ee:ff, aa-bb-..., and aabb.ccdd.eeff. */
    public static MacAddress parse(String s) { ... }
    public byte[] bytes() { return bytes.clone(); }
    public boolean isBroadcast() { /* all 0xFF */ }
    public boolean isMulticast() { return (bytes[0] & 0x01) != 0; }
    public boolean isZero()      { /* all 0x00 */ }
    @Override public boolean equals(Object o) { /* Arrays.equals on bytes */ }
    @Override public int hashCode() { return Arrays.hashCode(bytes); }
    @Override public String toString() { return HexFormat.ofDelimiter(":").formatHex(bytes); }
}
```

```java
package io.xlogistx.nosneak.net.common;

import java.math.BigInteger;
import java.net.InetAddress;

/** A CIDR block with a lazy iterator over host addresses (v4 and v6). */
public final class CidrRange {
    public static CidrRange parse(String cidr) { ... }   // "192.168.1.0/24", "fe80::/64"
    public InetAddress networkAddress() { ... }
    public int  prefixLength() { ... }
    public boolean isIpv6() { ... }

    /**
     * BigInteger, not long: a /64 has 2^64 hosts, which overflows a signed long.
     * Callers must compare against SweepOptions.maxHosts before expanding.
     */
    public BigInteger hostCount() { ... }

    public java.util.stream.Stream<InetAddress> hosts() { ... } // lazy
}
```

```java
package io.xlogistx.nosneak.net.common;

public record SweepOptions(
        int maxInFlight,                    // bounded concurrency window, e.g. 256
        int maxPacketsPerSecond,            // hard pacing cap; 0 = unlimited
        java.time.Duration perHostTimeout,
        boolean doIcmp,
        boolean doMac,
        int pingCount,                      // probes per host; default 1
        long maxHosts) {                    // hard cap; refuses absurd v6 ranges

    public static SweepOptions defaults() {
        return new SweepOptions(256, 2000, java.time.Duration.ofMillis(1000),
                                true, true, 1, 65536);
    }
}
```

> `maxPacketsPerSecond` is not optional polish. Sweeping a /16 unpaced from an appliance will churn switch CAM tables and trip customer IDS. `pingCount` defaults to **1** — with ARP as the liveness oracle, multi-probe is not needed to defend against the cold-neighbour drop, and it would multiply sweep wall time.

### 3.6 NIC binding

```java
package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.common.MacAddress;

import java.net.InetAddress;
import java.util.List;

/**
 * Local addressing for the bound interface. ALL of this comes from
 * java.net.NetworkInterface — no native getifaddrs/ioctl. This is the single
 * biggest simplifier: it eliminates the fiddliest native pointer-walking.
 */
public record NicBinding(
        String javaName,          // NetworkInterface.getName(), e.g. "eth0" / "en0"
        String backendDeviceName, // pcap device name on Windows; == javaName elsewhere
        int ifIndex,              // NetworkInterface.getIndex()
        MacAddress hardwareAddress, // NULLABLE — see below
        List<LocalAddress> ipv4,
        List<LocalAddress> ipv6,  // include link-local for NDP
        int mtu) {

    public NicBinding {
        ipv4 = List.copyOf(ipv4);
        ipv6 = List.copyOf(ipv6);
    }

    /**
     * An address PLUS its prefix length. The prefix is not decoration: it is
     * the only way to answer "is this target on-link for this interface", which
     * the Windows pinger needs before it can pick a NIC to inject through
     * (§8.6), and which sweep() needs to know whether ARP is even applicable.
     *
     * NetworkInterface.getInterfaceAddresses() -> InterfaceAddress carries both;
     * getInetAddresses() drops the prefix, so do not use it.
     */
    public record LocalAddress(InetAddress address, int prefixLength) {

        /** True when target falls inside this address's subnet. */
        public boolean onLink(InetAddress target) { ...}
    }

    /** First binding-local address in the same family as target, or empty. */
    public java.util.Optional<LocalAddress> sourceFor(InetAddress target) { ...}

    /** True when any local address of the matching family has target on-link. */
    public boolean isOnLink(InetAddress target) { ...}

    /**
     * Build from a java.net.NetworkInterface plus a backend device-name resolver.
     *
     * IMPORTANT: nif.getHardwareAddress() returns null for loopback and some
     * virtual interfaces. Do NOT feed null into the MacAddress constructor — it
     * throws. Leave hardwareAddress null and let the factory reject the binding
     * for L2 operations.
     */
    public static NicBinding from(java.net.NetworkInterface nif,
                                  java.util.function.Function<java.net.NetworkInterface, String> deviceNameResolver) {
        ...
    }
}
```

> **`onLink` is a subnet test, not a routing table.** Compare `prefixLength` bits of the address bytes and stop. Do not attempt metrics, default routes, or longest-prefix arbitration across interfaces — that is a bad reimplementation of the OS routing stack, and on Linux/macOS the kernel already does it properly. This method exists for the one platform that has no routing available (§8.6) and for deciding whether ARP applies.

### 3.7 Capabilities

```java
package io.xlogistx.nosneak.net.common;

/**
 * What the running backend can actually do. Returned by BOTH interfaces: on an
 * ICMPPing only the icmp/ttl/offLink/rawEvidence rows are meaningful; on a
 * HostDiscovery the arp/ndp/passive rows are, and the icmp rows report whether
 * a pinger is wired in (§3.2).
 *
 * Constant for the lifetime of the object — the factory finishes all wiring
 * before publishing, so this never changes under a caller.
 */
public record DiscoveryCapabilities(
        boolean icmpV4,
        boolean icmpV6,
        boolean activeArp,
        boolean activeNdp,
        boolean passiveObservation,   // Linux: yes. Windows: yes (promisc). macOS: NO.
        boolean rawEvidence,          // full received packet bytes available
        boolean ttlAvailable,         // Linux IPv4 + Windows: yes. Otherwise NO.
        boolean offLinkIcmp,          // Windows v1: false. Linux/macOS: true.
        Backend backend) {

    public enum Backend { LINUX_NATIVE, MACOS_NATIVE, WINDOWS_PCAP }
}
```

> `ttlAvailable` exists so the fingerprinting layer can distinguish "this host is far away" from "this backend cannot tell you." A `-1` TTL must never be interpreted as a distance.

### 3.8 Factory, subscription, exception

Three separate files. **The factory is the only place that knows how the two interfaces are wired together**, and it is what makes the set-once collaborator safe.

```java
package io.xlogistx.nosneak.net.common;

import java.net.NetworkInterface;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.ICMPPing;
import org.zoxweb.server.task.TaskUtil;   // the module's ONLY third-party import

public final class HostDiscoveryFactory {

    /**
     * Open one L2 backend per interface, plus a pinger, fully wired.
     *
     * WIRING ORDER — this is the whole reason the factory exists:
     *   1. open a HostDiscovery per NetworkInterface
     *   2. construct the ICMPPing
     *        Linux/macOS: standalone, no interfaces needed
     *        Windows:     over the list from step 1 (§8.6); the returned
     *                     ICMPPing IS one of those objects, not a new one
     *   3. set-once inject the pinger into each HostDiscovery
     *   4. only now return — nothing was published mid-wiring, so no caller can
     *      observe a half-built object or a capabilities() that later changes
     *
     * Selects the backend by os.name. Fails fast if os.arch is outside
     * {amd64, x86_64, aarch64, arm64}.
     */
    public static Discovery open(List<NetworkInterface> nics,
                                 ScheduledExecutorService scheduler,
                                 ExecutorService dispatcher) throws DiscoveryException { ...}

    /**
     * Same, on the process-wide zoxweb pools (§4.3). This is the normal call.
     *
     * Equivalent to open(nics, TaskUtil.defaultTaskScheduler(),
     *                          TaskUtil.defaultTaskProcessor()).
     * NOTE the scheduler is defaultTaskScheduler(), NOT defaultTaskProcessor() —
     * the latter is a plain ExecutorService and cannot arm a timeout.
     *
     * Executors passed this way are BORROWED: close() will not shut them down.
     */
    public static Discovery open(List<NetworkInterface> nics) throws DiscoveryException { ...}

    /** Single-interface convenience. Same wiring, one NIC. */
    public static Discovery open(NetworkInterface nif) throws DiscoveryException { ...}

    /** Convenience: pick the interface owning a given local address. */
    public static Discovery openForLocalAddress(java.net.InetAddress local)
            throws DiscoveryException { ...}

    /**
     * ICMP only — no interface, no ARP/NDP, no cache. Two reader threads for the
     * whole JVM (§2.0).
     *
     * UNSUPPORTED ON WINDOWS: pcap cannot ping without a device and a resolved
     * destination MAC. Throws DiscoveryException there naming the reason; use
     * open(List) instead.
     */
    public static ICMPPing openIcmpOnly(ScheduledExecutorService scheduler,
                                        ExecutorService dispatcher) throws DiscoveryException { ...}

    /** Same, on the process-wide zoxweb pools. */
    public static ICMPPing openIcmpOnly() throws DiscoveryException { ...}

    /**
     * What open() hands back: the per-NIC backends and the shared pinger.
     *
     * close() closes the pinger AND every HostDiscovery, in that order. This is
     * the ONLY owner of the pinger — HostDiscovery.close() must not close it
     * (§3.2).
     *
     * It does NOT close the scheduler or the dispatcher. Those are borrowed —
     * by default they are zoxweb's process-wide pools, shared with the rest of
     * no-sneak, and shutting them down here would stop task processing for the
     * whole application (§4.3).
     */
    public record Discovery(List<HostDiscovery> perInterface, ICMPPing ping)
            implements java.io.Closeable {
        public HostDiscovery forName(String javaName) { ...}

        @Override
        public void close() { ...}
    }
}
```

> **Why `open()` returns a bundle rather than a bare `HostDiscovery`.** The pinger is shared across every NIC, so somebody has to own its lifetime, and it cannot be any one of the per-NIC backends — closing eth0 would kill ICMP for eth1. `Discovery` is that owner. It also gives the Windows path somewhere to express that `perInterface.get(0)` and `ping` may be **the same object**.

```java
package io.xlogistx.nosneak.net.common;

public interface Subscription extends java.io.Closeable {
    @Override void close();   // narrowed: does not throw IOException
}
```

```java
package io.xlogistx.nosneak.net.common;

public final class DiscoveryException extends Exception {
    public DiscoveryException(String msg) { super(msg); }
    public DiscoveryException(String msg, Throwable cause) { super(msg, cause); }
}
```

---

## 4. Backend contract (all three implementations)

### 4.1 Lifecycle

- A `HostDiscovery` binds one interface and starts its reader threads. An `ICMPPing` binds no interface (except on Windows, §8.6) and starts its own. Either may fail with `DiscoveryException` (missing privilege, pcap not loadable, interface down, no hardware address for an L2 request).
- `close()` signals reader threads, closes native FDs / pcap handles, closes arenas, and **completes pending futures normally** with a result carrying `PingError.IO` / `ResolveOutcome.ERROR`. Do not complete exceptionally — that contradicts the "never throws for an unreachable host" contract in §3.1.
- **`HostDiscovery.close()` must NOT close its `icmpPing()`.** The pinger is borrowed and shared across every NIC; closing it from one backend would kill ICMP for all the others. Only `Discovery.close()` (§3.8) owns it. On Windows the two are the same object, so `close()` there tears down both roles at once and must be idempotent.
- **Arenas:** use `Arena.ofShared()` for instance-lifetime native allocations. `Arena.ofConfined()` is single-thread-owned; reader threads touching segments allocated by the constructor thread would throw `WrongThreadException`. Per-send confined arenas are fine, because a send allocates, fills, and closes its arena on the one thread performing that send — the segment never crosses a thread boundary, whatever §12.7 settles on for send serialization.

### 4.2 Correlation of replies to requests

Both send and receive happen on different threads, so requests and replies must be correlated through a shared `ConcurrentHashMap<CorrelationKey, PendingRequest>`.

| Path | Correlation key | Notes |
|------|-----------------|-------|
| ICMPv4 echo, Linux `SOCK_RAW` | `(identifier, sequence)` | **We own the identifier and the checksum.** Raw sockets receive a copy of *every* ICMP packet delivered to the host, so filtering on our identifier is mandatory, not optional. |
| ICMPv6 echo, Linux `SOCK_RAW` | `(identifier, sequence)` | We own the identifier; the **kernel computes the ICMPv6 checksum** (mandatory per RFC 3542). Asymmetric with IPv4 — do not compute it twice. |
| ICMPv4/v6 echo, macOS `SOCK_DGRAM` | `sequence` only | The kernel **overwrites the identifier** with the socket's assigned value. Read it back from the reply; match on sequence. |
| ICMPv4/v6 echo, Windows pcap | `(identifier, sequence)` | Full control; we compute every checksum. |
| ARP | reply's sender protocol address == the target we asked for | A gratuitous ARP can falsely satisfy a pending resolve. Acceptable; note it. |
| NDP NA | target address in the advertisement | Prefer NAs with the Solicited flag set when several match. |

**Sequence allocation:** one `AtomicInteger` **per socket**, masked to 16 bits, shared across all concurrent `ping()` calls on that socket. Not a per-call counter starting at zero — with `count > 1` and concurrent callers, per-call counters collide immediately. Wraparound is only reachable beyond 65536 outstanding probes, which `maxInFlight` already bounds.

**Identifier allocation — must be unique per socket across the whole JVM.** A raw ICMP socket receives every ICMP packet delivered to the host, so the identifier is the *only* thing separating our replies from another socket's. Two sockets that derive the identifier the same way — from the PID, from a constant, from a per-instance counter starting at zero — will match each other's replies and complete the wrong probe. Allocate from **one process-wide `AtomicInteger`**, masked to 16 bits, and hand each socket a distinct value at construction.

> This is not hypothetical once §8.6 exists: the Windows pinger sends through N per-NIC handles, and a bare `openIcmpOnly()` pinger can coexist with a `Discovery` bundle in the same JVM. Both would otherwise start at the same identifier.

A `ping(target, count, timeout)` call registers **`count`** in-flight entries and **`count`** scheduled timeouts, not one.

### 4.3 Timeouts

A `ScheduledExecutorService` arms per-probe timeouts. On fire: remove the in-flight entry, record the probe as `replied=false, error=TIMEOUT`, and complete the aggregate future once all probes for that call have settled.

**This module does NOT create thread pools. Both executors are constructor parameters**, supplied by the factory (§3.8), defaulting to zoxweb's process-wide pools:

| Role | Type | Default | Used for |
|------|------|---------|----------|
| scheduler | `ScheduledExecutorService` | `TaskUtil.defaultTaskScheduler()` | per-probe and per-solicitation timeouts (§4.5) |
| dispatcher | `ExecutorService` | `TaskUtil.defaultTaskProcessor()` | user `Consumer` callbacks |

> **Mind which is which.** `TaskUtil.defaultTaskProcessor()` returns a `TaskProcessor`, which implements **`ExecutorService`** — it cannot schedule delayed work and will not compile where a `ScheduledExecutorService` is required. The scheduled one is `TaskUtil.defaultTaskScheduler()`, returning `TaskSchedulerProcessor implements ScheduledExecutorService`. It is *constructed over* `defaultTaskProcessor()`, so both roles share one underlying pool — which is the point: an N-NIC appliance adds zero threads for timers or callbacks.

**These pools are BORROWED. Never close them.** `TaskProcessor` and `TaskSchedulerProcessor` are `DaemonController`s and process-wide singletons shared with the rest of no-sneak; calling `close()` or `TaskUtil.close()` from this module would shut down task processing for the whole application. Same rule as the pinger (§4.1): `Discovery.close()` releases sockets, handles and arenas, and lets the executors alone. A caller who passes its *own* executors owns them and closes them itself.

**Never block a reader thread on a user callback.** Dispatch `Consumer<HostRecord>` and `Consumer<ObservedNeighbor>` callbacks through the dispatcher — a slow consumer must never stall packet reception. This matters most on Windows, where one reader thread serves **both** roles of the single backend object (§8.6): a blocked callback there stalls ARP, NDP and ICMP at once.

> Because the pools are shared with the whole application, a sweep with a large `maxInFlight` competes with everything else running on them. If sweep latency ever needs isolating from the rest of no-sneak, pass dedicated executors at the factory rather than reintroducing private pools here.

### 4.4 Threading model (replaces the NIO selector for this subsystem)

- One **reader thread per receive source**, and the split in §2.0 decides who owns each:
    - Linux `ICMPPing` — one per raw ICMP socket, one per raw ICMPv6 socket. **Two threads for the whole JVM**, not per NIC.
    - Linux `HostDiscovery` — one per `AF_PACKET` socket, so two per NIC (`ETH_P_ARP`, `ETH_P_IPV6`).
    - macOS `ICMPPing` — one per dgram ICMP socket, one per dgram ICMPv6 socket, JVM-wide.
    - macOS `HostDiscovery` — no blocking reader; a scheduled neighbor-table poller per NIC.
    - Windows — one thread per NIC running `pcap_next_ex`, demultiplexing by ethertype and serving **both** roles of the single object (§8.6).

  So an N-interface Linux appliance costs `2 + 2N` reader threads, not `4N`. That arithmetic is the practical payoff of the split.
- Reader threads are **blocking**. Do not wire these FDs into `java.nio.channels.Selector` — arbitrary native FDs cannot be registered, and pcap handles are not portably selectable. This is the deliberate transport divergence from the TCP probe engine: per-target FSMs are driven off the reader-thread dispatch queue, not off selector readiness.
- **Reader threads are DEDICATED PLATFORM THREADS. Never take them from the §4.3 executor pools.** A reader is an infinite blocking loop, so submitting one does not *use* a pool thread, it *permanently consumes* one. `TaskUtil` sizes its pool at `max(availableProcessors * 4, 16)`, so a 4-core appliance has 16 threads; a 4-NIC box needs `2 + 2N` = 10 readers, which would hold 10 of them forever, and adding a writer thread per source would need 20 in a 16-thread pool — at which point no timeout ever fires and no callback ever dispatches, for no-sneak **and** for every other component sharing that process-wide singleton. The pools take short bursty work (fire a timeout, run one callback); reader and writer loops are not that.
- **Virtual threads do not help here.** An FFM downcall pins its carrier for the duration of the call, and `recvfrom` blocks *inside* the native call — so a virtual reader pins a carrier for the whole wait, costing what a platform thread costs with extra indirection.
- Sends must not interleave on a given native source — one `sendto` / `pcap_sendpacket` in flight per fd or pcap handle, since two threads filling a shared native buffer produce a corrupt frame. **Do not reach for a `ReentrantLock` to get this.** The mechanism is an open decision (§12.7) and is deliberately unspecified for now; until it is settled, keep every send funnelled through **one** private method per source that owns its own buffer, so serialization can be imposed at that single choke point instead of being sprinkled through the backends.

**Shutdown — this is not optional.** Closing a file descriptor does **not** wake a thread blocked in `recvfrom` on Linux or macOS, and the fd number can be reused underneath the blocked thread. Since §6.1 forbids binding `fcntl`, there is no non-blocking escape. Every blocking reader loop must therefore:

1. Set `SO_RCVTIMEO` to ~200 ms at socket creation.
2. Loop on `recvfrom`, treating `EAGAIN`/`EWOULDBLOCK` as a normal tick.
3. Re-check a `volatile boolean running` on every tick.

For the Windows pcap loop, pass a positive `to_ms` to `pcap_open_live` (never 0, which means wait forever) and treat a `pcap_next_ex` return of 0 as the same tick.

`struct timeval` for `SO_RCVTIMEO`:

```java
// Linux (x86-64 and aarch64) — 16 bytes.
MemoryLayout.structLayout(JAVA_LONG.withName("tv_sec"), JAVA_LONG.withName("tv_usec"));

// macOS (x86-64 and arm64) — 16 bytes. tv_usec is 32-bit, padded.
MemoryLayout.structLayout(JAVA_LONG.withName("tv_sec"),
                          JAVA_INT.withName("tv_usec"),
                          MemoryLayout.paddingLayout(4));
```

| Constant     | Linux | macOS    |
|--------------|-------|----------|
| `SOL_SOCKET` | 1     | `0xFFFF` |
| `SO_RCVTIMEO`| 20    | `0x1006` |

### 4.5 Retransmission

A single solicitation with a single timeout produces false negatives on a busy segment. Both active L2 paths retransmit:

- **ARP:** up to 3 attempts, 1 s apart, first reply wins.
- **NDP:** RFC 4861 `RETRANS_TIMER` = 1000 ms, `MAX_MULTICAST_SOLICIT` = 3.

`resolve()`'s `timeout` parameter bounds the whole retry sequence, not each attempt. If `timeout` is shorter than one retransmission interval, send once and honour the caller's bound.

### 4.6 Cold-neighbour first-probe loss

**This is ARP, not DNS.** `ping()` takes an already-resolved `InetAddress`, so DNS is not in the path at all.

When the kernel has no neighbor entry for the destination, it queues the outgoing packet and emits an ARP request first. Linux holds only a small number of packets per unresolved neighbor (`unres_qlen_bytes`, historically one), so the first probe is dropped while resolution completes; the second finds a resolved entry and succeeds. Darwin behaves the same way. For off-link targets it is the gateway's entry that is cold, or a `STALE` entry being revalidated.

Two consequences the implementation must handle:

1. **Sending ARP over `AF_PACKET` does not prime the kernel cache.** Our ARP bypasses the kernel neighbor table entirely, and the reply arrives at our reader thread; Linux will not create an entry from a reply it did not solicit (`arp_accept=0` by default). So ordering `doMac` before `doIcmp` in a sweep does *not* fix the drop. This is exactly why ARP is the liveness oracle rather than a warm-up step. On macOS the opposite holds — the sysctl path reads the kernel's own table, so anything resolved there is already primed.
2. **Probe 0's RTT is inflated even when it succeeds**, having queued behind the ARP round trip. Set `PingProbe.neighborResolutionPending` when the backend knows resolution was in flight at send time, and exclude those probes from `min/avg/max/stdDev` when `count > 1` (§3.3).

**Who can actually set that flag differs per platform, and on the appliance the answer is "nobody".** The flag is best-effort, and a `false` means "not known to be pending", never "known not to be pending":

| Platform | Can it know? | Why |
|----------|--------------|-----|
| Linux | **no** | The kernel owns the neighbor table and resolves on its own; the pinger never sees it, and this module deliberately does not read `/proc/net/arp` or `AF_NETLINK`. Our own `AF_PACKET` ARP is a separate conversation the kernel ignores (point 1 above). Expect the flag to be permanently `false`. |
| macOS | **yes** | §7.3 reads the kernel's own table via `sysctl`, so a miss immediately before the send is exactly this condition. |
| Windows | **yes** | The backend does its own ARP and owns the `IpMacCache`, so it knows precisely whether the destination MAC was cached or had to be solicited (§8.6). |

> Do not fake it on Linux by consulting `IpMacCache` — that cache reflects **our** ARP, not the kernel's neighbor table, and the two are independent. A false positive here silently drops a valid probe from the RTT statistics.

> **NARROWED, 2026-07-27.** "Linux does not read the kernel neighbor table" is a rule about **this flag**, and it still holds: `neighborResolutionPending` is always `false` on Linux and must not be inferred. It is *not* a blanket ban on ever reading `/proc/net/arp`. `platform.linux.KernelNeighbors` now reads it for one purpose — a destination MAC to aim a unicast ARP request at when broadcast has failed (§13.12). That is a hint, never an answer: resolution still requires a reply on our own `AF_PACKET` socket, the reported `ResolveSource` stays `ACTIVE_ARP`, and a stale hint costs one wasted frame rather than a wrong result. The distinction that matters is **evidence versus aim**: the flag would have been reported as fact, the hint only decides where to send a probe whose answer we still verify ourselves.

### 4.7 errno mapping

Capture `errno` with `Linker.Option.captureCallState("errno")` and read it on every `-1` return. Minimum mapping on `sendto`:

| errno | `PingError` |
|-------|-------------|
| `EHOSTUNREACH` | `HOST_UNREACHABLE` |
| `ENETUNREACH`  | `NETWORK_UNREACHABLE` |
| `EACCES`, `EPERM` | `PERMISSION` |
| `ENETDOWN`, `ENXIO` | `INTERFACE_DOWN` |
| anything else | `IO` |

---

## 5. Shared packet codecs  **[IMPLEMENT]**

Package `io.xlogistx.nosneak.net.codecs`. Pure Java, no FFM. Operates on `byte[]` / `ByteBuffer`. Big-endian (network order) throughout.

### 5.1 Internet checksum (RFC 1071)

```java
public final class InternetChecksum {
    /**
     * One's-complement sum over 16-bit words, then complemented.
     * The RETURN VALUE is the finished checksum — write it into the packet
     * verbatim in network order. Do not complement it again.
     *
     * PRECONDITION: the checksum field in the input must already be zeroed.
     */
    public static int checksum(byte[] data, int off, int len) { ... }

    /** ICMPv6 checksum requires an IPv6 pseudo-header. */
    public static int icmpv6Checksum(byte[] srcAddr16, byte[] dstAddr16,
                                     byte[] icmpv6, int off, int len) { ... }
    // pseudo-header = src(16) + dst(16) + upperLayerLen(4, BE) + zeros(3) + nextHeader(1 = 58)
}
```

### 5.2 ARP  **[REFERENCE + IMPLEMENT]**

Fixed **28 bytes** (payload only; the Ethernet header is prepended by the kernel on `AF_PACKET`/`SOCK_DGRAM`, and hand-built on the Windows pcap path).

| Offset | Size | Field | Value (request) |
|-------:|-----:|-------|-----------------|
| 0 | 2 | Hardware type (HTYPE) | `0x0001` (Ethernet) |
| 2 | 2 | Protocol type (PTYPE) | `0x0800` (IPv4) |
| 4 | 1 | Hardware addr len (HLEN) | `6` |
| 5 | 1 | Protocol addr len (PLEN) | `4` |
| 6 | 2 | Operation (OPER) | `1` request / `2` reply |
| 8 | 6 | Sender hardware addr (SHA) | our MAC |
| 14 | 4 | Sender protocol addr (SPA) | our IPv4 |
| 18 | 6 | Target hardware addr (THA) | `00:00:00:00:00:00` for request |
| 24 | 4 | Target protocol addr (TPA) | target IPv4 |

```java
public final class ArpPacket {
    public static byte[] request(MacAddress senderMac, byte[] senderIpv4, byte[] targetIpv4) { ... }
    public static java.util.Optional<ArpView> parse(byte[] frame, int off, int len) { ... }
    public record ArpView(int oper, MacAddress sha, byte[] spa, MacAddress tha, byte[] tpa) {}
}
```

A frame is a **gratuitous ARP** when SPA == TPA (either operation). Classify it as `ObservationKind.GRATUITOUS_ARP`, not as a reply.

### 5.3 ICMPv4 echo  **[REFERENCE + IMPLEMENT]**

Header is **8 bytes** + payload:

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 1 | Type | `8` request / `0` reply |
| 1 | 1 | Code | `0` |
| 2 | 2 | Checksum | RFC 1071 over header+payload |
| 4 | 2 | Identifier | per-socket allocator |
| 6 | 2 | Sequence | per-probe |
| 8 | .. | Payload | monotonic nanoTime for RTT + magic cookie |

```java
public final class Icmp4Echo {
    public static byte[] request(int id, int seq, byte[] payload) { ... } // type=8, checksum computed
    public static java.util.Optional<EchoView> parseReply(byte[] pkt, int off, int len) { ... }
    public record EchoView(int id, int seq, byte[] payload) {}
}
```

Checksum and identifier ownership differs per path — see the table in §4.2. Summary: **we own both on Linux `SOCK_RAW` and Windows pcap; the macOS dgram socket rewrites the identifier and computes the checksum.**

### 5.4 ICMPv6 echo + NDP  **[REFERENCE + IMPLEMENT]**

ICMPv6 echo: Type `128` request / `129` reply; same 8-byte header shape as ICMPv4. Checksum uses the IPv6 pseudo-header (§5.1) — except on Linux `SOCK_RAW`/`IPPROTO_ICMPV6`, where the kernel computes it.

**Neighbor Solicitation (Type 135), RFC 4861:**

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Type = `135` |
| 1 | 1 | Code = `0` |
| 2 | 2 | Checksum |
| 4 | 4 | Reserved = 0 |
| 8 | 16 | Target address (the IPv6 being resolved) |
| 24 | 8 | Option: Source Link-Layer Address — Type=`1`, Len=`1` (units of 8 B), then 6-byte MAC |

**Neighbor Advertisement (Type 136):** byte 4 carries R/S/O flags in its top three bits (`R=0x80`, `S=0x40`, `O=0x20`); offsets 8..23 hold the target address; option Type=`2` (Target Link-Layer Address) carries the MAC.

Destination for an NS is the **solicited-node multicast** address `ff02::1:ffXX:XXXX` (low 24 bits of the target), which maps to destination MAC `33:33:ff:XX:XX:XX` (`33:33` + the low 32 bits of the multicast address).

> **HOP LIMIT MUST BE 255.** RFC 4861 §7.1.1 requires receivers to discard NS and NA whose IPv6 hop limit is not 255 — this is the on-link attack defence. Wherever the implementation builds its own IPv6 header (the Linux `AF_PACKET` NDP path, the Windows pcap NDP path), it must set 255, and it must **validate** 255 on received NS/NA. Getting this wrong produces a total silent failure of IPv6 resolution with no error anywhere.

```java
public final class Icmp6 {
    public static byte[] echoRequest(byte[] src16, byte[] dst16, int id, int seq, byte[] payload) { ... }
    public static byte[] neighborSolicitation(byte[] src16, byte[] targetIp16, MacAddress srcMac) { ... }
    public static byte[] solicitedNodeMulticast(byte[] targetIp16) { ... } // 16-byte addr
    public static MacAddress solicitedNodeMac(byte[] targetIp16) { ... }   // 33:33:ff:xx:xx:xx
    public static java.util.Optional<NaView> parseAdvertisement(byte[] pkt, int off, int len) { ... }
    public record NaView(byte[] targetIp16, MacAddress targetMac, int flags) {}
}
```

### 5.5 TTL as distance  **[IMPLEMENT]**

Each router decrements TTL by one, so `hopCount = initialTTL - observedTTL`, with the initial value inferred from convention:

| Initial TTL | Typical source |
|------------:|----------------|
| 64  | Linux, macOS, BSD, most IoT/embedded |
| 128 | Windows |
| 255 | Cisco/network gear, Solaris |

```java
public final class TtlDistance {
    /** Nearest standard initial TTL >= observed. Empty if observed <= 0. */
    public static java.util.Optional<Integer> hopCount(int observedTtl) { ... }
    /** Coarse OS family hint from the inferred initial TTL. Corroborating evidence only. */
    public static java.util.Optional<String> osHint(int observedTtl) { ... }
}
```

TTL is the better distance signal of the two available — RTT includes queuing, target processing delay, and (on probe 0) neighbour resolution. The inferred initial value is a coarse OS signal worth feeding into Tier-1 probe evidence as a **corroborating field, never a conclusion**: NAT and tunnels rewrite it, tuned stacks depart from defaults, and it is trivially spoofable.

Only populate `HostRecord.hopCount` when `capabilities().ttlAvailable()` is true.

---

## 6. Linux native backend  **[IMPLEMENT]**

Package `io.xlogistx.nosneak.net.platform.linux`. Binds `libc` via `Linker.nativeLinker().defaultLookup()`.

**Privilege model: the host process runs as root on the appliance.** `SOCK_RAW` is therefore unconditionally available. There is no capability grant, no `setcap`, no `net.ipv4.ping_group_range` dependency, and no `AT_SECURE`/`LD_LIBRARY_PATH` interaction to worry about.

A `SOCK_DGRAM`/`IPPROTO_ICMP` fallback may be kept for running the backend unprivileged on a dev laptop; it reports `ttlAvailable == false` and `rawEvidence == false`. It is not an appliance code path.

### 6.1 Downcall handles (all in libc)

| Function | FunctionDescriptor |
|----------|--------------------|
| `socket(int,int,int)` | `of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT)` |
| `bind(int, sockaddr*, socklen_t)` | `of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT)` |
| `sendto(int, void*, size_t, int, sockaddr*, socklen_t)` | `of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS, JAVA_INT)` |
| `recvfrom(int, void*, size_t, int, sockaddr*, socklen_t*)` | `of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS)` |
| `setsockopt(int,int,int,void*,socklen_t)` | `of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT)` |
| `close(int)` | `of(JAVA_INT, JAVA_INT)` |
| `if_nametoindex(char*)` | `of(JAVA_INT, ADDRESS)` — prefer `NetworkInterface.getIndex()` |

Capture `errno` via `Linker.Option.captureCallState("errno")`; read it through `Linker.Option.captureStateLayout()` on every `-1`.

> **Do NOT bind `fcntl` or `ioctl`.** The reader-thread model uses blocking sockets with `SO_RCVTIMEO` (§4.4). This sidesteps the `O_NONBLOCK` value difference and every variadic `ioctl` hazard.

### 6.2 Constants  **[REFERENCE — Linux]**

```
AF_INET             = 2
AF_INET6            = 10          // differs on macOS (30) and Windows (23)
AF_PACKET           = 17
SOCK_DGRAM          = 2
SOCK_RAW            = 3
IPPROTO_ICMP        = 1
IPPROTO_ICMPV6      = 58
ETH_P_ALL           = 0x0003      // htons() when placed in sockaddr_ll.sll_protocol
ETH_P_IP            = 0x0800
ETH_P_ARP           = 0x0806
ETH_P_IPV6          = 0x86DD
SOL_SOCKET          = 1
SO_RCVTIMEO         = 20
SOL_PACKET          = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP= 2
PACKET_MR_PROMISC   = 1
ICMP6_FILTER        = 1           // level = IPPROTO_ICMPV6
IPV6_UNICAST_HOPS   = 16
IPV6_MULTICAST_HOPS = 18
```

All values are identical on x86-64 and aarch64.

### 6.3 `sockaddr_in` / `sockaddr_in6` layouts  **[REFERENCE — Linux]**

```java
// Linux sockaddr_in — 16 bytes. family is 2 bytes at offset 0.
static final MemoryLayout SOCKADDR_IN = MemoryLayout.structLayout(
    JAVA_SHORT.withName("sin_family"),          // AF_INET, host order
    JAVA_SHORT.withName("sin_port"),            // network order
    JAVA_INT.withName("sin_addr"),              // network order (raw 4 bytes of IPv4)
    MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero")
);

// Linux sockaddr_in6 — 28 bytes.
static final MemoryLayout SOCKADDR_IN6 = MemoryLayout.structLayout(
    JAVA_SHORT.withName("sin6_family"),         // AF_INET6 = 10
    JAVA_SHORT.withName("sin6_port"),
    JAVA_INT.withName("sin6_flowinfo"),
    MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("sin6_addr"),
    JAVA_INT.withName("sin6_scope_id")          // set to ifIndex for link-local
);
```

> Write `sin_port`/`sin_addr` in **network byte order**. `JAVA_SHORT`/`JAVA_INT` default to native (little-endian) order on both supported architectures. Provide `htons`/`htonl` helpers and use them everywhere addresses and ports are packed; do not rely on ad-hoc `withOrder` views scattered through the code.

### 6.4 `sockaddr_ll` layout for AF_PACKET  **[REFERENCE — Linux]**

```java
// Linux sockaddr_ll — 20 bytes. Identical on x86-64 and aarch64.
static final MemoryLayout SOCKADDR_LL = MemoryLayout.structLayout(
    JAVA_SHORT.withName("sll_family"),          // AF_PACKET = 17
    JAVA_SHORT.withName("sll_protocol"),        // htons(ETH_P_ARP) etc.
    JAVA_INT.withName("sll_ifindex"),           // from NetworkInterface.getIndex()
    JAVA_SHORT.withName("sll_hatype"),
    JAVA_BYTE.withName("sll_pkttype"),
    JAVA_BYTE.withName("sll_halen"),            // 6 for Ethernet
    MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sll_addr") // MAC in first 6
);
```

**Use `SOCK_DGRAM` with `AF_PACKET`, not `SOCK_RAW`.** The kernel then prepends and strips the Ethernet header, so only the 28-byte ARP payload is handled and no Ethernet header is ever hand-built.

Three consequences that follow directly from that, and that are the most common source of bugs on this path:

1. **On send, the on-wire ethertype comes from `sll_protocol` in the DESTINATION `sockaddr_ll` passed to `sendto`** — not from the `protocol` argument given to `socket()`. The socket's protocol argument governs *receive* filtering. Set both.
2. **On receive, there is no ethertype in the buffer**, because the kernel stripped the Ethernet header. It arrives in `sll_protocol` of the `sockaddr_ll` filled in by `recvfrom`. The reader thread must pass a `sockaddr_ll` buffer to `recvfrom` and dispatch on that field. Parsing an ethertype out of the payload will read ARP HTYPE instead and silently misroute every frame.
3. **The source MAC also arrives in `sll_addr`** of that same sockaddr (`sll_halen` bytes). For ARP the SHA in the payload is authoritative, but `sll_addr` is what catches a mismatch between the frame header and the ARP payload — worth recording as spoofing evidence.

Per-operation setup:

- **ARP send:** `socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))`; fill `sockaddr_ll` with `sll_ifindex`, `sll_halen = 6`, `sll_addr = ff:ff:ff:ff:ff:ff`, `sll_protocol = htons(ETH_P_ARP)`; `sendto` the 28-byte ARP request.
- **NDP send:** `socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6))`; destination MAC is the solicited-node multicast MAC; payload is a hand-built **IPv6 header (hop limit 255)** + ICMPv6 NS. See open decision §12.1 — there is a simpler alternative.
- **Passive + reply capture:** two typed sockets (`ETH_P_ARP` and `ETH_P_IPV6`) rather than one `ETH_P_ALL` socket, so the kernel does the filtering and each reader thread has one job.
- **Scope receive to this interface.** An `AF_PACKET` socket that is never `bind()`-ed receives from **every** interface on the box. With one `HostDiscovery` per NIC (§2.0) that means the eth0 instance sees eth1's ARP and learns those neighbours into a cache that claims to be per-binding. Either `bind()` the socket to a `sockaddr_ll` carrying `sll_ifindex` and `sll_protocol`, or discard frames whose `sll_ifindex` does not match the binding. `bind()` is better — the kernel filters instead of the reader thread — and the fallback filter is one comparison on a field the reader already has to read.
- **Promiscuous mode** (required for `observe()` to see third-party traffic) is enabled with `setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, 16)`:

```java
// struct packet_mreq — 16 bytes.
MemoryLayout.structLayout(
    JAVA_INT.withName("mr_ifindex"),
    JAVA_SHORT.withName("mr_type"),      // PACKET_MR_PROMISC = 1
    JAVA_SHORT.withName("mr_alen"),
    MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("mr_address")
);
```

Receive buffers must be at least MTU-sized; use 65536 and be done with it.

### 6.5 ICMP path (Linux, root) — this is the `ICMPPing` implementation

- **IPv4:** `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`.
    - **We compute the ICMP checksum and own the identifier.**
    - Receives deliver the **full IPv4 header followed by the ICMP message**, so TTL is read directly at IP header offset 8 — no `recvmsg`, no cmsg. This is the entire reason for choosing `SOCK_RAW`, and it makes `ttlAvailable` and `rawEvidence` both true.
    - A raw ICMP socket receives a copy of **every** ICMP packet delivered to the host, including other processes' traffic. Filtering on our identifier is mandatory.
    - Send with `sendto` to a `sockaddr_in`. The kernel builds the IP header and routes normally, so **off-link targets work** without any next-hop logic.
- **IPv6:** `socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)`.
    - We own the identifier; the **kernel computes the ICMPv6 checksum** — do not compute it as well.
    - The kernel **strips the IPv6 header** on receive regardless of privilege, so hop limit is unavailable without `IPV6_RECVHOPLIMIT` + `recvmsg`. Out of scope (§1): report `ttlOrHopLimit = -1` on all IPv6.
    - Install an `ICMP6_FILTER` via `setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, ...)` to receive only echo replies (type 129), cutting reader-thread noise substantially. `struct icmp6_filter` is 8 × `uint32` = 32 bytes; the "block all, pass 129" pattern is zeroed words with the bit for 129 cleared.
- **RTT:** embed a monotonic `System.nanoTime()` in the echo payload and compute on reply. Do not use wall-clock time.

### 6.6 Socket summary (Linux)

The **Owner** column is the §2.0 split made concrete: the two ICMP sockets exist once per JVM, the two `AF_PACKET` sockets once per NIC.

| Operation | Socket | Owner | Count |
|-----------|--------|-------|-------|
| ICMPv4 echo | `AF_INET`, `SOCK_RAW`, `IPPROTO_ICMP` | `ICMPPing` | 1 per JVM |
| ICMPv6 echo | `AF_INET6`, `SOCK_RAW`, `IPPROTO_ICMPV6` + `ICMP6_FILTER` | `ICMPPing` | 1 per JVM |
| ARP send/recv | `AF_PACKET`, `SOCK_DGRAM`, `htons(ETH_P_ARP)`, bound to ifindex | `HostDiscovery` | 1 per NIC |
| NDP send/recv | `AF_PACKET`, `SOCK_DGRAM`, `htons(ETH_P_IPV6)`, bound to ifindex | `HostDiscovery` | 1 per NIC |
| Passive observe | the same two `AF_PACKET` sockets + `PACKET_MR_PROMISC` | `HostDiscovery` | — |

---

## 7. macOS native backend  **[IMPLEMENT]**

Package `io.xlogistx.nosneak.net.platform.darwin`. Binds `libc` via `Linker.nativeLinker().defaultLookup()`. No pcap, no BPF, no `ioctl`.

**This backend is deliberately the least capable of the three.** It provides ICMP liveness and MAC resolution, and nothing else. `capabilities()` must report `passiveObservation == false`, `ttlAvailable == false`, `rawEvidence == false`.

### 7.1 Constants  **[REFERENCE — macOS]**

```
AF_INET        = 2
AF_INET6       = 30        // NOT 10
AF_LINK        = 18
SOCK_DGRAM     = 2
IPPROTO_ICMP   = 1
IPPROTO_ICMPV6 = 58
SOL_SOCKET     = 0xFFFF
SO_RCVTIMEO    = 0x1006
CTL_NET        = 4
PF_ROUTE       = 17
NET_RT_FLAGS   = 2
RTF_LLINFO     = 0x400
```

Identical on x86-64 and arm64.

### 7.2 `sockaddr_in` / `sockaddr_in6` layouts  **[REFERENCE — macOS]**

Same **sizes** as Linux (16 and 28), different **shape**: Darwin has a leading `sin_len` byte, so the family is one byte at offset 1 rather than two bytes at offset 0. Same size with a different layout is precisely the kind of error that fails silently — do not reuse the Linux layouts.

```java
// macOS sockaddr_in — 16 bytes.
static final MemoryLayout SOCKADDR_IN = MemoryLayout.structLayout(
    JAVA_BYTE.withName("sin_len"),              // = 16
    JAVA_BYTE.withName("sin_family"),           // AF_INET = 2
    JAVA_SHORT.withName("sin_port"),            // network order
    JAVA_INT.withName("sin_addr"),
    MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero")
);

// macOS sockaddr_in6 — 28 bytes.
static final MemoryLayout SOCKADDR_IN6 = MemoryLayout.structLayout(
    JAVA_BYTE.withName("sin6_len"),             // = 28
    JAVA_BYTE.withName("sin6_family"),          // AF_INET6 = 30
    JAVA_SHORT.withName("sin6_port"),
    JAVA_INT.withName("sin6_flowinfo"),
    MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("sin6_addr"),
    JAVA_INT.withName("sin6_scope_id")
);
```

### 7.3 Neighbor table read via `sysctl`  **[VERIFY — do not generate from memory]**

macOS has no `AF_PACKET`, and BPF is excluded (root-owned, exclusive-open, `ioctl`-configured, and variadic — the Darwin arm64 `firstVariadicArg` hazard). Instead this backend reads the **kernel's own neighbor table**, which is what `arp -a` and `ndp -a` do.

`sysctl` is non-variadic, so the arm64 variadic hazard does not apply. This is the main argument for the approach over any `ioctl`-based alternative.

```
sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
  -> of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG)
```

MIB for the ARP table: `{CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO}` (6 elements). For the NDP table, substitute `AF_INET6`.

Two-pass call: invoke with `oldp = NULL` to size the buffer, allocate from a confined arena, invoke again, then walk the returned block as a sequence of `rt_msghdr` records, advancing by `rtm_msglen` (a `u_short` at offset 0). Each record is followed by a set of sockaddrs selected by the `rtm_addrs` bitmask; the `AF_LINK` / `sockaddr_dl` entry carries the MAC at `sdl_data + sdl_nlen` with length `sdl_alen`.

> **[VERIFY] This is the only unverified ABI in the design, and it must not be generated from memory.**
> `rt_msghdr` embeds `struct rt_metrics`, and the `ROUNDUP` padding rule applied to the trailing sockaddrs has diverged between Darwin and the BSDs. `RTF_LLINFO` semantics have also shifted across macOS releases.
>
> Before writing this backend, emit `sizeof(struct rt_msghdr)`, `offsetof` for `rtm_msglen`/`rtm_addrs`/`rtm_flags`, `sizeof(struct sockaddr_dl)`, and the `ROUNDUP` constant from a short C probe on **both** Intel and Apple Silicon, using the existing `NativeBindingFactory` GCC-assisted strategy. Cross-check the parsed output against `arp -a` before building anything on top of it. Expect the two architectures to agree; confirm it rather than assuming it.

### 7.4 Active resolution is indirect

There is no solicitation to send. Instead, provoke the kernel into resolving, then read the table:

1. Check `IpMacCache`.
2. On miss, read the kernel neighbor table. If present, return with `ResolveSource.KERNEL_TABLE`.
3. Still missing: emit traffic to the target — the ICMP echo from `ping()` is sufficient, or a UDP datagram to a closed port.
4. Poll the neighbor table on a short interval (~100 ms) until the entry appears or the caller's `timeout` expires.

A useful property falls out of this and should be documented in the javadoc: **a host that is alive but ICMP-filtered still resolves**, because the kernel must ARP before it can transmit anything. So on macOS `resolve()` can succeed where `ping()` fails — a different failure mode from Linux and Windows, and worth surfacing to the fingerprinting layer.

What this backend gives up, all of which must be reported honestly through `capabilities()`: gratuitous and spoofed-source ARP visibility, passive learning, `ObservedNeighbor` entirely, and solicitation timing (you learn *that* it resolved, not the RTT of the solicitation, so `ResolveResult.elapsed` measures the poll loop, not the wire).

### 7.5 ICMP path (macOS) — this is the `ICMPPing` implementation

- **IPv4:** `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` — unprivileged on Darwin, as on Linux. The kernel computes the checksum and **rewrites the identifier**; read it back from the reply and correlate on sequence (§4.2).
- **IPv6:** `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)`. Same model. Note `AF_INET6 = 30`.
- The kernel strips the IP header, so **TTL is unavailable**: report `ttlOrHopLimit = -1` and `ttlAvailable == false`. Obtaining it would require `IP_RECVTTL` + `recvmsg`, which is out of scope (§1).
- Kernel routing applies, so off-link targets work.

---

## 8. Windows pcap backend  **[IMPLEMENT]**

Package `io.xlogistx.nosneak.net.platform.windows`. Binds Npcap's `wpcap.dll` via FFM. This backend crafts and captures **full L2 frames** — pcap operates below IP.

### 8.1 Library lookup and Npcap detection  **[REFERENCE]**

`wpcap.dll` installs to `%SystemRoot%\System32\Npcap\`, which is **not** on the default DLL search path.

> **Loader hazard:** `wpcap.dll` depends on `Packet.dll` in the same directory. Loading `wpcap.dll` by absolute path without first adding that directory to the DLL search path fails at dependency resolution with an unhelpful error. Either require Npcap's WinPcap-compatibility install mode (which places the DLLs in `System32`), or set the DLL directory before the lookup.

Make the path configurable via the system property `io.xlogistx.nosneak.net.platform.windows.lib`.

**If Npcap is absent, fail at `HostDiscoveryFactory.open()`** with a `DiscoveryException` naming the missing library and the install URL. Do not fail obscurely at first use, and do not bundle the installer.

> **Licensing.** The free Npcap edition is limited to installation on five systems and explicitly does not permit redistribution within a product; redistribution requires an Npcap OEM license from the Nmap Project. Since Windows is dev-parity only (§11), five developer machines is within the free terms — but this must be revisited before any Windows no-sneak build is shipped to a customer. Do not treat the free tier as covering distribution.

### 8.2 Downcall handles (libpcap API)

| Function | Descriptor |
|----------|------------|
| `pcap_findalldevs(pcap_if_t**, char* errbuf)` | `of(JAVA_INT, ADDRESS, ADDRESS)` |
| `pcap_freealldevs(pcap_if_t*)` | `ofVoid(ADDRESS)` |
| `pcap_open_live(char* dev,int snaplen,int promisc,int to_ms,char* errbuf)` | `of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS)` |
| `pcap_datalink(pcap_t*)` | `of(JAVA_INT, ADDRESS)` |
| `pcap_sendpacket(pcap_t*, u_char*, int)` | `of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT)` |
| `pcap_next_ex(pcap_t*, pcap_pkthdr**, u_char**)` | `of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS)` |
| `pcap_compile(pcap_t*, bpf_program*, char* str, int optimize, bpf_u_int32 netmask)` | `of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT)` |
| `pcap_setfilter(pcap_t*, bpf_program*)` | `of(JAVA_INT, ADDRESS, ADDRESS)` |
| `pcap_freecode(bpf_program*)` | `ofVoid(ADDRESS)` |
| `pcap_close(pcap_t*)` | `ofVoid(ADDRESS)` |
| `pcap_geterr(pcap_t*)` | `of(ADDRESS, ADDRESS)` |

`pcap_t*` and `pcap_if_t*` are opaque `ADDRESS`.

**Do not use `pcap_loop`.** It requires an upcall stub and `pcap_breakloop` to exit. Standardize on `pcap_next_ex` with a positive `to_ms` (§4.4).

Required constants and structs the v1 draft omitted:

```
PCAP_ERRBUF_SIZE     = 256          // MANDATORY minimum errbuf allocation
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF   // pass as pcap_compile's netmask
DLT_EN10MB           = 1            // the only datalink this backend supports
```

> Under-allocating the errbuf is a native buffer overflow into JVM memory. Allocate exactly `PCAP_ERRBUF_SIZE` bytes, always.

```java
// struct bpf_program — 16 bytes on LLP64 (u_int + padding + pointer).
static final MemoryLayout BPF_PROGRAM = MemoryLayout.structLayout(
    JAVA_INT.withName("bf_len"),
    MemoryLayout.paddingLayout(4),
    ADDRESS.withName("bf_insns")
);
```

Always `pcap_freecode` a compiled program after `pcap_setfilter`, or it leaks.

**Verify the datalink.** Call `pcap_datalink()` after `pcap_open_live` and reject anything other than `DLT_EN10MB` with a clear `DiscoveryException`. The codecs assume an Ethernet header unconditionally; loopback and tunnel interfaces are not Ethernet and would be parsed as garbage.

### 8.3 Device enumeration & selection

Device names have nothing in common with Java's (`\Device\NPF_{GUID}` vs whatever `NetworkInterface.getName()` returns). **Never hardcode, never pattern-match the name.** Enumerate with `pcap_findalldevs`, walk the `pcap_if_t` linked list, and match each device to the target `NetworkInterface` **by IP address**, comparing `pcap_addr` entries against the addresses in `NicBinding.ipv4`/`ipv6` (each a `LocalAddress`, so compare `.address()`). Store the match as `NicBinding.backendDeviceName`.

`pcap_if_t` fields needed: `next` (ADDRESS at offset 0), `name` (ADDRESS at offset 8), `description`, `addresses` (ADDRESS). `pcap_addr`: `next`, `addr` (`sockaddr*`). This is pointer-chasing via `MemorySegment.get(ADDRESS, off)` + `reinterpret`.

Windows `sockaddr` shape for that parse — **one column now that macOS is off this backend**:

```
             AF_INET   AF_INET6   sockaddr_in shape
Windows      2         23         family = 2 bytes @ 0, no sin_len
```

### 8.4 Sending frames (pcap builds nothing)

Every send is a **complete Ethernet frame**:

- **ARP:** `dstMAC = broadcast`, `srcMAC = ourMAC`, `ethertype = 0x0806`, then the 28-byte ARP payload.
- **ICMPv4 echo:** `dstMAC = the NEXT HOP's MAC` — the target's when on-link, the gateway's when not (§8.7) — resolved by ARP first, `ethertype = 0x0800`, IPv4 header (TTL, protocol = 1, IP ID, src/dst, header checksum), then the ICMP echo. **We compute both the IPv4 header checksum and the ICMP checksum.**
- **ICMPv6 echo / NS:** `ethertype = 0x86DD`, IPv6 header (**hop limit 255 for NS/NA**, next header = 58), then ICMPv6 with pseudo-header checksum. NS destination MAC is the solicited-node multicast MAC.

Injection bypasses OS routing entirely, so an off-link destination needs the default gateway's MAC, hence its IP. That is what §8.7's `iphlpapi` binding supplies. When it is unavailable, `offLinkIcmp` reports false and off-link targets complete with `PingError.NETWORK_UNREACHABLE` — the old v1 behaviour, now a fallback rather than the rule.

**Capture setup:** `pcap_open_live(dev, 65536, promisc, 200, errbuf)`. Pass `promisc = 1` only when an `observe()` subscription exists — promiscuous mode raises capture volume substantially and is detectable on the segment. BPF filter: `arp or icmp or icmp6`. Note that this filter does **not** match 802.1Q-tagged frames; prefix with `vlan` if the dev network is tagged, and remember that a tag shifts every subsequent offset by 4 bytes in the parser.

### 8.5 `pcap_pkthdr` layout — Windows only  **[REFERENCE]**

Read on **every** received packet. With macOS moved off this backend, only one variant is live.

```java
// Windows (LLP64) — 16 bytes. timeval = { long tv_sec (4), long tv_usec (4) }.
static final MemoryLayout PKTHDR_WINDOWS = MemoryLayout.structLayout(
    JAVA_INT.withName("tv_sec"),
    JAVA_INT.withName("tv_usec"),
    JAVA_INT.withName("caplen"),     // offset 8
    JAVA_INT.withName("len")         // offset 12
);
```

Identical on x86-64 and arm64. Read `caplen` to know how many bytes of the `u_char*` buffer are valid — never `len`, which is the on-wire length and may exceed the captured bytes.

**Defensive check:** assert `0 < caplen <= len <= snaplen` on every packet. If a future Npcap build changes the struct, this catches it immediately instead of producing silently corrupt frames.

### 8.6 One object, both interfaces  **[IMPLEMENT]**

Windows is where the §2.0 split does not hold, and pretending otherwise produces a construction cycle. `WindowsPcapBackend` implements **`HostDiscovery` and `ICMPPing` on the same instance**.

The reason is physical, not stylistic. pcap injects at L2 and bypasses routing, so an echo request needs a device handle, a source MAC and IP, and the **destination's MAC** — which means it needs ARP, which is the other interface. One `pcap_t`, one device, one `pcap_next_ex` reader thread demultiplexing by ethertype: splitting that across two objects would mean a second handle on the same adapter, a second capture thread, and a second `IpMacCache` that disagrees with the first.

**Multi-interface pinging.** The Windows `ICMPPing` role is constructed over the **list** of open `HostDiscovery` instances (`Discovery.perInterface`, §3.8) — not over bare `NetworkInterface`s, so it reuses their handles, their ARP paths, and their caches. `ping(target)` then:

1. Walks the supplied bindings and picks the first whose `isOnLink(target)` is true (§3.6). This is an on-link table, **not** a routing table — no metrics, no default route, no cross-interface longest-prefix.
2. No match → complete with `PingError.NETWORK_UNREACHABLE`. Off-link still needs the gateway's MAC, hence its IP, hence `iphlpapi`; **`offLinkIcmp` stays false** and adding interfaces does not change that.
3. Resolves the destination MAC through that binding's own `resolve()`, hitting its `IpMacCache` first.
4. Injects through that binding's handle. Send serialization is per `pcap_t` (§12.7) — the pinger does not own the handle, so the choke point is the handle's, not the pinger's.
5. Replies arrive on that binding's `pcap_next_ex` reader, which must dispatch ICMP into the pinger's in-flight correlation map (§4.2). Same object, so this is a direct call rather than a callback.

**Per-binding send capability must be probed, not assumed.** `pcap_sendpacket` is driver-dependent and commonly fails on wireless adapters — capture works, injection does not. Probe each supplied binding once at construction, mark the failures capture-only, exclude them from step 1, and report the reduced set through `capabilities()`. **Do not fail construction** because one NIC of several cannot inject.

> The bare `ICMPPing` from `HostDiscoveryFactory.openIcmpOnly()` does not exist on Windows and throws `DiscoveryException` (§3.8). Every other platform gets a real one.

### 8.7 Off-link routing via `iphlpapi`  **[IMPLEMENT]**

**Reverses the original "Windows is on-link only" constraint.** Off-link ICMP now works on all three platforms — Linux and macOS always did, because the kernel routes; Windows now does too.

The obstacle was never difficulty, it was an assumed cost: injecting at L2 needs the *next hop's* MAC, which needs the next hop's IP, which only the routing table knows. That turned out to be **one function and one struct field**:

```c
GetBestRoute2(NULL, 0, NULL, &destination, 0, &row, &bestSource);   // iphlpapi.dll
```

`Iphlpapi` binds exactly that and reads exactly one field, `MIB_IPFORWARD_ROW2.NextHop` at **byte offset 44**:

```
  0   NET_LUID          InterfaceLuid       (8, aligned 8)
  8   NET_IFINDEX       InterfaceIndex      (4)
 12   IP_ADDRESS_PREFIX DestinationPrefix   (SOCKADDR_INET 28 + UINT8 + pad = 32)
 44   SOCKADDR_INET     NextHop             (28)
```

**That offset was derived, then confirmed empirically rather than trusted.** A diagnostic scan of the filled row found exactly two `AF_INET`-shaped fields — offset 12 decoding as `0.0.0.0` (the default route's prefix) and offset 44 as the machine's real gateway. `probeNextHopOffset` is retained so a struct change on a future Windows can be located the same way. The row buffer is deliberately over-allocated to 512 bytes and only `NextHop` is read: `MIB_IPFORWARD_ROW2` has sixteen members and two `SOCKADDR_INET` unions, and hand-deriving all of it would be a large unverified surface for no benefit.

`routeFor(target)` then decides in this order:

1. Is the target on-link for this binding, or any peer's? Use it directly. This stays a **subnet test**, not route selection (§8.6).
2. Otherwise ask `GetBestRoute2` for the next hop, and find the injectable binding that has *the gateway* on-link.
3. Nothing? `NETWORK_UNREACHABLE`, as before.

Two details that are easy to get wrong:

- **The Ethernet destination and the IP destination differ.** The frame is addressed to the gateway's MAC while the IPv4 header still carries the real target. Resolving the *target's* MAC for an off-link host is meaningless — nothing beyond the segment answers ARP.
- **`sourceFor(target)` is empty for an off-link target**, since it has no address in our subnet. The source falls back to the interface's own address of the right family; without that, the send throws.

`offLinkIcmp` now reports `l2 && Iphlpapi.isAvailable()`, so a machine where the DLL cannot be loaded degrades to the old on-link-only behaviour and says so, rather than failing obscurely.

**Verified on live hardware**: `yahoo.com` (74.6.231.21) answers in ~85 ms with **TTL 47** — an initial 64 minus 17 hops, i.e. a genuine internet path, not a local reply. On-link pings still report TTL 64 and ~13 ms.

---

## 9. IpMacCache  **[IMPLEMENT]**

Package `io.xlogistx.nosneak.net.util`. Pure Java. Shared by all three backends.

### 9.1 Contract

- Keyed by `InetAddress` (v4 and v6). Value carries MAC, first-seen, last-seen, state, provenance.
- **One cache instance per `HostDiscovery` binding.** `Inet6Address.equals()` compares the 16 address bytes and does not consider the scope id, so `fe80::1%eth0` and `fe80::1%eth1` collide. Per-binding ownership makes that harmless. If a cross-interface cache is ever wanted, the key must become `(ifIndex, address)`.
- Never call `InetAddress.getHostName()` anywhere near this class — it triggers reverse DNS. `equals`, `hashCode`, and `toString` do not.
- Thread-safe via `ConcurrentHashMap` atomic operations (`compute`, `merge`). No synchronized wrappers. Upserts must use `compute`/`merge` — `getOrDefault` is a read-only fallback and cannot substitute for an atomic insert.
- Aging: entries expire after a configurable TTL since `lastSeen`. Lazy expiry on read, plus an optional scheduled daemon sweep.
- Provenance: `ResolveSource` (§3.4). Passive and kernel-table updates refresh `lastSeen` and may upgrade state.
- State machine: `INCOMPLETE` (solicited, no reply yet) → `REACHABLE` (fresh reply/observation) → `STALE` (TTL passed) → evicted.
- **Conflict detection:** if an observation reports a different MAC for an IP that is currently `REACHABLE` with a different MAC, record it rather than silently overwriting. On a security appliance an IP↔MAC change is either a legitimate DHCP/failover event or ARP spoofing, and the fingerprinting layer wants to know. A `conflictCount` on `Entry` plus a `lastConflictAt` is enough for v1.

### 9.2 Skeleton

```java
public final class IpMacCache {

    public record Entry(
            java.net.InetAddress ip,
            MacAddress mac,                 // null while INCOMPLETE
            State state,
            ResolveSource provenance,
            java.time.Instant firstSeen,
            java.time.Instant lastSeen,
            int conflictCount,
            java.time.Instant lastConflictAt) {}

    public enum State { INCOMPLETE, REACHABLE, STALE }

    private final java.util.concurrent.ConcurrentHashMap<java.net.InetAddress, Entry> map;
    private final java.time.Duration reachableTtl;   // e.g. 30s
    private final java.time.Duration staleTtl;       // e.g. 5m before eviction

    public IpMacCache(int expectedHosts, java.time.Duration reachableTtl, java.time.Duration staleTtl) {
        // ConcurrentHashMap's one-arg constructor ALREADY applies 1.5x headroom
        // internally: sizeCtl = tableSizeFor(n + (n >>> 1) + 1). Do NOT apply the
        // HashMap n/0.75 idiom on top of it — that yields ~2x the intended table.
        this.map = new java.util.concurrent.ConcurrentHashMap<>(Math.max(16, expectedHosts));
        this.reachableTtl = reachableTtl;
        this.staleTtl = staleTtl;
    }

    /** Lookup with lazy aging. Empty if absent or evicted. */
    public java.util.Optional<Entry> get(java.net.InetAddress ip) { ... }

    /** Record an active/passive/kernel observation. Atomic upsert via compute(). */
    public void observe(java.net.InetAddress ip, MacAddress mac, ResolveSource src) { ... }

    /**
     * Mark an in-flight solicitation. INFORMATIONAL ONLY — this does NOT dedupe
     * concurrent resolves. Deduplication belongs in the §4.2 in-flight map, where
     * a second caller can computeIfAbsent onto the first caller's
     * CompletableFuture and actually await a result. A cache entry gives the
     * second caller nothing to wait on.
     */
    public void markIncomplete(java.net.InetAddress ip) { ... }

    /** Optional background sweep; returns count evicted. */
    public int sweepExpired() { ... }

    /** For the admin UI. */
    public java.util.List<Entry> snapshot() { ... }
}
```

---

## 10. Module & build  **[IMPLEMENT]**

### 10.1 `module-info.java` — **NOT USED (§12.8 resolved)**

**Do not add one.** `platform.*` stays internal by convention, not by compiler enforcement, and the native-access flag is `ALL-UNNAMED` (§10.2). The sketch below is kept only to show what was rejected and why.

```java
module io.xlogistx.nosneak.net {
    requires org.zoxweb.core;             // <-- does not exist; see below
    exports io.xlogistx.nosneak.net.common;
    exports io.xlogistx.nosneak.net.util;
    exports io.xlogistx.nosneak.net.codecs;
    // platform.linux / platform.darwin / platform.windows are internal —
    // do not export. All FFM and pcap code lives there and nowhere else.
}
```

`requires java.base` is implicit; omit it.

> **Two findings that make this unwritable as-is.** First, `zoxweb-core` has **no `module-info.java` and no `Automatic-Module-Name`** in its pom, so `requires` would have to name an automatic module derived from the jar filename — which changes whenever the artifact is renamed or versioned differently. Second, **no other module in no-sneak declares a `module-info.java` at all**; the whole project builds and runs on the classpath. Adding JPMS to exactly this one module gains encapsulation of the `platform.*` packages and costs a fragile `requires` on a filename.
>
> Both point the same way: **drop `module-info.java`, keep the `platform.*` packages internal by convention**, and use the `ALL-UNNAMED` form of the native-access flag (§10.2). That is a decision for the maintainer, not an assumption — recorded as open decision §12.8.

### 10.2 Native access

FFM restricted methods require enabling native access at launch:

```
java --enable-native-access=io.xlogistx.nosneak.net ...
```

Without it: warnings on JDK 25, hard failure in a future release. This is a **JVM module-access check and is orthogonal to OS privilege** — running as root does not satisfy it.

> **jar-loader interaction:** the flag above only applies if this module is genuinely loaded as a named module. If a custom classloader (jar-loader) ends up placing it on the classpath, the correct flag is `--enable-native-access=ALL-UNNAMED`. Confirm which applies during the §12 spike and pin it in the launcher script; do not leave it to chance.
>
> **Current evidence says `ALL-UNNAMED`.** Nothing in no-sneak declares a `module-info.java`, so this module would be loaded from the classpath as an unnamed module and the named form would silently fail to grant access — producing exactly the warning it was meant to suppress. Settle §12.8 before pinning the launcher flag.

### 10.3 Maven

- Module `no-sneak-net` under the no-sneak reactor (parent `io.xlogistx:no-sneak:1.0.0`); already created.
- **The pom is written** — do not re-derive it. Compile dependencies, all version-managed by the parent (never pin a version here):

  | Artifact | Why |
  |---|---|
  | `org.zoxweb:zoxweb-core` | `TaskUtil` shared pools (§4.3) |
  | `io.xlogistx:xlogistx-common` | house utilities — check here before hand-rolling helpers |
  | `io.xlogistx:xlogistx-core` | house utilities |
  | `org.junit.jupiter:junit-jupiter-params` | tests |

  Anything beyond these is a design change, not a build tweak. In particular there is **no** Netty, pcap4j, or Guava, and crypto helpers belong in `opsec/OPSecUtil`, not here.

- **Release 25 is already inherited — verified, no action needed.** `xlogistx-mvn` configures `maven-compiler-plugin` with `<release>${jdk.version}</release>` and defaults `jdk.version` to **8**; the no-sneak root pom overrides it to **25**, and `no-sneak-net` has an empty `<properties>` block so it inherits that. Leave it alone: setting `maven.compiler.release` locally would shadow the chain and silently diverge from the rest of the reactor.
- **Still missing: Surefire `argLine`** — `--enable-native-access=...` is not configured anywhere. Not yet blocking, because §13 steps 1–4 are pure Java and the grandparent sets `<skipTests>true</skipTests>` anyway, but any FFM test will warn without it. Pin the form §12.8 settles on (`ALL-UNNAMED` on current evidence) at the same time as the launcher flag.
- Do not attempt native-image; the closed-world incompatibility is documented in `no-sneak-net/README.md`.
- The 64-bit-only constraint is documented in `no-sneak-net/README.md` as a **platform** constraint, not a preference: FFM has no 32-bit linker implementation, and the Windows x86-32 port was removed in JDK 24.

---

## 11. Testing & validation plan  **[IMPLEMENT]**

The appliance (Linux/aarch64) is the gate. macOS and Windows are dev-parity.

1. **Codec unit tests (host-independent, run everywhere).** Build/parse round-trips for ARP, ICMPv4, ICMPv6 echo, NS/NA. Known-good RFC 1071 checksum vectors and an ICMPv6 pseudo-header vector. Solicited-node multicast and `33:33:ff:*` MAC derivation vectors. Gratuitous-ARP classification (SPA == TPA). NS/NA hop-limit-255 validation, both accept and reject cases. `TtlDistance.hopCount` boundary cases (64/128/255, and observed values just below each).
2. **Layout tests — three targets, not six.** Every layout is selected on `os.name` only (§2.3), so the matrix collapses. Assert: Linux `sockaddr_in`=16, `sockaddr_in6`=28, `sockaddr_ll`=20, `timeval`=16, `packet_mreq`=16; macOS `sockaddr_in`=16 with `sin_family` at offset **1**, `sockaddr_in6`=28, `timeval`=16; Windows `pcap_pkthdr`=16 with `caplen` at offset **8**, `bpf_program`=16.
3. **Cache tests.** Upsert paths use `compute`/`merge`; aging transitions `INCOMPLETE → REACHABLE → STALE → evicted` with a compressed TTL; conflict detection increments rather than silently overwriting; concurrent `observe()` under contention.
4. **Ping aggregation tests (no network).** Drive `PingResult.of` with synthetic probe lists: all-replied, all-lost, mixed, `count == 1`, and the `neighborResolutionPending` exclusion — assert that probe 0 counts toward `sent`/`received` but not toward `min`/`avg`/`stdDev` when `count > 1`.
5. **Loopback / self tests.** Ping `127.0.0.1` and `::1`; confirm `NicBinding.from` tolerates a null hardware address on loopback rather than throwing.
6. **Shutdown tests.** Assert `close()` returns promptly while reader threads are blocked in `recvfrom` — this is the `SO_RCVTIMEO` path (§4.4) and it is the one that silently hangs if implemented wrong. Assert pending futures complete normally with an error result, not exceptionally.
7. **Split / wiring tests (no network).** These cover the failure modes the two-interface design introduces:
   - `openIcmpOnly()` returns a working pinger with **no** `binding()` accessor and `activeArp == false`.
   - `HostDiscovery.close()` leaves its `icmpPing()` usable — open two bindings, close one, assert the other can still ping. This is the borrowed-not-owned rule (§4.1) and it fails silently in production if got wrong.
   - `Discovery.close()` closes both, and a second `close()` is a no-op.
   - `capabilities()` is identical before and after the factory returns — the set-once injection must not be observable.
   - Degraded sweep: with `icmpPing()` empty, every `HostRecord` has `icmpAlive == false` and a present `mac`, and no host is skipped.
   - `NicBinding.LocalAddress.onLink` boundary cases: /31 and /32, /24 first and last address, IPv6 /64 and /128, and a target in a *different* family than the address.
   - Two sockets never share an ICMP identifier (§4.2).
8. **Live integration (tagged, opt-in).** Ping a known-up host with `count = 4` and assert loss/stats shape; ARP-resolve a host on the same /24; NDP-resolve a link-local neighbour; sweep a small range and assert alive count; assert that an ICMP-filtered host still reports alive via ARP.
9. **aarch64 appliance spike — do this FIRST (§13).**

---

## 12. Open decisions

**All decisions are now closed.** Items 1, 7 and 8 were settled on 2026-07-26; the reasoning is kept so a later reader can see what was traded away.

1. ~~Linux NDP transport~~ — **resolved: keep `AF_PACKET`**, as the draft assumed.
   The alternative was to send the NS from the raw `AF_INET6`/`IPPROTO_ICMPV6` socket and let the kernel build the IPv6 header, do the solicited-node → `33:33:*` mapping, and route, with hop limit 255 set via `setsockopt(IPV6_MULTICAST_HOPS/IPV6_UNICAST_HOPS, 255)`.
   *Why `AF_PACKET` wins:* the socket has to exist anyway for ARP, so the alternative saves no socket type, only one instance of it. It would cost `rawEvidence` for NS/NA — a capability §3.7 advertises and the fingerprinting layer consumes — and would make NA receipt share a socket with echo replies, which is more filtering, not less. The manual IPv6 header it avoids is now a solved problem: `Ipv6Header.forNeighborDiscovery` (step 2) pins hop limit 255 so it cannot be got wrong, and it is tested in both the accept and reject directions.
   *What was given up:* the kernel would have handled the multicast mapping for us. We do it in `Icmp6.solicitedNodeMulticast`/`solicitedNodeMac` instead, which is tested against RFC vectors.

2. ~~pcap ICMP: crafted vs OS-native~~ — **resolved.** Windows is pcap-only by constraint; ICMP is crafted over pcap. (Originally "on-link only"; off-link was added later, §8.7.)

3. ~~AF_PACKET socket count~~ — **resolved:** two typed sockets (`ETH_P_ARP`, `ETH_P_IPV6`), with ethertype read from `sll_protocol` in the recvfrom sockaddr.

4. ~~TTL on Linux~~ — **resolved:** `SOCK_RAW` on IPv4 gives the full IP header, so TTL and raw evidence come free. IPv6 hop limit stays `-1` in v1; no `recvmsg`.

5. ~~Gateway MAC for off-link ICMP over pcap~~ — **REOPENED AND IMPLEMENTED** (§8.7). The original resolution ("on-link only, no `iphlpapi`") assumed the binding would be costly. It is one function and one struct field, and the routing decision is delegated to Windows rather than reimplemented. Verified against a live internet path.

6. ~~Npcap absence behaviour~~ — **resolved:** detect at `open()`, fail with a clear message, never bundle.

7. **Send serialization mechanism — NEW, needs a call.**
   The v1 draft mandated a per-source `ReentrantLock` (§4.4). That mandate is **withdrawn**: no `ReentrantLock` goes into this module for now. The invariant it was buying still holds — one send in flight per fd / pcap handle — but the mechanism is open. Candidates:
   *(a)* a single-writer send thread per source fed by a queue, which makes the invariant structural — there is no lock a future call site can forget — and pairs with the one-reader-thread-per-source model already specced. It is also the only candidate that gives `maxPacketsPerSecond` (§3.2) somewhere real to live, since every packet on that descriptor passes through one place; a lock serializes sends but has no vantage point from which to pace them. Costs: it roughly doubles the thread count to `4 + 4N`, errno must be routed back onto the caller's future instead of thrown, and **the RTT timestamp must be written by the writer immediately before `sendto`, not by the caller when it builds the packet** — otherwise §6.5's `nanoTime` payload silently absorbs the queue delay, worst exactly when sweeping hard. A per-source `newSingleThreadExecutor` is a legitimate way to build this; the §4.3 shared pool is NOT, see §4.4;
   *(b)* zoxweb `StateMachine` dispatch (`publish` / `publishSync`), which is how concurrency is done elsewhere in no-sneak — **and which no longer costs anything on the dependency side**, since §4.3 already puts `zoxweb-core` on the compile path for `TaskUtil`. The zero-dependency objection to this option is withdrawn; judge it on fit alone;
   *(c)* plain `synchronized` on the per-source send method, which is the smallest thing that works if (a) proves like over-engineering.
   **RESOLVED: (c) `synchronized` on the one per-source send method.** Rationale: it is the smallest thing that satisfies the invariant, and the invariant is all that is required today. (a) doubles the thread count to `4 + 4N`, forces errno back through the caller's future, and introduces the RTT-stamping trap above — real cost for a benefit (a home for pacing) that nothing yet consumes. (b) is an event-dispatch mechanism being asked to do mutual exclusion, which is not what it is for.
   **This is explicitly revisitable, and cheaply.** Every send already funnels through one private method per source, so swapping in (a) touches that method and nothing else. **Do it the day `maxPacketsPerSecond` needs to be enforced globally** — §3.2 notes that N concurrent sweeps through one shared pinger emit N times the cap, and a writer thread is the only one of the three candidates with a vantage point to fix that.
   Note `synchronized` is NOT the withdrawn `ReentrantLock` mandate returning: the rule stands that no `ReentrantLock` enters this module, and the choke point remains a single method rather than locking sprinkled through the backends.

8. **JPMS or classpath — NEW, needs a call (§10.1).**
   The spec assumed a `module-info.java`. Two facts found since: `zoxweb-core` ships **no** `module-info` and **no** `Automatic-Module-Name`, so `requires` would bind to a jar-filename-derived module name; and **no other no-sneak module uses JPMS at all**. Declaring a module here buys compile-time encapsulation of the `platform.*` packages and costs a brittle `requires` plus a launcher flag that must match the actual load mode.
   **RESOLVED: no `module-info.java`.** `platform.*` stays internal by convention, and the flag is `--enable-native-access=ALL-UNNAMED` everywhere — launcher and Surefire `argLine` (§10.3). Confirmed empirically, and then re-confirmed the way that counts: the subsystem runs correctly under **jar-loader** with `--enable-native-access=ALL-UNNAMED` (§13.12), which is the production load path the earlier plain-`-cp` evidence could not reach. The named form would silently fail to grant access and produce the very warning it was meant to suppress.
   The one residual risk is that jar-loader might load this module as *named* in production, which would flip the correct flag. The spike prints which form applies on every run, so the appliance run re-checks it for free. Revisit only if the rest of no-sneak adopts JPMS.

---

## 13. Implementation order

**Ship Linux first.** The interfaces are common and the factory isolates the backends, so nothing is lost by sequencing — and a working Linux backend is a shippable appliance. macOS and Windows are dev-parity by §11 and can land in v1.1 without blocking anything.

**The split also gives a shippable midpoint that the single-interface design did not.** `ICMPPing` on Linux needs no interface, no `AF_PACKET`, no MAC, and no cache — it is two sockets and two reader threads. Land it whole, at step 6, before any L2 work exists.

1. ~~Public API types (§3) + `MacAddress`, `CidrRange`, `NicBinding` (with `LocalAddress` + `onLink`) — compile-only, no native.~~ — **DONE.** 20 types in `io.xlogistx.nosneak.net.common`, one public type per file, compiling at release 25 (bytecode major 69). `MacAddress`, `CidrRange`, `NicBinding`/`LocalAddress` and the `SweepOptions` validation are fully implemented; `PingResult.of` throws pending step 4 and `IpMacCache` throws pending step 3, both naming the step. See §13.2 for what the code added beyond the spec.
2. ~~Shared codecs (§5) + full unit tests (§11.1) — entirely host-independent, highest confidence per unit of effort.~~ — **DONE.** Six classes in `io.xlogistx.nosneak.net.codecs`, **94 codec tests** (the suite is larger now). `InternetChecksum`, `ArpPacket`, `Icmp4Echo`, `Icmp6`, `TtlDistance` as specced, plus `Ipv6Header` (see §13.3). Run with `mvn -o -pl no-sneak-net test -DskipTests=false`.
3. ~~`IpMacCache` (§9) + tests (§11.3).~~ — **DONE.** In `io.xlogistx.nosneak.net.util`, **26 tests**, suite now 120 green. Aging driven by an injected `Clock` so transitions are exact rather than sleep-based. See §13.4.
4. ~~`PingResult.of` aggregation + tests (§11.4) — still no native.~~ — **DONE.** 18 tests, suite now 138 green. **This is the last step before the §13.1 gate.** See §13.5 for the one case §3.3 did not cover.
5. ~~**aarch64 appliance spike (§13.1).** Gate: do not proceed past this point.~~ — **SUPERSEDED AND DELETED.** The spike existed to answer three questions before the backend was written; all three have since been answered by the backend itself running on real Linux hardware (§13.12): libc downcalls and `captureCallState("errno")` work, `AF_PACKET`/`SOCK_DGRAM` ARP round-trips with the ethertype read from `sll_protocol`, and `SOCK_RAW` delivers the full IPv4 header with a usable TTL. `LinuxSpike` is gone. **What is still owed is the aarch64 run**, not the spike — §2.3 argues every layout is architecture-independent, and that argument wants one measurement on the appliance.
6. ~~**Linux `ICMPPing`** — raw ICMP/ICMPv6 (§6.5), process-wide identifier allocation (§4.2), `SO_RCVTIMEO` shutdown (§4.4).~~ — **DONE and VERIFIED on live Linux hardware.** IPv4 echo returns real RTT and TTL; hop counts derive correctly. See §13.9 and §13.12.
7. ~~**Linux `HostDiscovery`** — `AF_PACKET` ARP (§6.4, bound to ifindex) → NDP → passive observe.~~ — **DONE and VERIFIED on live Linux hardware.** A `/24` sweep resolves every live host. The first run exposed four defects, one of them a property of real segments rather than of the code — see §13.12. IPv6/NDP is still unexercised: this segment has no v6 neighbours.
8. ~~`HostDiscoveryFactory`: the §3.8 wiring order, set-once injection, capability reporting, the `os.arch` precondition, and `Discovery.close()` ownership.~~ — **DONE and verified on live hardware** (Windows path; Linux/macOS raise a clear "not built yet" error naming the step). See §13.8.
9. ~~`sweep()` fan-out with bounded in-flight window and pps pacing, **including the no-pinger degraded path**; `discoverIpv6Segment()`.~~ — **DONE** in both backends; Windows verified live (a /27 finds 11 hosts in ~1 s). **`maxPacketsPerSecond` was validated but NOT enforced until a doc audit caught it** — the API accepted a rate cap and silently ignored it, which is worse than not offering one. Now enforced by `util.RateLimiter`; see §13.11.
10. Shutdown tests (§11.6) — verify before declaring the Linux backend done.
11. **Ship v1 (Linux).**
12. **PARTIALLY DONE — split by the §7.3 gate.** ICMP half (§7.5) is **written**: `DarwinIcmpPing`, unprivileged, `openIcmpOnly()` works. L2 half is **deliberately NOT written** — the neighbor-table ABI is `[VERIFY]` and the C probe must run on both Intel and Apple Silicon first. See §13.10.
13. ~~v1.1: `WindowsPcapBackend` — library lookup and Npcap detection (§8.1) → device enumeration (§8.3) → frame send (§8.4) → capture loop (§8.5) → **dual-interface role and multi-NIC ping selection (§8.6), last**, since it depends on everything above it.~~ — **DONE, built out of order and VERIFIED ON LIVE HARDWARE.** See §13.7. Factory wiring (step 8) still pending.
14. Full matrix validation.

### 13.1 The aarch64 spike — three items, half a day

Everything about privilege dropped out of this once the process runs as root. What remains:

1. libc downcalls resolve through `defaultLookup()`, and `Linker.Option.captureCallState("errno")` returns a readable errno on a deliberate `-1`.
2. `AF_PACKET` + `SOCK_DGRAM` ARP request round-trips against a known on-link host, with the **ethertype read from `sll_protocol` in the `recvfrom` sockaddr** and the source MAC from `sll_addr` (§6.4).
3. `SOCK_RAW`/`IPPROTO_ICMP` echo returns the **full IPv4 header** with a plausible TTL at offset 8 (§6.5).

Also confirm during this spike which `--enable-native-access` form applies given jar-loader's classloading (§10.2).

Each numbered step in §13 is independently compilable and testable. Do not proceed past step 5 without the spike passing.

### 13.2 What step 1 added beyond §3

Small conveniences the spec's sketches implied but did not spell out. All are pure Java with no behavioural surprises; listed so §3 and the code do not drift.

| Addition | Why |
|---|---|
| `MacAddress.LENGTH`, `MacAddress.BROADCAST` | the ARP builder needs both; a shared constant beats `new byte[]{-1,...}` at each call site |
| `PingProbe.TTL_UNAVAILABLE` (= `-1`) | names the sentinel, so `-1` is never mistaken for a distance (§5.5) |
| `PingProbe.replied(...)` / `.failed(...)` / `.hasTtl()` | the two shapes every backend constructs, minus six repeated arguments |
| `ResolveResult.resolved(...)` / `.notResolved(...)` / `.resolved()` | keeps `outcome` and `mac` from being set inconsistently |
| `HostRecord.alive()` | encodes the `mac.isPresent() \|\| icmpAlive` rule §3.4 states in prose, so consumers cannot get it wrong |
| `CidrRange.contains(...)` | the sweep needs a range test; `hosts()` cannot answer it for a `/64` |
| `NicBinding.supportsLayer2()` | the null-hardware-address check from §3.6, named once |
| `DiscoveryCapabilities.anyIcmp()` / `.anyLayer2()` | readability at call sites that only care whether a family works at all |
| `SweepOptions` compact-constructor validation | rejects `maxInFlight < 1`, `pingCount < 1`, non-positive `perHostTimeout` at construction rather than mid-sweep |
| `HostDiscoveryFactory.requireSupportedArch()` | the §2.3 `os.arch` precondition, callable before any backend exists |
| `Discovery.forName` returns `Optional<HostDiscovery>` | §3.8 sketched a bare return; an absent interface is an ordinary outcome, not an error |

Two contract decisions §3 left open, now settled in code and javadoc:

- **`CidrRange.hosts()` yields EVERY address in the block**, including the IPv4 network and broadcast addresses at `/30` and shorter. Filtering those is `sweep()` policy, not a property of the range — but the broadcast address must not be pinged, so whoever implements step 9 owns that skip.
- **Parsing never touches DNS.** `CidrRange` uses `InetAddress.ofLiteral` (JDK 22+), not `getByName`, so a hostname in a CIDR string is rejected rather than resolved. This is the same discipline §9.1 demands of `IpMacCache`.

### 13.3 What step 2 added beyond §5

**Package renamed `packet` → `codecs`.** §5's five classes are all present with the specced signatures.

**`Ipv6Header` is new and was required, not optional.** §11.1 mandates "NS/NA hop-limit-255 validation, both accept and reject cases", but the hop limit lives in the IPv6 header, which §5 never gave anyone to build or check. Both paths that inject below IP — Linux `AF_PACKET` NDP (§6.4) and Windows pcap (§8.4) — need it anyway. It carries `build`, `parse`, `forNeighborDiscovery` (hop limit pinned at 255 so a caller cannot get it wrong), and `isValidNeighborDiscovery` for the receive-side check.

Smaller additions, all pure:

| Addition | Why |
|---|---|
| `InternetChecksum.verify(...)` | the receiver's own test — a message carrying a correct checksum sums to zero. Used by `Icmp4Echo.parseReply` and by the tests as an oracle |
| `Icmp6.echoRequestUnchecksummed(...)` | encodes the §4.2 asymmetry in the API: Linux `SOCK_RAW`/`IPPROTO_ICMPV6` has the kernel compute the checksum, so computing it here too is wasted work |
| `Icmp6.parseSolicitation` / `NsView` | §5.4 gave only an NA parser, but §11.1 requires an NS round-trip |
| `Icmp6.neighborAdvertisement(...)`, `Icmp4Echo.reply(...)` | responder-side builders, needed to round-trip the parsers under test |
| `Icmp6.multicastMac(...)` | `ff02::1` all-nodes needs the generic `33:33` + low-32-bits mapping, not just the solicited-node form — `discoverIpv6Segment` uses it |
| `TtlDistance.initialTtl(...)` | the inferred initial value is worth reporting as evidence on its own, separately from the hop count |
| `ArpPacket.reply(...)`, `ArpView.isRequest/isReply` | symmetry with `isGratuitous`, and the reply builder is what makes the round-trip test possible |

Three decisions worth knowing before writing a backend against these:

- **`Icmp4Echo.parseReply` VERIFIES the checksum and returns empty on mismatch.** A corrupted reply can therefore never reach the §4.2 correlation map. `Icmp6`'s parsers deliberately do NOT, because the pseudo-header needs addresses the ICMPv6 message does not carry — the caller must verify with `InternetChecksum.icmpv6Checksum` where it has them.
- **`Icmp6.neighborSolicitation` derives its own destination.** The checksum must be computed against the solicited-node multicast address, not the target, so the builder computes it internally rather than accepting it — the two can then never disagree. A test asserts the checksum fails when verified against the target address.
- **Option walking terminates on malformed input.** An ND option length of zero would advance the walk by nothing; the parser stops rather than spinning, and an option claiming more bytes than are present is rejected instead of read past the end.

### 13.4 What step 3 settled in `IpMacCache`

Moved to `io.xlogistx.nosneak.net.util`. §9.1 fixed the contract but left the edges open; these are the answers, all covered by tests.

| Question §9.1 left open | Answer |
|---|---|
| Does a conflicting MAC get adopted, or rejected? | **Adopted, and counted.** The cache must track reality — DHCP and failover legitimately move an address — but `conflictCount` and `lastConflictAt` record it. "Record rather than silently overwrite" means *not silently*, not *not at all*. A non-zero count is what separates a lease change from spoofing downstream |
| Is replacing a `STALE` MAC a conflict? | **No.** The old binding had already aged out, so there is nothing to contradict. Only a currently-`REACHABLE` entry can conflict — exactly as §9.1 words it |
| How does `INCOMPLETE` age? | **Evicted at `reachableTtl`, never `STALE`.** A stale entry's value is the MAC it still carries; an unanswered solicitation has none, so there is nothing to go stale with |
| Does `markIncomplete` overwrite a known entry? | **No.** Soliciting an address we already hold a MAC for leaves it intact. The opposite would let a routine re-resolve blank the cache |
| Does eviction preserve conflict history? | **No.** History belongs to the entry, not to the address; a re-observed address starts clean with a fresh `firstSeen` |
| What does `snapshot()` do about aging? | **Projects, never mutates.** Entries are reported at the state they have reached and evicted ones are omitted, but nothing is reclaimed by reading. `size()` is therefore the raw stored count and `snapshot().size()` the live one |

Two implementation notes:

- **The `Clock` is injected** (`IpMacCache(expectedHosts, reachableTtl, staleTtl, clock)`), so §11.3's "compressed TTL" aging tests step time by hand instead of sleeping — the boundaries are asserted exactly, at the TTL and one second past it, and the suite stays fast. This is wall-clock time because `Entry` timestamps are `Instant`s, so a large NTP step backwards makes entries look younger; harmless for a cache, and unrelated to RTT measurement, which uses `System.nanoTime()` per §6.5.
- **One private `aged(entry, now)` projection** is shared by `get`, `observe`, `markIncomplete`, `sweepExpired` and `snapshot`, so no two paths can disagree about an entry's state at a given instant. Every mutation runs inside `compute`; the concurrency tests flip MACs from eight threads and assert conflicts are counted exactly, which a read-then-write upsert would fail.

### 13.5 The `PingResult.of` case §3.3 did not cover

§3.3 says flagged probes are excluded from the statistics when `probes.size() > 1`. It does not say what happens when **every** replied probe is flagged, which leaves the statistics with no samples at all.

Reporting `Duration.ZERO` there would be actively misleading: a consumer cannot distinguish it from the `received == 0` zero, so a host that answered in 500 ms would read as 0 ms. **The implementation falls back to using the flagged probes** — an inflated but real measurement, still marked `neighborResolutionPending` in the probe list for anyone who looks. Tested both ways: with a clean probe present the flagged ones are excluded; with none, they are used.

Two related boundaries, also tested:

- **A single flagged probe is measured, not excluded.** The exclusion is conditional on `probes.size() > 1` precisely because there is otherwise nothing left, and `pingCount` defaults to 1 (§3.5) — so the common sweep case would report no statistics at all if the rule were applied unconditionally.
- **Standard deviation is POPULATION, not sample** — divide by `n`, not `n - 1`. These are all the measurements taken, not a sample drawn from a larger set. The test pins an exact vector (10 ms and 30 ms give sigma 10 ms; the sample formula would give ~14.1 ms), so a future "fix" to `n - 1` fails loudly.

Arithmetic runs in nanoseconds throughout, so sub-millisecond RTTs on a local segment survive the averaging rather than rounding to zero.

### 13.6 What the step-5 gate proved, and why it is gone

`LinuxSpike` was diagnostic scaffolding for three questions that had to be answered before anyone
wrote the Linux backend. It was written, never run, and then overtaken: the backend itself now runs
against live hardware (§13.12), which answers all three more convincingly than a spike could.

| Original check | How it is now answered |
|---|---|
| 1 — `defaultLookup()` resolves libc and `captureCallState("errno")` returns a readable errno | Every `Libc` call path is exercised by `HostScan`; a deliberate `socket()` failure without root reports `EPERM` by name |
| 2 — `AF_PACKET`+`SOCK_DGRAM` ARP round-trips, ethertype from `sll_protocol`, source MAC from `sll_addr` | A `/24` sweep resolves every live host; captured `sockaddr_ll` reads `11 00 08 06 02 00 …`, ethertype `0x0806` off `sll_protocol` at offset 2 |
| 3 — `SOCK_RAW` delivers the FULL IPv4 header with a plausible TTL | `hostscan ping` reports TTL and hop counts; sweep populates `hopCount` |
| §12.8 — which `--enable-native-access` form applies | `ALL-UNNAMED`, confirmed under **jar-loader**, which is the case that actually matters and the one the spike could not reach |

Two results from the earlier Windows-box run still stand and were re-confirmed: layout sizes
(`sockaddr_in`=16, `sockaddr_ll`=20, `timeval`=16) are pinned by `LinuxLayoutTest`, and `ALL-UNNAMED`
is the right flag.

**Still owed: the aarch64 appliance run.** §2.3 argues every layout and constant is identical on
x86-64 and aarch64, and the evidence above is all from x86-64. That is an argument, not a
measurement. Run `hostscan list`, `resolve`, `ping` and a small `sweep` on the appliance and record
the result here.

### 13.7 Step 13 — the Windows backend, and what running it taught us

Built out of order (before steps 6-12) because the dev box is Windows with Npcap installed, making this the one backend testable during development. **Verified against live hardware**, not merely compiled: ARP resolve, cache hit, a 4-probe pipelined ping with TTL and raw evidence, off-link rejection, and idempotent close.

Classes, all in `io.xlogistx.nosneak.net.platform.windows`:

| Class | Role |
|---|---|
| `Pcap` | FFM bindings for all 11 `wpcap.dll` entry points, constants, `bpf_program` and `pcap_pkthdr` layouts, library loading |
| `PcapDevices` | `pcap_findalldevs` walk, and NIC-to-device matching **by IP address** (§8.3) |
| `PcapHandle` | one `pcap_t`: open + datalink check, BPF filter, injection, capture, teardown. Owns the §12.7 choke point |
| `WindowsPcapBackend` | `HostDiscovery` **and** `ICMPPing` on one object (§8.6) |

Two codecs §5 omitted had to be added, since pcap injects at L2 and so must build the whole packet: **`EthernetFrame`** (build/parse, and it unwraps 802.1Q on parse so a tagged segment cannot silently shift every offset) and **`Ipv4Header`** (build/parse with its own header checksum, separate from the ICMP one). Plus **`util.Identifiers`**, the process-wide ICMP identifier allocator §4.2 demands — both backends need it, so it is shared, not Windows-specific.

**Two bugs that only real hardware would have surfaced:**

- **The read timeout is an RTT floor, not just a shutdown knob.** libpcap batches captured packets until `to_ms` expires. At the draft's 200 ms, a gateway one hop away measured **~197 ms** with a 495 us spread — the spread was real, the 197 ms was the timeout. `READ_TIMEOUT_MS` is now **10 ms**, and the same path reports ~12 ms. An idle reader wakes 100 times a second rather than 5, which costs nothing measurable. Resolve latency fell from 202 ms to 16 ms for the same reason.
- **Closing a shared `Arena` under an active downcall throws.** The capture buffers live in an `Arena.ofShared()` (they must — §4.1, the reader thread touches them), and passing them to `pcap_next_ex` acquires that arena's session. Closing the handle before joining the reader produced `IllegalStateException: Session is acquired by 1 clients` and left the mapping unfreed. `close()` now stops and **joins the reader first**, then closes the handle, with a catch as belt-and-braces.

Deliberate limitations, honestly reported through `capabilities()`:

- **Injection is probed, not assumed.** `open()` sends one broadcast ARP for our own address — what duplicate address detection does, so it is unremarkable on the wire — purely to learn whether the driver accepts injected frames. A failure marks the binding **capture-only** (`icmpV4`/`activeArp` false, `passiveObservation` still true) instead of failing the open. This is the wireless case §8.6 warns about.
- **`discoverIpv6Segment` returns only cached and passively-learned neighbours.** Windows stacks generally do not answer multicast echo, so the active half would under-report badly; reporting what is known beats pretending.
- **`offLinkIcmp` is false and off-link targets complete with `NETWORK_UNREACHABLE`** — confirmed against `8.8.8.8`.

**Not yet done for this backend:** nothing — step 8 wired the factory and step 9's sweep is exercised live (§13.8).

### 13.8 Step 8 — factory wiring

`HostDiscoveryFactory` implements the §3.8 order for real, dispatching on `os.name` through a private `Platform` enum. **Verified end to end on live hardware**: two interfaces opened, both reporting the pinger through `icmpPing()`, `forTarget` picking the right one, and a `/29` sweep finding 5 hosts in ~1s with MACs, `icmpAlive` and hop counts.

Decisions the sketch in §3.8 did not pin down:

| Question | Answer |
|---|---|
| How does the factory inject the pinger uniformly, when Windows needs no injection at all? | A `default` no-op `HostDiscovery.attachPinger(ICMPPing)`, documented as factory-only SPI. Windows is its own pinger so the default is already correct; Linux and macOS will override it with a set-once assignment. No new public type, and no `instanceof` in the factory |
| Which backend becomes the pinger on Windows? | The first that can actually **inject**. A capture-only adapter (§8.6) would reject every send, so preferring it would break ping on a machine where another NIC works fine |
| What happens if interface 3 of 4 fails to open? | Everything already opened is closed before the exception propagates. A partially-built `Discovery` is never leaked |
| What do Linux and macOS do today? | Throw a `DiscoveryException` naming the missing backend **and the build-order step that will provide it**, rather than a bare `UnsupportedOperationException` |

Also added: `usableInterfaces()` (up, addressed, non-loopback — the usual argument to `open`) and `Discovery.forTarget(InetAddress)`, which picks the opened backend that has an address on-link.

**A live sweep exposed a safety gap §13.2 had left owed.** The `/29` run probed both `10.0.0.0` and the range's last address, because `CidrRange.hosts()` yields every address by design and nothing was skipping the local network and directed broadcast. **Pinging a directed broadcast is answered by every host on the segment at once** — amplification, and on a security appliance indistinguishable from an attack.

Fixed with `NicBinding.isNetworkOrBroadcast`, backed by `LocalAddress.networkAddress()` / `broadcastAddress()`, and sweep now skips those addresses. The test is deliberately against **the interface's own prefix, not the swept range's**: sweeping a `/29` inside a `/24` must not lose two legitimate hosts to a guess about where the subnet boundary is. Empty for IPv6, which has no broadcast, and for `/31` and `/32`, which designate no spare addresses. Eight unit tests pin it, so the rule is verified without ever having to actually ping a broadcast address.

### 13.9 Steps 6 and 7 — the Linux backend

> **RUN AND VERIFIED ON LIVE HARDWARE, 2026-07-27** (Linux x86-64, under jar-loader, as root). A `/24` sweep finds every live host with its MAC, hop count and RTT; `resolve` and `ping` both work. What that run exposed is in §13.12 — the code was structurally right and still failed on real hosts for a reason no amount of re-reading would have found. **The aarch64 appliance run is still owed** (§13.6).

| Class | Role |
|---|---|
| `platform.linux.Libc` | libc bindings, §6.2 constants, §6.3/§6.4 layouts, errno mapping, and the `setsockopt` helpers (`SO_RCVTIMEO`, `ICMP6_FILTER`, `PACKET_MR_PROMISC`) |
| `platform.linux.LinuxIcmpPing` | step 6 — two raw sockets, JVM-wide, no interface |
| `platform.linux.LinuxHostDiscovery` | step 7 — two `AF_PACKET`/`SOCK_DGRAM` sockets per NIC, bound to the ifindex |

`HostDiscoveryFactory` now wires Linux for real; only macOS still reports "not built yet".

**A wrong struct offset was caught before it ever ran, by a test that needs no Linux.** `sockaddr_ll` was declared with `sll_halen` at byte 9 and `sll_addr` at 10. The real offsets are **11 and 12**, because `sll_hatype` is a `short` and not a byte. Left uncorrected, every ARP send would have written its destination MAC two bytes early — over `sll_pkttype` — and the frame would have gone nowhere, while receives read the source MAC from the wrong offset. That is precisely the class of bug §11.2 exists to catch, and it argues for writing layout tests **before** the hardware is available rather than after.

`LinuxLayoutTest` now pins all five struct sizes, the `sockaddr_ll` offsets, the platform-varying constants (`AF_INET6` = 10 here, 30 on Darwin, 23 on Windows), the byte-order helpers, and the §4.7 errno mapping — 8 tests that run anywhere. To keep them runnable off-Linux, `Libc`'s downcall handles moved into a lazily-initialised nested `Handles` class; resolving libc symbols in the outer static initialiser would make the constants unreadable on a dev machine.

Design points worth knowing before the first appliance run:

- **The two ICMP families are deliberately asymmetric** (§4.2). IPv4 owns identifier *and* checksum and receives the full IP header, so TTL comes from offset 8 with no `recvmsg`. IPv6 owns the identifier but leaves the checksum **zero** — RFC 3542 makes it the kernel's job — and the kernel strips the IPv6 header, so hop limit is reported `-1`. An `ICMP6_FILTER` passing only type 129 keeps the reader from seeing every router advertisement on the segment.
- **Both `AF_PACKET` sockets are `bind()`-ed to the ifindex.** Unbound, they receive from every interface, and the eth0 instance would learn eth1's neighbours into a cache that claims to be per-binding.
- **NDP goes over `AF_PACKET` with a hand-built IPv6 header**, per the §12.1 decision, with `Ipv6Header.forNeighborDiscovery` pinning hop limit 255. Received NS/NA are rejected unless the hop limit is exactly 255 (RFC 4861 §7.1.1).
- **`neighborResolutionPending` is always false here**, as §4.6's table says it must be: the kernel owns the neighbor table and this module deliberately does not read it.
- **A frame-source/payload-SHA mismatch is recorded, not discarded.** The payload SHA is authoritative for ARP, but `sll_addr` disagreeing with it is spoofing evidence, so both are fed to the cache and its conflict counter notices.

### 13.10 Step 12 — macOS, split by the §7.3 gate

**This step is deliberately half-done, and the missing half is the point.** §7.3 marks the kernel neighbor-table ABI `[VERIFY]` and states plainly that it "must not be generated from memory". Writing it anyway would have produced code that compiles, looks right, and silently mis-parses the table — the exact failure the marker exists to prevent.

| Half | State |
|---|---|
| **ICMP (§7.1, §7.2, §7.5)** | **Written.** `DarwinLibc` + `DarwinIcmpPing`. Unprivileged, so it needs no root; `HostDiscoveryFactory.openIcmpOnly()` returns it on macOS |
| **L2 / neighbor table (§7.3, §7.4)** | **NOT written.** `openBackend` throws a `DiscoveryException` explaining the gate and naming the probe to run |

**The probe is written and ready**: `src/main/c/darwin_neighbor_abi_probe.c`.

```bash
cc -Wall -O0 -o probe src/main/c/darwin_neighbor_abi_probe.c && ./probe
```

It emits `sizeof(struct rt_msghdr)`, the offsets of `rtm_msglen`/`rtm_addrs`/`rtm_flags`, `sizeof(struct rt_metrics)`, the whole `sockaddr_dl` shape, an `SA_SIZE`/`ROUNDUP` table across sockaddr lengths, and `RTF_LLINFO` — then **dumps the live ARP and NDP tables in the same walk the Java parser will use**, so the output can be compared line-for-line against `arp -a`. Run it on **both Intel and Apple Silicon**, confirm they agree, record the numbers in §7.3, and only then write the parser.

Two behaviours of the ICMP half worth knowing, both from §4.2 and neither shared with any other backend:

- **Correlation is by SEQUENCE ALONE.** The kernel overwrites the identifier with the socket's own, so ours never reaches the wire. Consequently ONE sequence allocator is shared across both the v4 and v6 sockets rather than one each — with the identifier gone, a bare sequence collision between families would cross-match replies.
- **No TTL and no raw evidence.** The kernel strips the IP header, so `ttlAvailable` and `rawEvidence` are false and every probe reports `TTL_UNAVAILABLE`. Getting the TTL would need `IP_RECVTTL` + `recvmsg`, which §1 rules out.

The v4 reader **tolerates both receive shapes**: §7.5 says Darwin strips the IP header on a datagram ICMP socket, but that behaviour has varied across releases, so it parses at offset 0 first and retries past a plausible IPv4 header if that fails. Being wrong in either direction would mean every reply is silently dropped, and this cannot be tested from a Windows dev box.

`DarwinLayoutTest` pins the shapes that differ from Linux despite matching in size — the leading `sin_len` byte putting the family at **offset 1**, the padded 32-bit `tv_usec`, `AF_INET6` = 30, `SOL_SOCKET` = 0xFFFF, `SO_RCVTIMEO` = 0x1006 — plus the BSD errno numbers, with an explicit assertion that a *Linux* `EHOSTUNREACH` (113) does **not** map to `HOST_UNREACHABLE` here.

#### 13.10.1 First macOS run — it threw before it ever sent a packet

**2026-07-27, first execution on real macOS hardware: it failed at startup.** Two independent
all-or-nothing assumptions were in the way, both of which turned a *partially* available platform
into a *totally* unavailable one. Neither could have been caught on the Windows dev box, and neither
was a bug in the ICMP logic itself — which is precisely why they survived review.

**1. `HostScan` demanded the full wiring for every command.** `ping`, like `list`, opened
`HostDiscoveryFactory.open(usableInterfaces())`, which calls `Platform.MACOS.openBackend` — and that
throws the §7.3 gate exception by design. So the CLI died on macOS *deterministically, on every
command*, including the one command the platform fully supports. `openIcmpOnly()` worked the whole
time; nothing reachable from the CLI called it.
**Fixed:** `ping` and `list` now catch `DiscoveryException` from `open()` and fall back to
`openIcmpOnly()`, printing the reason. `resolve` and `sweep` still fail, correctly — they genuinely
need L2. The ownership rule is preserved on both paths: a `Discovery` closes the pinger it owns, a
standalone pinger closes itself.

**2. `DarwinIcmpPing.open` was all-or-nothing across the two ICMP families.** It opened the IPv4
socket, then the IPv6 socket, and *closed the working IPv4 socket and rethrew* if the second failed.
That is the wrong trade on this platform specifically: Darwin hands `SOCK_DGRAM`/`IPPROTO_ICMP` to
any user — that is why `/sbin/ping` no longer needs setuid — but the ICMPv6 equivalent is **not**
dependably unprivileged, and `ping6` has historically wanted root. One refused family took the whole
pinger down.
**Fixed:** the families open independently via a new non-throwing `DarwinLibc.trySocket`, and `open`
succeeds when **either** does. It throws only when *neither* is available, and then names **both**
errnos so the cause is diagnosable rather than guessed at. `EPROTONOSUPPORT` (43) and `EAFNOSUPPORT`
(47) were added to the BSD errno table for exactly this message.

> **`capabilities()` was returning literal `true` for both ICMP families**, which meant it could not
> express this state at all. It is now computed from the sockets that actually opened, and `ping()`
> on a family the kernel refused returns a failed `PingResult` carrying the mapped errno instead of
> sending on fd `-1` and letting every probe time out. This is the §2.1 honest-degradation rule; the
> record existed to say exactly this and was hardcoded past it.

The generalisable lesson, and it is the same one §13.11 drew about `maxPacketsPerSecond`: **a
capability record that is written as a literal cannot degrade.** If a field of
`DiscoveryCapabilities` is knowable only at runtime, it must be *computed* at construction, or the
honest-degradation contract is decoration.

`DarwinLibc.socket` was deleted in the process — `trySocket` replaces it and it had no other caller.

---

### 13.11 Sweep pacing — a parameter that was accepted and ignored

`SweepOptions.maxPacketsPerSecond` was **validated in the compact constructor and then never read**.
Both backends honoured only `maxInFlight`. A doc audit caught it, not a test — nothing asserted the
rate, so nothing failed.

That distinction matters: **`maxInFlight` bounds how many probes are OUTSTANDING; the rate cap bounds
how fast they leave.** They are different constraints. 256 outstanding probes that each complete in a
millisecond still emit a quarter of a million packets a second — precisely the "churns switch CAM
tables and trips customer IDS" outcome §3.5 calls not-optional-polish.

`util.RateLimiter` is a leaky bucket, deliberately **without burst capacity** — a burst allowance is
exactly what trips the IDS this exists to avoid. It computes the wake time under its lock but sleeps
outside it, so callers queue in arrival order without one sleeping thread holding the monitor. Both
sweeps acquire `1 + pingCount` permits per host before starting it.

The test that matters is `rateIsSharedAcrossThreads`: eight threads on one limiter must emit at the
configured rate **in aggregate**. A per-thread limiter would multiply the cap by the sweep's own
concurrency, which is the failure mode the whole mechanism exists to prevent.

> Worth generalising: an option that is parsed, validated, and then ignored is worse than an absent
> one, because the caller has been told it works. If a `SweepOptions` field is added, add the
> assertion that it changes behaviour at the same time.

---

## 14. `HostScan` — the CLI  **[IMPLEMENT]**

`io.xlogistx.nosneak.net.tools.HostScan`. Not part of the subsystem's contract, but it is how the
Windows backend was actually verified, and the fastest way for anyone to see this working.

```
hostscan list                  interfaces, backend devices, capabilities
hostscan resolve <ip|host>     ARP/NDP - the MAC, and where it came from
hostscan ping    <ip|host> [n] ICMP echo, pipelined (default 4)
hostscan sweep   <cidr>        ARP + ICMP across a range
```

Run it from an IDE (VM options `--enable-native-access=ALL-UNNAMED`), or from a terminal after
`mvn dependency:copy-dependencies -DoutputDirectory=target/deps` with
`-cp "target/classes;target/deps/*"`. A `hostscan.cmd` launcher existed briefly and was removed
as redundant with IDE run configurations.

Four things it does that are worth preserving if it is ever rewritten:

- **It resolves hostnames** — `InetAddress.getByName`, not `ofLiteral`. `ofLiteral` refuses DNS,
  which is correct for `CidrRange` and anywhere near `IpMacCache` (§9.1 forbids reverse DNS), and
  wrong for a CLI.
- **It explains an unreachable target BEFORE probing it**, rather than leaving the user with a bare
  `NETWORK_UNREACHABLE`. If `offLinkIcmp` is false and the target is off-link, it says why. Since
  §8.7 that path is rarely taken on Windows, but it still fires if `iphlpapi` will not load.
- **It refuses `resolve` on an off-link address with a category error, not a limitation.** ARP and
  NDP are link-local by definition; there is no such thing as the MAC of a host beyond the segment,
  and what you would get is the router's.
- **It calls `TaskUtil.close()` on exit.** zoxweb's pool threads are not daemons, so without it the
  process hangs after the work is done. This is legitimate ONLY because `HostScan` is the whole
  application and owns the process. **A library must never do this** — `Discovery.close()`
  deliberately leaves the executors alone (§4.3).

> If a launcher script is ever reintroduced on Windows: stage jars into a directory and use a
> wildcard classpath rather than reading one into a variable. The classpath is ~3 KB and `cmd`'s
> `set /p` silently truncates a line at about 1 KB, which surfaces as `NoClassDefFoundError` on a
> dependency that is demonstrably present.

---

### 13.12 First live Linux run — broadcast ARP is not universally delivered

The Linux backend's first real outing found four defects. Three were ordinary. The fourth is the
interesting one, because the code was **correct** and still did not work.

#### The symptom

`hostscan resolve 10.0.0.108` returned `TIMEOUT` after the full 3008 ms, while `ping 10.0.0.108`
answered in 2.2 ms and the kernel held a complete ARP entry for it. A `/24` sweep found 19 live
hosts but MACs for only 17. Reading the code proved nothing: the ARP payload, the `sockaddr_ll`
offsets, the ethertype byte order, the bind-to-ifindex and the reply demux were all right, and 17
other hosts resolved through that exact path.

#### What the wire showed

Instrumenting the send and capturing with `tcpdump` split the question in one run. Our requests were
leaving, correctly formed:

```
15:43:46.079  b0:7b:25:82:64:45 > ff:ff:ff:ff:ff:ff  Request who-has 10.0.0.108 tell 10.0.0.61
15:43:50.119  15:43:51.120  15:43:52.121   (the retries)
```

Nothing ever answered. Then, sending the **identical payload** to the host's known MAC instead of the
broadcast address:

```
BROADCAST ARP x3  ->  0 replies
UNICAST   ARP x3  ->  3 replies    oper=2 sha=94:e6:ba:4d:66:1b spa=10.0.0.108
```

**The host answers unicast ARP reliably and ignores broadcast ARP completely.** Access points buffer
broadcast and multicast against the DTIM interval and commonly suppress or proxy it, so a station can
be fully reachable by unicast while never seeing a broadcast frame. The same capture showed the
kernel sidestepping this by revalidating a known neighbour with a *unicast* probe
(`b0:7b:… > 42:25:47:35:03:ec Request who-has 10.0.0.1`) — which is why `arp` and `ping` worked
throughout and only our broadcast-only solicitation failed.

#### The fix, and why it needs a hint source

`sendArp` now sends unicast whenever a MAC hint exists, and broadcast on attempt 0 as well so a
*stale* hint cannot blind us to a host that has moved. Both frames on the first attempt matters more
than it looks: `sweep()`'s default one-second per-host budget allows **only** attempt 0, so a swept
host gets exactly one round to answer.

The hint comes from `IpMacCache` first and then `platform.linux.KernelNeighbors`. The cache alone
cannot bootstrap the case — the first ever resolve of a broadcast-suppressed host has nothing cached,
which is precisely when the hint is needed — so `/proc/net/arp` is read as a fallback. See the
narrowing note under §4.6 for why that does not contradict the "Linux does not read the kernel
neighbor table" rule: this is **aim, not evidence**. A hint only decides where to send a probe whose
answer we still verify on our own socket, and `ResolveSource` stays `ACTIVE_ARP`.

Result on the same segment: `resolve 10.0.0.108` went from `TIMEOUT` at 3008 ms to `RESOLVED` at
11 ms, and the sweep from 17-of-19 MACs to **19 of 19**, at the same wall time.

#### The other three

- **Resolving our own address timed out.** Nothing answers an ARP request for an address whose only
  owner is the host asking, so `10.0.0.61` burned the full budget every time. `NicBinding.
  isLocalAddress` plus a short-circuit returning `ResolveSource.LOCAL_INTERFACE` fixes it. Note this
  is distinct from `isOnLink`, which is true for the whole subnet including us.
- **A latent sweep hang.** `PendingResolve` gave each caller its own future and `completeAll`
  cleared the list after the reader had already removed the entry from `pending`. A `resolve()` that
  took the entry and added its future in that window was completed by nobody — the timeout task
  removes by key and finds nothing. In `sweep()` that future feeds `allOf`, so the sweep would hang
  forever rather than fail. Both backends now share ONE future per entry; `complete` is idempotent,
  so a late caller simply observes the finished result. **Windows had the identical bug** and got the
  identical fix.
- **Every send error was discarded.** `sendPacket` named the `sendto` result `ignored` and caught
  `Throwable` empty, and `readLoop` treated every negative `recvfrom` as an `EAGAIN` tick without
  checking errno. A rejected send, a dead reader and a silent host were therefore indistinguishable —
  all three produced a bare `TIMEOUT` at exactly the caller's budget, which is why this took a packet
  capture to diagnose at all. A failed send is now recorded and reported as `ResolveOutcome.ERROR`
  rather than `TIMEOUT`, and a non-`EAGAIN` receive error backs off instead of spinning a core.

> Two things generalise. First, **the honest-degradation rule has a diagnosability twin**: a failure
> that cannot be distinguished from a different failure is not honestly reported, however accurate
> the enum is. Second, and the reason the §13.1 gate mattered even though it was never run: this
> subsystem's assumptions are about *other people's networks*, and no amount of reading the code
> tests those. A `/24` sweep on a real segment found in one run what a careful reading had missed
> twice.

---

## Appendix A — Changes from the v1 draft

### A.0 Post-v2 revisions (applied in place)

Made after v2 was written, in this order. Anything below in A.1 that contradicts these is superseded.

- **Rehomed into no-sneak.** Root namespace `io.xlogistx.nosneak.net`, Maven module `no-sneak-net`; the public API sits in the `.common` subpackage, matching the house layout. The original `io.xlogistx.mgw.netdiscovery` is dead — it must not reappear in code, `module-info`, launch flags, or the pcap library system property.
- **`Probe` → `PingProbe`,** joining the `PingResult`/`PingError` family and clearing the collision with no-sneak-core's Tier-1 probe engine vocabulary.
- **`ReentrantLock` mandate withdrawn** (§4.4). The send-serialization invariant stands; the mechanism is open decision §12.7.
- **The single `HostDiscovery` interface split into `ICMPPing` + `HostDiscovery`** (§2.0, §3.1, §3.2). ICMP is host-scoped and unbound; ARP/NDP is per-interface. `HostDiscovery` holds the pinger as an optional, set-once, **borrowed** collaborator; `sweep()` degrades cleanly without one. Thread cost on an N-NIC Linux box drops from `4N` to `2 + 2N`.
- **`HostDiscoveryFactory` now returns a `Discovery` bundle** (§3.8) and owns the wiring order — it is the only thing that can make set-once injection safe, and the only owner of the pinger's lifetime. Added `openIcmpOnly()`.
- **Backend packages renamed** to `platform.linux` / `platform.darwin` / `platform.windows`. `darwin` rather than `macos` because `mac` reads as MAC address in this module; all FFM and pcap code lives in these three and nowhere else.
- **Windows implements both interfaces on one object** (§8.6), because pcap ping needs ARP and it is physically one handle, one device, one reader. Its pinger is constructed over the per-NIC backends and selects among them by on-link test. Off-link stays false; per-NIC send capability is probed, not assumed.
- **`NicBinding` addresses carry prefix lengths** (`LocalAddress`, §3.6) — without them "is this on-link" cannot be answered at all.
- **Thread pools are injected, not created.** `ScheduledExecutorService` + `ExecutorService` are constructor parameters defaulting to `TaskUtil.defaultTaskScheduler()` / `defaultTaskProcessor()` (§4.3). This puts `zoxweb-core` on the compile path, so the original "ZERO third-party Java libraries" rule became "house libraries only". The pools are borrowed and must never be closed by this module.
- **Dependencies settled and the pom written** (§10.3): `zoxweb-core`, `xlogistx-common`, `xlogistx-core`, JUnit — all parent-version-managed. Release 25 confirmed inherited: `xlogistx-mvn` compiles at `${jdk.version}` which defaults to 8, and the no-sneak root pom overrides it to 25. Do not set `maven.compiler.release` locally.
- **JPMS resolved** (§12.8): no `module-info.java`; `--enable-native-access=ALL-UNNAMED` everywhere, and the Surefire `argLine` is now set in the pom.
- **Off-link ICMP on Windows REVERSED and implemented** (§8.7). The v2 draft ruled it out to avoid an `iphlpapi` binding; that binding is one function (`GetBestRoute2`) and one struct field, so §1's non-goal and §12.5's resolution are both superseded. Off-link now works on all three platforms. Verified against a live internet path.
- **A CLI exists** (§14): `io.xlogistx.nosneak.net.tools.HostScan`, with a `hostscan.cmd` launcher. It is how the Windows backend was verified, and the fastest way to see the subsystem work.
- **Gaps closed:** ICMP identifiers must be unique per socket **process-wide**, not per instance (§4.2); `AF_PACKET` sockets must be scoped to their ifindex or they receive every interface's traffic (§6.4); link-local IPv6 ping needs a scope id (§3.1); sweep pacing is per-sweep, so N concurrent sweeps through one pinger emit N× the cap (§3.2).

### A.1 Original v1 → v2 changes

**Architecture**

- Two backends became **three**. macOS moved off pcap onto a native libc backend using the kernel neighbor table via `sysctl`; the v1 rationale ("libpcap ships preinstalled on macOS so routing macOS through pcap costs nothing") no longer applies. `Backend` enum is now `{LINUX_NATIVE, MACOS_NATIVE, WINDOWS_PCAP}`.
- Linux runs as **root**. The entire capabilities section (`AmbientCapabilities`, `setcap`, `ping_group_range`, the `AT_SECURE`/`LD_LIBRARY_PATH` hazard) is deleted, and the spike shrank from six items to three.
- Linux IPv4 ICMP moved from `SOCK_DGRAM` to `SOCK_RAW`, which resolves the TTL question without `recvmsg`.
- `pcap_pkthdr` went from three layouts to one; the `sockaddr` family table from three columns to two (Linux native, Windows pcap) plus a separate macOS table.
- Windows was **on-link only** in the v2 draft, avoiding an `iphlpapi` binding. That was later reversed — see §8.7.
- 32-bit is explicitly out of scope; all layouts select on `os.name` only, collapsing the layout-test matrix from six targets to three.

**API**

- `ping(target, timeout)` → `ping(target, count, timeout)`, pipelined, returning an aggregate `PingResult` with a `List<PingProbe>` and min/avg/max/stddev. `PingResult.of` is the sole construction path.
- `ResolveSource` split into `ResolveSource` (provenance: `ACTIVE_ARP`, `ACTIVE_NDP`, `PASSIVE`, `KERNEL_TABLE`, `CACHE_HIT`) and `ResolveOutcome` (`RESOLVED`, `TIMEOUT`, `UNSUPPORTED`, `ERROR`). `TIMEOUT` is no longer stored as a cache provenance.
- Added `PingError.HOST_UNREACHABLE`, mapped from `EHOSTUNREACH`.
- Added `discoverIpv6Segment()`; CIDR sweep is not a viable v6 discovery mechanism.
- Added `DiscoveryCapabilities.ttlAvailable` and `offLinkIcmp`.
- Added `SweepOptions.pingCount` (default 1) and `maxPacketsPerSecond`.
- `CidrRange.hostCount()` returns `BigInteger` — a `/64` overflows a signed long.
- All enums made `public`; one public top-level type per file.
- `observe()` javadoc corrected: on a switched network it sees broadcast ARP and multicast NS/NA, not unicast third-party replies, and needs promiscuous mode.
- `close()` completes pending futures **normally** with an error result, not exceptionally with an enum.

**Correctness fixes**

- `AF_PACKET`/`SOCK_DGRAM`: ethertype comes from `sll_protocol` in the sockaddr, not from the payload; source MAC from `sll_addr`; send ethertype from the destination sockaddr's `sll_protocol`.
- NS/NA **hop limit 255** requirement added (RFC 4861 §7.1.1) — silent total failure of IPv6 resolution if missed.
- `Arena.ofShared()` for instance lifetime; `ofConfined` would throw `WrongThreadException` on reader threads.
- `SO_RCVTIMEO` + `volatile running` shutdown pattern added — closing an fd does not wake a blocked `recvfrom`.
- `ConcurrentHashMap` pre-sizing corrected: the one-arg constructor already applies 1.5× headroom; the `n * 4 / 3` idiom is for `HashMap`.
- ARP/NDP established as the on-link liveness oracle; `icmpAlive` is a separate fact. Fixes the cold-neighbour first-probe drop, ICMP-filtered hosts, and sweep false negatives.
- Probe 0 flagged `neighborResolutionPending` and excluded from RTT statistics.
- Per-socket 16-bit sequence allocator shared across concurrent `ping()` calls.
- Retransmission policy added (ARP 3×1 s; NDP per RFC 4861).
- Missing pcap surface added: `PCAP_ERRBUF_SIZE`, `pcap_datalink` + `DLT_EN10MB` check, `pcap_freecode`, `bpf_program` layout, `PCAP_NETMASK_UNKNOWN`. `pcap_loop` dropped.
- `NicBinding.from` handles a null `getHardwareAddress()`.
- `IpMacCache` scoped per-binding (link-local scope-id collision); `markIncomplete` documented as informational, with dedupe moved to the in-flight future map; IP↔MAC conflict detection added.
- Checksum contract made explicit: zero the field first, return value is already complemented.
- Identifier/checksum ownership tabulated per path — they differ between Linux raw v4, Linux raw v6, macOS dgram, and Windows pcap.
- VLAN tagging noted for the pcap parser and BPF filter.