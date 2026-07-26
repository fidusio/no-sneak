# MGW Host Discovery Subsystem — Implementation Spec **v2**

**Target module:** `io.xlogistx.mgw.netdiscovery`
**Runtime:** OpenJDK 25 (FFM stable API). Source targets JDK 25.
**Architectures:** 64-bit only — `x86-64` and `aarch64`/`arm64`. 32-bit is out of scope and unsupported by the platform (FFM has no 32-bit linker implementation; `Linker.nativeLinker()` throws `UnsupportedOperationException`, and the Windows x86-32 port was removed in JDK 24 / JEP 479).
**Deployment:** ARM aarch64 Ubuntu 20.04 appliance, **running as root** (primary). Dev/secondary: macOS (Intel + Apple Silicon), Windows 10/11 (x86-64 + arm64).
**Dependencies:** ZERO third-party Java libraries. FFM (`java.lang.foreign`) only. Linux and macOS bind `libc`. Windows binds Npcap's `wpcap.dll`.

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
- A single public interface (`HostDiscovery`) with **three** platform implementations selected at runtime.

### Explicit non-goals (v1)

- No TCP/UDP port scanning here — that belongs to the existing Tier-1 probe engine. This subsystem answers "is this host alive, what is its MAC, and how far away is it."
- No integration into the NIO `Selector`. These sockets are native FDs / pcap handles serviced by dedicated blocking reader threads (§4.4).
- **No `recvmsg`/cmsg in v1.** The `CMSG_FIRSTHDR`/`CMSG_NXTHDR`/`CMSG_DATA` accessors are preprocessor macros, not exported symbols, so FFM cannot bind them; using control messages means reimplementing control-buffer alignment arithmetic in Java, with layouts that differ between Linux and Darwin. The cost of skipping it is IPv6 hop limit and macOS IPv4 TTL — see §3.6 `ttlAvailable`.
- **No off-link ICMP on Windows in v1.** pcap injects at L2 and bypasses OS routing, so an off-link target needs the default gateway's MAC, which needs the gateway's IP, which needs an `iphlpapi` binding. Windows v1 is on-link only and reports `offLinkIcmp == false`. Linux and macOS send through the kernel, which routes normally, so off-link works there.
- No GraalVM/native-image support. Dynamic FFM binding is incompatible with closed-world AOT — a hard constraint consistent with the rest of MGW.

---

## 2. Architecture overview

```
                       ┌─────────────────────────────┐
                       │        HostDiscovery         │  public interface
                       │  ping / resolve / sweep /    │
                       │  observe / cache accessor    │
                       └──────────────┬──────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
┌───────▼────────────┐   ┌────────────▼─────────┐   ┌───────────────▼──────┐
│ LinuxNativeBackend  │   │  MacOsNativeBackend   │   │  WindowsPcapBackend   │
│ libc via FFM, root  │   │  libc via FFM         │   │  wpcap.dll via FFM    │
│                     │   │                       │   │                       │
│ • SOCK_RAW  ICMP    │   │ • SOCK_DGRAM ICMP     │   │ • pcap_open_live      │
│ • SOCK_RAW  ICMPv6  │   │ • SOCK_DGRAM ICMPv6   │   │ • pcap_sendpacket     │
│ • AF_PACKET ARP     │   │ • sysctl(PF_ROUTE)    │   │ • pcap_next_ex loop   │
│ • AF_PACKET NDP     │   │   neighbor table read │   │ • BPF filter          │
│ • AF_PACKET passive │   │ • NO passive observe  │   │ • passive via promisc │
└───────┬────────────┘   └────────────┬─────────┘   └───────────────┬──────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │       IpMacCache         │  shared, pure Java
                         │  ConcurrentHashMap based │
                         └─────────────────────────┘
```

Shared, platform-independent code (used by **all three** backends):

- Packet codecs: ARP frame, ICMPv4 echo, ICMPv6 echo, ICMPv6 NS/NA — build + parse.
- Internet checksum (RFC 1071) and ICMPv6 pseudo-header checksum.
- `IpMacCache`.
- All public API types.
- The in-flight correlation map and timeout scheduler (§4.2, §4.3).

Platform-specific code lives **only** inside the three backends, behind `HostDiscovery`.

### 2.1 Capability matrix

|                     | Linux (root)              | macOS                     | Windows (Npcap)           |
|---------------------|---------------------------|---------------------------|---------------------------|
| Binding             | libc (FFM)                | libc (FFM)                | `wpcap.dll` (FFM)         |
| ICMPv4              | `SOCK_RAW`/`IPPROTO_ICMP` | `SOCK_DGRAM`/`IPPROTO_ICMP` | crafted over pcap       |
| ICMPv6              | `SOCK_RAW`/`IPPROTO_ICMPV6` | `SOCK_DGRAM`/`IPPROTO_ICMPV6` | crafted over pcap   |
| ARP                 | `AF_PACKET` + `SOCK_DGRAM`, crafted | kernel neighbor table via `sysctl` | crafted L2 frame |
| NDP                 | `AF_PACKET`, crafted NS   | kernel neighbor table via `sysctl` | crafted NS         |
| Passive observation | yes                       | **no**                    | yes (promisc)             |
| TTL available       | **yes** (IPv4 only)       | no                        | **yes**                   |
| Raw evidence        | yes                       | no                        | yes                       |
| Off-link ICMP       | yes (kernel routes)       | yes (kernel routes)       | **no** (v1)               |
| Privilege           | root                      | none                      | Npcap install             |

`DiscoveryCapabilities` (§3.6) is the runtime expression of this table. On the appliance every row is `true`; macOS is honestly degraded and the API must say so rather than silently returning empty results.

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

All public types live in package `io.xlogistx.mgw.netdiscovery`. **One public top-level type per file** — the code blocks below group related types for readability only.

### 3.1 Core interface

```java
package io.xlogistx.mgw.netdiscovery;

import java.io.Closeable;
import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Host discovery over ICMP/ICMPv6 (liveness) and ARP/NDP (L2 identity).
 * One instance is bound to exactly one network interface.
 * Implementations are created via {@link HostDiscoveryFactory}.
 *
 * Thread-safety: all methods are safe for concurrent use. Backends serialize
 * native sends internally; reads are serviced by dedicated reader threads.
 */
public interface HostDiscovery extends Closeable {

    /** The interface this instance is bound to. */
    NicBinding binding();

    /** What this backend can actually do on this interface (see §3.6). */
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
     * @param count   number of echo requests; must be >= 1
     * @param timeout PER-PROBE timeout, not a deadline for the whole call
     */
    CompletableFuture<PingResult> ping(InetAddress target, int count, Duration timeout);

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
     * Sweep a CIDR block. Fans out resolve()+ping() across the range with a
     * bounded in-flight window and a packet-rate cap. Results stream to onHost
     * as they arrive; the returned future completes when the whole range has
     * been swept or timed out.
     *
     * For ON-LINK targets, ARP/NDP is the liveness oracle: a host that answers
     * ARP is alive whether or not it answers ICMP. HostRecord.icmpAlive is a
     * separate fact from "this host exists".
     *
     * Rejects IPv6 ranges whose host count exceeds SweepOptions.maxHosts;
     * use discoverIpv6Segment() for v6 segments instead.
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

### 3.2 Ping result types

```java
package io.xlogistx.mgw.netdiscovery;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Aggregate result of a ping() call.
 *
 * NOTE: contains an array-bearing component list. Records give reference
 * identity for arrays, so PingResult and Probe are NOT value-comparable.
 * Do not use them as map keys or in set membership tests.
 */
public record PingResult(
        InetAddress target,
        int sent,
        int received,
        List<Probe> probes,
        Duration minRtt,          // Duration.ZERO when received == 0
        Duration avgRtt,
        Duration maxRtt,
        Duration stdDevRtt,       // population stddev over replied probes
        Optional<PingError> error) {

    public PingResult { probes = List.copyOf(probes); }

    public boolean reachable()   { return received > 0; }
    public double  lossPercent() { return sent == 0 ? 0.0 : 100.0 * (sent - received) / sent; }

    /**
     * THE ONLY construction path. Computes every aggregate from the probe list.
     *
     * Probes flagged neighborResolutionPending are EXCLUDED from min/avg/max/
     * stdDev when probes.size() > 1, because their RTT includes the ARP/NDP
     * round trip and is not a measurement of the target (§4.6). They still
     * count toward sent/received.
     */
    public static PingResult of(InetAddress target, List<Probe> probes, PingError err) { ... }
}
```

```java
package io.xlogistx.mgw.netdiscovery;

/** One echo request/reply pair. */
public record Probe(
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
package io.xlogistx.mgw.netdiscovery;

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

### 3.3 Resolution and record types

```java
package io.xlogistx.mgw.netdiscovery;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
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
package io.xlogistx.mgw.netdiscovery;

/** WHERE a MAC came from. This is provenance and is what IpMacCache stores. */
public enum ResolveSource {
    ACTIVE_ARP,     // we sent an ARP request and got a reply
    ACTIVE_NDP,     // we sent an NS and got an NA
    PASSIVE,        // observed on the segment, unsolicited
    KERNEL_TABLE,   // read out of the OS neighbor table (macOS backend)
    CACHE_HIT       // served from IpMacCache without touching the wire
}
```

```java
package io.xlogistx.mgw.netdiscovery;

/** WHAT HAPPENED. An outcome is not a source — keep these enums separate. */
public enum ResolveOutcome { RESOLVED, TIMEOUT, UNSUPPORTED, ERROR }
```

```java
package io.xlogistx.mgw.netdiscovery;

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
package io.xlogistx.mgw.netdiscovery;

/** Passive observation of a neighbour on the segment. */
public record ObservedNeighbor(
        java.net.InetAddress ip,
        MacAddress mac,
        ObservationKind kind,
        java.time.Instant seenAt) {
}
```

```java
package io.xlogistx.mgw.netdiscovery;

public enum ObservationKind { ARP_REQUEST, ARP_REPLY, GRATUITOUS_ARP, NDP_NS, NDP_NA }
```

```java
package io.xlogistx.mgw.netdiscovery;

public record SweepSummary(
        int total,
        int alive,             // mac resolved OR icmp alive
        int macsResolved,
        int icmpAlive,
        java.time.Duration elapsed) {
}
```

### 3.4 Value types

```java
package io.xlogistx.mgw.netdiscovery;

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
package io.xlogistx.mgw.netdiscovery;

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
package io.xlogistx.mgw.netdiscovery;

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

### 3.5 NIC binding

```java
package io.xlogistx.mgw.netdiscovery;

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
        List<InetAddress> ipv4,
        List<InetAddress> ipv6,   // include link-local for NDP
        int mtu) {

    public NicBinding {
        ipv4 = List.copyOf(ipv4);
        ipv6 = List.copyOf(ipv6);
    }

    /**
     * Build from a java.net.NetworkInterface plus a backend device-name resolver.
     *
     * IMPORTANT: nif.getHardwareAddress() returns null for loopback and some
     * virtual interfaces. Do NOT feed null into the MacAddress constructor — it
     * throws. Leave hardwareAddress null and let the factory reject the binding
     * for L2 operations while still permitting ICMP.
     */
    public static NicBinding from(java.net.NetworkInterface nif,
                                  java.util.function.Function<java.net.NetworkInterface,String> deviceNameResolver) {
        ...
    }
}
```

### 3.6 Capabilities

```java
package io.xlogistx.mgw.netdiscovery;

/** What the running backend can actually do on this interface. */
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

### 3.7 Factory, subscription, exception

Three separate files.

```java
package io.xlogistx.mgw.netdiscovery;

import java.net.NetworkInterface;

public final class HostDiscoveryFactory {
    /**
     * Select backend by os.name, bind to the given interface, start reader threads.
     * Fails fast if os.arch is outside {amd64, x86_64, aarch64, arm64}.
     */
    public static HostDiscovery open(NetworkInterface nif) throws DiscoveryException { ... }

    /** Convenience: pick the interface owning a given local address. */
    public static HostDiscovery openForLocalAddress(java.net.InetAddress local)
            throws DiscoveryException { ... }
}
```

```java
package io.xlogistx.mgw.netdiscovery;

public interface Subscription extends java.io.Closeable {
    @Override void close();   // narrowed: does not throw IOException
}
```

```java
package io.xlogistx.mgw.netdiscovery;

public final class DiscoveryException extends Exception {
    public DiscoveryException(String msg) { super(msg); }
    public DiscoveryException(String msg, Throwable cause) { super(msg, cause); }
}
```

---

## 4. Backend contract (all three implementations)

### 4.1 Lifecycle

- Construction binds one interface and starts reader thread(s). May fail with `DiscoveryException` (missing privilege, pcap not loadable, interface down, no hardware address for an L2 request).
- `close()` signals reader threads, closes native FDs / pcap handles, closes arenas, and **completes pending futures normally** with a result carrying `PingError.IO` / `ResolveOutcome.ERROR`. Do not complete exceptionally — that contradicts the "never throws for an unreachable host" contract in §3.1.
- **Arenas:** use `Arena.ofShared()` for instance-lifetime native allocations. `Arena.ofConfined()` is single-thread-owned; reader threads touching segments allocated by the constructor thread would throw `WrongThreadException`. Per-send confined arenas are fine, because sends occur on the calling thread under the per-source lock.

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

A `ping(target, count, timeout)` call registers **`count`** in-flight entries and **`count`** scheduled timeouts, not one.

### 4.3 Timeouts

A single shared `ScheduledExecutorService` (daemon threads) arms per-probe timeouts. On fire: remove the in-flight entry, record the probe as `replied=false, error=TIMEOUT`, and complete the aggregate future once all probes for that call have settled.

**Never block a reader thread on a user callback.** Dispatch `Consumer<HostRecord>` and `Consumer<ObservedNeighbor>` callbacks on a separate executor.

### 4.4 Threading model (replaces the NIO selector for this subsystem)

- One **reader thread per receive source**:
    - Linux: one per raw ICMP socket, one per raw ICMPv6 socket, one per `AF_PACKET` socket.
    - macOS: one per dgram ICMP socket, one per dgram ICMPv6 socket, plus a scheduled neighbor-table poller (not a blocking reader).
    - Windows: one thread running `pcap_next_ex`, demultiplexing by ethertype.
- Reader threads are **blocking**. Do not wire these FDs into `java.nio.channels.Selector` — arbitrary native FDs cannot be registered, and pcap handles are not portably selectable. This is the deliberate transport divergence from the TCP probe engine: per-target FSMs are driven off the reader-thread dispatch queue, not off selector readiness.
- Sends are serialized behind a per-source `ReentrantLock`, consistent with MGW's public-locks / `0`-suffixed-internal convention.

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
2. **Probe 0's RTT is inflated even when it succeeds**, having queued behind the ARP round trip. Set `Probe.neighborResolutionPending` when the backend knows resolution was in flight at send time, and exclude those probes from `min/avg/max/stdDev` when `count > 1` (§3.2).

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

Package `io.xlogistx.mgw.netdiscovery.packet`. Pure Java, no FFM. Operates on `byte[]` / `ByteBuffer`. Big-endian (network order) throughout.

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

Package `io.xlogistx.mgw.netdiscovery.linux`. Binds `libc` via `Linker.nativeLinker().defaultLookup()`.

**Privilege model: the MGW process runs as root on the appliance.** `SOCK_RAW` is therefore unconditionally available. There is no capability grant, no `setcap`, no `net.ipv4.ping_group_range` dependency, and no `AT_SECURE`/`LD_LIBRARY_PATH` interaction to worry about.

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

### 6.5 ICMP path (Linux, root)

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

### 6.6 Interface summary (Linux)

| Operation | Socket |
|-----------|--------|
| ICMPv4 echo | `AF_INET`, `SOCK_RAW`, `IPPROTO_ICMP` |
| ICMPv6 echo | `AF_INET6`, `SOCK_RAW`, `IPPROTO_ICMPV6` + `ICMP6_FILTER` |
| ARP send/recv | `AF_PACKET`, `SOCK_DGRAM`, `htons(ETH_P_ARP)` |
| NDP send/recv | `AF_PACKET`, `SOCK_DGRAM`, `htons(ETH_P_IPV6)` |
| Passive observe | the same two `AF_PACKET` sockets + `PACKET_MR_PROMISC` |

---

## 7. macOS native backend  **[IMPLEMENT]**

Package `io.xlogistx.mgw.netdiscovery.macos`. Binds `libc` via `Linker.nativeLinker().defaultLookup()`. No pcap, no BPF, no `ioctl`.

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

### 7.5 ICMP path (macOS)

- **IPv4:** `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` — unprivileged on Darwin, as on Linux. The kernel computes the checksum and **rewrites the identifier**; read it back from the reply and correlate on sequence (§4.2).
- **IPv6:** `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)`. Same model. Note `AF_INET6 = 30`.
- The kernel strips the IP header, so **TTL is unavailable**: report `ttlOrHopLimit = -1` and `ttlAvailable == false`. Obtaining it would require `IP_RECVTTL` + `recvmsg`, which is out of scope (§1).
- Kernel routing applies, so off-link targets work.

---

## 8. Windows pcap backend  **[IMPLEMENT]**

Package `io.xlogistx.mgw.netdiscovery.pcap`. Binds Npcap's `wpcap.dll` via FFM. This backend crafts and captures **full L2 frames** — pcap operates below IP.

### 8.1 Library lookup and Npcap detection  **[REFERENCE]**

`wpcap.dll` installs to `%SystemRoot%\System32\Npcap\`, which is **not** on the default DLL search path.

> **Loader hazard:** `wpcap.dll` depends on `Packet.dll` in the same directory. Loading `wpcap.dll` by absolute path without first adding that directory to the DLL search path fails at dependency resolution with an unhelpful error. Either require Npcap's WinPcap-compatibility install mode (which places the DLLs in `System32`), or set the DLL directory before the lookup.

Make the path configurable via the system property `io.xlogistx.mgw.pcap.lib`.

**If Npcap is absent, fail at `HostDiscoveryFactory.open()`** with a `DiscoveryException` naming the missing library and the install URL. Do not fail obscurely at first use, and do not bundle the installer.

> **Licensing.** The free Npcap edition is limited to installation on five systems and explicitly does not permit redistribution within a product; redistribution requires an Npcap OEM license from the Nmap Project. Since Windows is dev-parity only (§11), five developer machines is within the free terms — but this must be revisited before any Windows MGW build is shipped to a customer. Do not treat the free tier as covering distribution.

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

Device names have nothing in common with Java's (`\Device\NPF_{GUID}` vs whatever `NetworkInterface.getName()` returns). **Never hardcode, never pattern-match the name.** Enumerate with `pcap_findalldevs`, walk the `pcap_if_t` linked list, and match each device to the target `NetworkInterface` **by IP address**, comparing `pcap_addr` entries against `NicBinding.ipv4`/`ipv6`. Store the match as `NicBinding.backendDeviceName`.

`pcap_if_t` fields needed: `next` (ADDRESS at offset 0), `name` (ADDRESS at offset 8), `description`, `addresses` (ADDRESS). `pcap_addr`: `next`, `addr` (`sockaddr*`). This is pointer-chasing via `MemorySegment.get(ADDRESS, off)` + `reinterpret`.

Windows `sockaddr` shape for that parse — **one column now that macOS is off this backend**:

```
             AF_INET   AF_INET6   sockaddr_in shape
Windows      2         23         family = 2 bytes @ 0, no sin_len
```

### 8.4 Sending frames (pcap builds nothing)

Every send is a **complete Ethernet frame**:

- **ARP:** `dstMAC = broadcast`, `srcMAC = ourMAC`, `ethertype = 0x0806`, then the 28-byte ARP payload.
- **ICMPv4 echo:** `dstMAC = target's MAC` (resolve by ARP first — **on-link only in v1**, §1), `ethertype = 0x0800`, IPv4 header (TTL, protocol = 1, IP ID, src/dst, header checksum), then the ICMP echo. **We compute both the IPv4 header checksum and the ICMP checksum.**
- **ICMPv6 echo / NS:** `ethertype = 0x86DD`, IPv6 header (**hop limit 255 for NS/NA**, next header = 58), then ICMPv6 with pseudo-header checksum. NS destination MAC is the solicited-node multicast MAC.

Because injection bypasses OS routing entirely, an off-link destination would need the default gateway's MAC, hence its IP, hence an `iphlpapi` binding. **v1 is on-link only**: `capabilities().offLinkIcmp()` returns false and off-link targets complete with `PingError.NETWORK_UNREACHABLE`.

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

---

## 9. IpMacCache  **[IMPLEMENT]**

Package `io.xlogistx.mgw.netdiscovery`. Pure Java. Shared by all three backends.

### 9.1 Contract

- Keyed by `InetAddress` (v4 and v6). Value carries MAC, first-seen, last-seen, state, provenance.
- **One cache instance per `HostDiscovery` binding.** `Inet6Address.equals()` compares the 16 address bytes and does not consider the scope id, so `fe80::1%eth0` and `fe80::1%eth1` collide. Per-binding ownership makes that harmless. If a cross-interface cache is ever wanted, the key must become `(ifIndex, address)`.
- Never call `InetAddress.getHostName()` anywhere near this class — it triggers reverse DNS. `equals`, `hashCode`, and `toString` do not.
- Thread-safe via `ConcurrentHashMap` atomic operations (`compute`, `merge`). No synchronized wrappers. Upserts must use `compute`/`merge` — `getOrDefault` is a read-only fallback and cannot substitute for an atomic insert.
- Aging: entries expire after a configurable TTL since `lastSeen`. Lazy expiry on read, plus an optional scheduled daemon sweep.
- Provenance: `ResolveSource` (§3.3). Passive and kernel-table updates refresh `lastSeen` and may upgrade state.
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

### 10.1 `module-info.java`

```java
module io.xlogistx.mgw.netdiscovery {
    exports io.xlogistx.mgw.netdiscovery;
    exports io.xlogistx.mgw.netdiscovery.packet;
    // linux / macos / pcap subpackages are internal — do not export
}
```

`requires java.base` is implicit; omit it.

### 10.2 Native access

FFM restricted methods require enabling native access at launch:

```
java --enable-native-access=io.xlogistx.mgw.netdiscovery ...
```

Without it: warnings on JDK 25, hard failure in a future release. This is a **JVM module-access check and is orthogonal to OS privilege** — running as root does not satisfy it.

> **jar-loader interaction:** the flag above only applies if this module is genuinely loaded as a named module. If MGW's custom classloader ends up placing it on the classpath, the correct flag is `--enable-native-access=ALL-UNNAMED`. Confirm which applies during the §12 spike and pin it in the launcher script; do not leave it to chance.

### 10.3 Maven

- New module under the MGW reactor.
- No third-party `<dependency>` entries. JUnit 5, test scope only.
- Surefire `argLine`: `--enable-native-access=io.xlogistx.mgw.netdiscovery`.
- Do not attempt native-image; document the closed-world incompatibility in the module README.
- Document the 64-bit-only constraint in the README as a **platform** constraint, not a preference: FFM has no 32-bit linker implementation, and the Windows x86-32 port was removed in JDK 24.

---

## 11. Testing & validation plan  **[IMPLEMENT]**

The appliance (Linux/aarch64) is the gate. macOS and Windows are dev-parity.

1. **Codec unit tests (host-independent, run everywhere).** Build/parse round-trips for ARP, ICMPv4, ICMPv6 echo, NS/NA. Known-good RFC 1071 checksum vectors and an ICMPv6 pseudo-header vector. Solicited-node multicast and `33:33:ff:*` MAC derivation vectors. Gratuitous-ARP classification (SPA == TPA). NS/NA hop-limit-255 validation, both accept and reject cases. `TtlDistance.hopCount` boundary cases (64/128/255, and observed values just below each).
2. **Layout tests — three targets, not six.** Every layout is selected on `os.name` only (§2.3), so the matrix collapses. Assert: Linux `sockaddr_in`=16, `sockaddr_in6`=28, `sockaddr_ll`=20, `timeval`=16, `packet_mreq`=16; macOS `sockaddr_in`=16 with `sin_family` at offset **1**, `sockaddr_in6`=28, `timeval`=16; Windows `pcap_pkthdr`=16 with `caplen` at offset **8**, `bpf_program`=16.
3. **Cache tests.** Upsert paths use `compute`/`merge`; aging transitions `INCOMPLETE → REACHABLE → STALE → evicted` with a compressed TTL; conflict detection increments rather than silently overwriting; concurrent `observe()` under contention.
4. **Ping aggregation tests (no network).** Drive `PingResult.of` with synthetic probe lists: all-replied, all-lost, mixed, `count == 1`, and the `neighborResolutionPending` exclusion — assert that probe 0 counts toward `sent`/`received` but not toward `min`/`avg`/`stdDev` when `count > 1`.
5. **Loopback / self tests.** Ping `127.0.0.1` and `::1`; confirm `NicBinding.from` tolerates a null hardware address on loopback rather than throwing.
6. **Shutdown tests.** Assert `close()` returns promptly while reader threads are blocked in `recvfrom` — this is the `SO_RCVTIMEO` path (§4.4) and it is the one that silently hangs if implemented wrong. Assert pending futures complete normally with an error result, not exceptionally.
7. **Live integration (tagged, opt-in).** Ping a known-up host with `count = 4` and assert loss/stats shape; ARP-resolve a host on the same /24; NDP-resolve a link-local neighbour; sweep a small range and assert alive count; assert that an ICMP-filtered host still reports alive via ARP.
8. **aarch64 appliance spike — do this FIRST (§13).**

---

## 12. Open decisions

Everything from the v1 draft is now resolved except the first item, which is new.

1. **Linux NDP transport — NEW, needs a call.**
   As specced in §6.4, NDP goes over `AF_PACKET` with a hand-built IPv6 header. Since the process runs as root, an alternative exists: send the NS from the raw `AF_INET6`/`IPPROTO_ICMPV6` socket, letting the kernel build the IPv6 header, perform the solicited-node multicast → `33:33:*` MAC mapping, and route. Hop limit 255 is then set with `setsockopt(IPV6_MULTICAST_HOPS/IPV6_UNICAST_HOPS, 255)` instead of hand-written into a header.
   *For:* deletes all manual IPv6 header construction and its checksum, and removes one of the two `AF_PACKET` sockets. *Against:* loses the full-frame raw evidence for NS/NA, and NA receipt then shares the ICMPv6 socket with echo replies (manageable via `ICMP6_FILTER`).
   **Default assumed: keep `AF_PACKET`** as specced, for raw-evidence uniformity. Confirm or flip. `AF_PACKET` is required for ARP either way.

2. ~~pcap ICMP: crafted vs OS-native~~ — **resolved.** Windows is pcap-only by constraint; ICMP is crafted over pcap, on-link only in v1.

3. ~~AF_PACKET socket count~~ — **resolved:** two typed sockets (`ETH_P_ARP`, `ETH_P_IPV6`), with ethertype read from `sll_protocol` in the recvfrom sockaddr.

4. ~~TTL on Linux~~ — **resolved:** `SOCK_RAW` on IPv4 gives the full IP header, so TTL and raw evidence come free. IPv6 hop limit stays `-1` in v1; no `recvmsg`.

5. ~~Gateway MAC for off-link ICMP over pcap~~ — **resolved:** Windows v1 is on-link only, so no gateway resolution and no `iphlpapi` binding.

6. ~~Npcap absence behaviour~~ — **resolved:** detect at `open()`, fail with a clear message, never bundle.

---

## 13. Implementation order

**Ship Linux first.** The interface is common and the factory pattern already isolates the backends, so nothing is lost by sequencing — and a working Linux backend is a shippable appliance. macOS and Windows are dev-parity by §11 and can land in v1.1 without blocking anything.

1. Public API types (§3) + `MacAddress`, `CidrRange`, `NicBinding` — compile-only, no native.
2. Shared codecs (§5) + full unit tests (§11.1) — entirely host-independent, highest confidence per unit of effort.
3. `IpMacCache` (§9) + tests (§11.3).
4. `PingResult.of` aggregation + tests (§11.4) — still no native.
5. **aarch64 appliance spike (§13.1).** Gate: do not proceed past this point.
6. `LinuxNativeBackend`: raw ICMP path (§6.5) → `AF_PACKET` ARP (§6.4) → NDP → passive observe.
7. `HostDiscoveryFactory` wiring + capability reporting + the `os.arch` precondition.
8. `sweep()` fan-out with bounded in-flight window and pps pacing; `discoverIpv6Segment()`.
9. Shutdown tests (§11.6) — verify before declaring the Linux backend done.
10. **Ship v1 (Linux).**
11. v1.1: `MacOsNativeBackend` — run the §7.3 C probe on both Intel and Apple Silicon **before** writing any of it.
12. v1.1: `WindowsPcapBackend` — library lookup and Npcap detection (§8.1) → device enumeration (§8.3) → frame send (§8.4) → capture loop (§8.5).
13. Full matrix validation.

### 13.1 The aarch64 spike — three items, half a day

Everything about privilege dropped out of this once the process runs as root. What remains:

1. libc downcalls resolve through `defaultLookup()`, and `Linker.Option.captureCallState("errno")` returns a readable errno on a deliberate `-1`.
2. `AF_PACKET` + `SOCK_DGRAM` ARP request round-trips against a known on-link host, with the **ethertype read from `sll_protocol` in the `recvfrom` sockaddr** and the source MAC from `sll_addr` (§6.4).
3. `SOCK_RAW`/`IPPROTO_ICMP` echo returns the **full IPv4 header** with a plausible TTL at offset 8 (§6.5).

Also confirm during this spike which `--enable-native-access` form applies given jar-loader's classloading (§10.2).

Each numbered step in §13 is independently compilable and testable. Do not proceed past step 5 without the spike passing.

---

## Appendix A — Changes from the v1 draft

**Architecture**

- Two backends became **three**. macOS moved off pcap onto a native libc backend using the kernel neighbor table via `sysctl`; the v1 rationale ("libpcap ships preinstalled on macOS so routing macOS through pcap costs nothing") no longer applies. `Backend` enum is now `{LINUX_NATIVE, MACOS_NATIVE, WINDOWS_PCAP}`.
- Linux runs as **root**. The entire capabilities section (`AmbientCapabilities`, `setcap`, `ping_group_range`, the `AT_SECURE`/`LD_LIBRARY_PATH` hazard) is deleted, and the spike shrank from six items to three.
- Linux IPv4 ICMP moved from `SOCK_DGRAM` to `SOCK_RAW`, which resolves the TTL question without `recvmsg`.
- `pcap_pkthdr` went from three layouts to one; the `sockaddr` family table from three columns to two (Linux native, Windows pcap) plus a separate macOS table.
- Windows is **on-link only** in v1, avoiding an `iphlpapi` binding.
- 32-bit is explicitly out of scope; all layouts select on `os.name` only, collapsing the layout-test matrix from six targets to three.

**API**

- `ping(target, timeout)` → `ping(target, count, timeout)`, pipelined, returning an aggregate `PingResult` with a `List<Probe>` and min/avg/max/stddev. `PingResult.of` is the sole construction path.
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