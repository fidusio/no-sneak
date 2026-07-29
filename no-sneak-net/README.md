# no-sneak-net

Host discovery: **is this host alive, what is its MAC, and how far away is it.** ICMP/ICMPv6 echo
for liveness, ARP and NDP for layer-2 identity, an aging IP↔MAC cache, and CIDR sweep — on
**JDK 25 FFM**, with no packet library at all.

Deliberately *not* here: port scanning and service identification. Those belong to `no-sneak-core`'s
Tier-1 probe engine. This module answers the question that comes before them.

> **`CLAUDE.md` in this directory is the authoritative spec**, and it is far more detailed than this
> file — ABI tables, the reasoning behind every design decision, and the build order. Read it before
> changing anything. Section numbers referenced below (§4.2, §7.3, …) are its sections.

## Status

| Step                                              | State                                                                                                                               |
|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| Public API, codecs, cache, ping aggregation       | **done**, 192 tests green                                                                                                           |
| Windows (Npcap/pcap) backend                      | **done and verified on live hardware**                                                                                              |
| Windows off-link routing (`iphlpapi`)             | **done and verified against a live internet path**                                                                                  |
| Factory wiring + `HostScan` CLI                   | **done and verified on live hardware**                                                                                              |
| Linux ICMP (`SOCK_RAW`, v4 + TTL)                 | **done and verified on live hardware — x86-64 and aarch64**                                                                         |
| Linux ARP (`AF_PACKET`)                           | **done and verified on live hardware — x86-64 and aarch64**                                                                         |
| Linux passive IPv4 learning (`ETH_P_IP`)          | **done and verified** — resolves hosts the kernel itself cannot reach                                                               |
| Windows unicast-ARP retry + `GetIpNetEntry2` hint | **done and verified on live hardware** — resolves a host that ignores broadcast ARP (§13.16)                                        |
| Windows passive learning (`ip`/`ip6` + NDP NS)    | **done and verified on live hardware** — finds hosts no sweep reaches (§13.17)                                                      |
| Linux IPv6 / NDP                                  | **written, never exercised on a wire** — no v6 neighbours on the test segment                                                       |
| macOS ICMP                                        | **done and verified on live hardware — Apple Silicon (arm64)** — on/off-link v4, v6, link-local                                     |
| macOS ARP/NDP                                     | **done and verified on live hardware — Apple Silicon (arm64)** — ARP, sweep, passive observe over libpcap, wired and Wi-Fi (§13.20) |

Windows, Linux **and now macOS** all have runtime evidence behind them, on real segments rather than
in principle — macOS was brought up on Apple Silicon on 2026-07-29 (§13.20), which found and fixed the
last two live-only bugs. One claim still lacks a wire: **Linux IPv6/NDP** (written, never on a wire —
no v6 neighbours on the test segment). Everywhere else, "done" means it moved packets.

**Broadcast ARP is not universally delivered, on either platform.** Wi-Fi access points buffer
broadcast against the DTIM interval and commonly suppress it, so a station can be fully reachable by
unicast while never answering a broadcast solicitation. Measured with `spike.WindowsArpSpike`: the
affected host answered 0 of 3 broadcast requests and 3 of 3 unicast requests, while the gateway
answered 3 of 3 both ways on the same handle. Both backends now retry unicast against a MAC hint —
Linux from its passive learner, Windows from `IpMacCache` and then Windows' own neighbour table via
`GetIpNetEntry2`, used strictly as an aiming hint since resolution still requires a reply on our own
wire. On Windows this took the host from a 3006 ms timeout and `HOST_UNREACHABLE` pings to
`RESOLVED` in 11 ms and 20 of 20 MACs across a `/24`. See `CLAUDE.md` §13.12, §13.13 and §13.16.

The first macOS run (2026-07-27) threw before sending a packet, for two reasons that were both
about *all-or-nothing wiring* rather than ICMP itself: `HostScan` demanded the full L2 wiring for
every command, so the §7.3 gate exception killed even `ping`; and `DarwinIcmpPing.open` aborted the
whole pinger when the IPv6 socket was refused, taking working IPv4 ICMP with it. Both were fixed —
the fallback to `openIcmpOnly()` lives in `HostScanner`, so every command degrades to `ICMP_ONLY`
together rather than one at a time, and the two ICMP families open independently. See `CLAUDE.md`
§13.10.1. The **2026-07-29 bring-up on Apple Silicon** (§13.20) then confirmed the whole platform on
a wire and found the same *all-or-nothing* pattern one level up — a single non-Ethernet interface
(`utun`) was aborting the entire factory open — plus a libpcap loader that could not find the
dyld-cached library at all. Both are fixed and macOS now moves packets end to end.

**The Linux backend runs on real hardware, on both supported architectures.** The §13.1 spike was
superseded by the thing it existed to de-risk: `HostScan` lists, resolves, pings and sweeps live on
**x86-64 and on the aarch64 appliance**, so `AF_PACKET` ARP, `SOCK_RAW` ICMP with TTL, and the
`ALL-UNNAMED` native-access form under jar-loader are all confirmed against the wire rather than
against a checklist. `LinuxSpike` has been deleted. §2.3's claim that every layout and constant is
identical on x86-64 and aarch64 is now a measurement rather than an argument — no arch-specific
divergence turned up.

**No ABI gate remains.** The macOS one was retired rather than passed — see below.

## Design in one paragraph

Two public interfaces, not one, because ICMP and L2 have genuinely different scopes.
**`ICMPPing`** is L3 and **host-scoped**: the kernel routes each request and picks the source
address, so it has no interface binding and one instance serves the whole JVM.
**`HostDiscovery`** is L2 and **interface-scoped**: ARP and NDP frames carry an ifindex and the
interface's own MAC, and nothing routes that for you. A `HostDiscovery` optionally holds an
`ICMPPing` to enrich `sweep()`; without one it sweeps on ARP/NDP alone. On an N-interface Linux box
that costs `2 + 3N` reader threads instead of `4N` — two JVM-wide ICMP readers, plus ARP, NDP and a
receive-only `ETH_P_IP` learner per NIC.

**Passive learning is not a nicety.** Broadcast ARP is not universally delivered — access points
buffer broadcast against the DTIM interval and commonly suppress it — so a station can be fully
reachable by unicast while never answering a solicitation. Every Ethernet frame carries its sender's
MAC, so the `ETH_P_IP` socket on Linux — and every captured `ip`/`ip6` frame on Windows — learns
those hosts from their own traffic, and the resolver then aims a *unicast* ARP at them. Measured on
Linux: four consecutive cold resolves of such a host succeeded with the kernel's own neighbour table
empty (§13.13). Measured on Windows: an identical 60-second listen learned **2 neighbours with the
old ICMP-only filter and 9 with `ip`/`ip6`**, two of which never appear in a `/24` sweep at all —
phones using MAC randomisation, which ignore ARP from strangers and drop ICMP, and are found solely
because they announce themselves over multicast (§13.17).

**Our own addresses are answered from configuration, not from the wire.** Nothing on a segment
answers an ARP request for the asker's own address, and a pcap ping of it cannot see its own
loopback reply — the frame would carry our MAC as both source and destination, and no switch sends
it back. `NetworkInterface` already knows the answer, so `resolve()` reports
`ResolveSource.LOCAL_INTERFACE` and `ping()` reports probes marked `localInterface` with **no RTT at
all** rather than a fabricated zero. On Linux and macOS the kernel routes a self-ping over loopback
and returns a real measurement, which is kept (§13.18).

**ARP is the liveness oracle, not ICMP.** A host that answers ARP is alive whether or not it
answers a ping, so `HostRecord.mac` and `HostRecord.icmpAlive` are independent facts and
`alive() == mac.isPresent() || icmpAlive`. That is what finds hosts a plain ping sweep misses.

## Try it

`io.xlogistx.nosneak.net.tools.HostScan` is the CLI front end. Easiest from an IDE — main class
above, VM options `--enable-native-access=ALL-UNNAMED`, module `no-sneak-net`. From a terminal:

```bash
mvn -o -pl no-sneak-net compile
mvn -o -pl no-sneak-net dependency:copy-dependencies -DoutputDirectory=target/deps
java --enable-native-access=ALL-UNNAMED      -cp "no-sneak-net/target/classes;no-sneak-net/target/deps/*"      io.xlogistx.nosneak.net.tools.HostScan <command>
```

```
(no command)             interactive shell - one open session, many commands
list                     interfaces, devices, capabilities
status                   backend mode, and why it is what it is
resolve <ip|host>...     ARP/NDP - the MAC, and where it came from
ping    <ip|host>... [n] ICMP echo, pipelined
sweep   <cidr>...        ARP + ICMP across a range
segment <iface>          IPv6 neighbours on one segment
observe [seconds]        passive neighbours; transmits nothing
reopen                   rebuild the session after a NIC change

  -c/--count N   probes per host    -w/--timeout MS   per-probe timeout
  -i/--iface NAME   force the interface for sweep/segment
```

**Every command takes several targets.** Pings and resolves go out concurrently, so `ping a b c`
costs one round of wall time rather than three; sweeps run one range after another, because
`maxPacketsPerSecond` bounds a single sweep and running them together would multiply what hits the
segment. Run it with no command for a shell that keeps **one** session open across every command —
opening the factory per command costs a pcap handle or raw socket plus two reader threads per NIC
each time.

Windows needs [Npcap](https://npcap.com/); Linux needs root. Real output from a Windows box:

```
$ HostScan ping yahoo.com 3
yahoo.com resolved to 74.6.231.21
PING yahoo.com  3 probes, pipelined
  seq=0      rtt=89.640 ms  ttl=47
  seq=1      rtt=83.744 ms  ttl=47
  seq=2      rtt=82.902 ms  ttl=47

3 sent, 3 received, 0.0% loss
rtt min/avg/max/stddev = 82.903/85.429/89.641/2.998 ms

$ HostScan sweep 10.0.0.0/27
  10.0.0.9         b8:27:eb:30:40:d7   icmp     24.596 ms
  10.0.0.15        dc:a6:32:36:e7:6f   icmp     21.008 ms
  10.0.0.26        b8:27:eb:7a:a6:cc   icmp     11.109 ms
32 probed, 11 alive (11 by MAC, 11 by ICMP) in 1050 ms
```

That `ttl=47` is worth noticing: an initial 64 minus 17 hops, i.e. a genuine internet path. On-link
replies show 64.

```
$ HostScan
session : FULL - layer 2 and ICMP over 2 interface(s)
hostscan> sweep 10.0.0.0/29
sweeping 10.0.0.0/29 via ethernet_32769
  10.0.0.6      3a:68:7b:31:c8:72   icmp     23.614 ms
  10.0.0.1      42:25:47:35:03:ec   icmp     41.357 ms
8 probed, 5 alive (5 by MAC, 5 by ICMP) in 1021 ms
hostscan> ping 10.0.0.1 -c 1
  seq=5      rtt=10.330 ms  ttl=64
```

`seq=5` on a fresh command is the tell that the session really is shared: the sequence allocator
carried on from the sweep instead of restarting at zero.

## Embedding it

`HostScanner` is the surface an application drives — open it once, keep it, run as much as you like
through it:

```java
HostScanner scanner = HostScanner.open();          // never throws; ask mode() what you got

scanner.ping("10.0.0.1", 4, Duration.ofSeconds(2))
       .thenAccept(r -> SwingUtilities.invokeLater(() -> log(HostScanFormat.ping(r))));
scanner.resolveAll(List.of("10.0.0.1", "10.0.0.2"), Duration.ofSeconds(3));
scanner.sweep("10.0.0.0/24", SweepOptions.defaults(), host -> ...);   // streams as it goes

scanner.close();   // releases handles and reader threads; leaves the shared pools alone
```

Three properties that matter to a UI:

- **Nothing blocks the caller** except `open`, `reopen` and `close`. Even hostname lookup is pushed
  onto the dispatcher, so an action listener can call these straight from the event thread. Sweep
  records arrive on a dispatcher thread, never a reader thread.
- **It always opens.** No Npcap, or Linux without root, still yields a working object in a degraded
  `Mode` — `FULL`, `ICMP_ONLY` or `UNAVAILABLE` — with `diagnostic()` naming what failed. Disable
  the controls that mode cannot serve rather than guessing.
- **An unreachable host is a result, not an error.** Futures complete exceptionally only for a
  backend that cannot perform the operation at all: no pinger, an off-link `resolve` (ARP is
  link-local by definition — there is no MAC of a host beyond the segment), an unparseable CIDR.

`HostScanFormat` renders any result as the text the CLI prints, so a Swing log pane and a terminal
show the same thing.

## Usage — the layer underneath

`HostScanner` is a convenience over the factory; the interfaces are public and can be driven
directly when an application wants to own the wiring:

```java
// Everything, wired: one backend per NIC plus a shared pinger.
var discovery = HostDiscoveryFactory.open(HostDiscoveryFactory.usableInterfaces());
try {
    var eth0 = discovery.forName("eth0").orElseThrow();

    // MAC identity — proof of life independent of ICMP
    var resolved = eth0.resolve(InetAddress.ofLiteral("10.0.0.1"), Duration.ofSeconds(2)).join();

    // Liveness — pipelined, so 4 probes cost one timeout, not four
    var ping = discovery.ping().ping(InetAddress.ofLiteral("10.0.0.1"), 4,
                                     Duration.ofSeconds(1)).join();

    // Sweep — results stream in as they arrive
    eth0.sweep(CidrRange.parse("10.0.0.0/24"), SweepOptions.defaults(),
               host -> System.out.println(host.ip() + " " + host.mac().orElse(null))).join();
} finally {
    discovery.close();   // does NOT close the executors — they are borrowed
}
```

```java
// ICMP only: no interface, no ARP, two reader threads for the whole JVM.
// Not available on Windows, where pcap cannot ping without a resolved destination MAC.
ICMPPing ping = HostDiscoveryFactory.openIcmpOnly();
```

Check `capabilities()` before relying on anything. Backends degrade honestly rather than returning
empty results: a Wi-Fi adapter that pcap cannot inject
through is reported capture-only, Windows falls back to on-link only if `iphlpapi` will not load,
and a `-1` TTL means "this backend cannot tell you", never "zero hops away".

## Platform matrix

| | Linux | macOS | Windows |
|---|---|---|---|
| Binding | libc (FFM) | libc (FFM) | Npcap `wpcap.dll` + `iphlpapi` (FFM) |
| ICMP | `SOCK_RAW` | `SOCK_DGRAM` (unprivileged) | crafted over pcap |
| ARP/NDP | `AF_PACKET` | crafted L2 frames over libpcap | crafted L2 frames |
| Passive observation | yes | yes | yes (promiscuous) |
| TTL available | yes (IPv4) | no | yes |
| Off-link ICMP | yes | yes | yes (via `GetBestRoute2`) |
| Privilege | root | root for L2, none for ICMP | Npcap install |
| Objects | 2 | 2 | **1, implementing both interfaces** |

Windows is one object because pcap injects at L2 and bypasses routing, so a ping needs ARP — and it
is physically one handle, one device, one reader thread. Because it bypasses routing it also has to
ask Windows (`iphlpapi`'s `GetBestRoute2`) which gateway to hand an off-link packet to, then address
the frame to *that* MAC while the IP header still carries the real destination.

## Requirements and hard constraints

- **JDK 25.** The FFM API (`java.lang.foreign`) is used for every native call.
- **64-bit only**, `x86-64` and `aarch64`/`arm64`. This is a **platform constraint, not a
  preference**: FFM has no 32-bit linker implementation — `Linker.nativeLinker()` throws
  `UnsupportedOperationException` — and the Windows x86-32 port was removed in JDK 24 (JEP 479).
  `HostDiscoveryFactory` fails fast on any other `os.arch` rather than letting that surface from
  the first downcall.
- **No GraalVM / native-image.** Dynamic FFM binding is fundamentally incompatible with
  closed-world AOT compilation: the downcall handles are resolved at runtime from symbols that
  native-image cannot see. Do not attempt it.
- **Native access must be enabled** or JDK 25 warns and a future release will hard-fail:
  ```
  java --enable-native-access=ALL-UNNAMED ...
  ```
  `ALL-UNNAMED`, not a module name — this module declares no `module-info.java`, so it always loads
  unnamed. Already set as the Surefire `argLine`.
- **Dependencies**: the house libraries only — `zoxweb-core` (for `TaskUtil`'s shared thread pools),
  `xlogistx-common`, `xlogistx-core`. No Netty, no pcap4j, no Guava. Thread pools are **injected,
  never created**, and are borrowed: closing a `Discovery` never shuts them down.
- **Windows needs [Npcap](https://npcap.com/)**, which is not bundled — the free edition does not
  permit redistribution. Missing Npcap fails at `open()` with the install URL, not obscurely at
  first use.

## Build and test

```bash
mvn -o -pl no-sneak-net compile
mvn -o -pl no-sneak-net test -DskipTests=false     # the parent pom skips tests by default
```

The suite is host-independent: codecs, cache, aggregation, and the struct-layout assertions for all
three platforms all run anywhere. That is deliberate — layout tests caught a wrong `sockaddr_ll`
offset (`sll_halen` is at byte 11, not 9, because `sll_hatype` is a `short`) on a Windows machine,
before it ever became "ARP silently doesn't work" on the appliance.

## macOS: how the ABI gate was retired

§7.3 marked the kernel neighbor-table ABI `[VERIFY]` and forbade writing it from memory — `rt_msghdr`
embeds `rt_metrics`, the `ROUNDUP` padding rule has diverged between Darwin and the BSDs, and
`RTF_LLINFO` semantics have shifted across releases. A C probe was supposed to measure all of it on
both Intel and Apple Silicon first. **That probe was never written**, and it is no longer owed.

§2.2 picked the neighbour table for exactly one reason: BPF is `ioctl`-configured and `ioctl` is
variadic, which hits the Darwin arm64 `firstVariadicArg` hazard. **libpcap is the BPF wrapper** — the
`ioctl` calls happen inside the library, in C, where variadic conventions are the compiler's problem.
Through that door the hazard does not exist, and once the wire is visible there is nothing left for
`rt_msghdr` to answer. So `DarwinPcapBackend` does active ARP and NDP like every other platform, and
the gate is gone rather than cleared. See `CLAUDE.md` §13.14.

What this costs: `/dev/bpf*` is mode 0600, so macOS layer-2 now needs **root**. ICMP alone still does
not, and `openIcmpOnly()` — which `HostScanner` falls back to, giving `Mode.ICMP_ONLY` — stays
unprivileged.

What it buys: `passiveObservation` and `rawEvidence` become true on macOS, where both were previously
hardcoded false as a consequence of the neighbour-table design rather than of the OS. `ttlAvailable`
stays false, because TTL reaches callers through `PingProbe` and the unprivileged datagram ICMP
socket strips the IP header.

**It has now run on a Mac** (Apple Silicon, 2026-07-29 — §13.20). The 24-byte `pcap_pkthdr` it depends
on was already settled against live frames on Linux, and behaviour is settled too: active ARP, sweep
over wired and Wi-Fi, and passive observe all moved packets. The feared BSD read-timeout trap did not
appear — one-hop L2 RTTs were sub-millisecond — and Wi-Fi injection was not refused. The two bugs the
bring-up did find were elsewhere (a dyld-cache libpcap loader and an all-or-nothing factory open),
both fixed.

