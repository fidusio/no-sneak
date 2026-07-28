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

| Step | State |
|---|---|
| Public API, codecs, cache, ping aggregation | **done**, 189 tests green |
| Windows (Npcap/pcap) backend | **done and verified on live hardware** |
| Windows off-link routing (`iphlpapi`) | **done and verified against a live internet path** |
| Factory wiring + `HostScan` CLI | **done and verified on live hardware** |
| Linux ICMP (`SOCK_RAW`, v4 + TTL) | **done and verified on live hardware — x86-64 and aarch64** |
| Linux ARP (`AF_PACKET`) | **done and verified on live hardware — x86-64 and aarch64** |
| Linux IPv6 / NDP | **written, never exercised on a wire** — no v6 neighbours on the test segment |
| macOS ICMP | **run once, threw at startup; two all-or-nothing bugs fixed — needs re-test** |
| macOS ARP/NDP | **deliberately not written** — see *The macOS gate* below |

Windows and Linux both have runtime evidence behind them now, on real segments rather than in
principle. Three claims still do not, and they are the ones to distrust: **Linux IPv6/NDP** (written,
never on a wire), **macOS ICMP** (the fixes have not themselves been run on a Mac), and **macOS
layer-2** (unwritten by design). Everywhere else, "done" means it moved packets.

The first macOS run (2026-07-27) threw before sending a packet, for two reasons that were both
about *all-or-nothing wiring* rather than ICMP itself: `HostScan` demanded the full L2 wiring for
every command, so the §7.3 gate exception killed even `ping`; and `DarwinIcmpPing.open` aborted the
whole pinger when the IPv6 socket was refused, taking working IPv4 ICMP with it. Both are fixed —
`ping`/`list` fall back to `openIcmpOnly()`, and the two ICMP families now open independently — but
**the fix has not itself been run on a Mac.** See `CLAUDE.md` §13.10.1.

**The Linux backend runs on real hardware, on both supported architectures.** The §13.1 spike was
superseded by the thing it existed to de-risk: `HostScan` lists, resolves, pings and sweeps live on
**x86-64 and on the aarch64 appliance**, so `AF_PACKET` ARP, `SOCK_RAW` ICMP with TTL, and the
`ALL-UNNAMED` native-access form under jar-loader are all confirmed against the wire rather than
against a checklist. `LinuxSpike` has been deleted. §2.3's claim that every layout and constant is
identical on x86-64 and aarch64 is now a measurement rather than an argument — no arch-specific
divergence turned up.

One gate remains: **the macOS ABI probe** — see below.

## Design in one paragraph

Two public interfaces, not one, because ICMP and L2 have genuinely different scopes.
**`ICMPPing`** is L3 and **host-scoped**: the kernel routes each request and picks the source
address, so it has no interface binding and one instance serves the whole JVM.
**`HostDiscovery`** is L2 and **interface-scoped**: ARP and NDP frames carry an ifindex and the
interface's own MAC, and nothing routes that for you. A `HostDiscovery` optionally holds an
`ICMPPing` to enrich `sweep()`; without one it sweeps on ARP/NDP alone. On an N-interface Linux box
that costs `2 + 2N` reader threads instead of `4N`.

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
list                  interfaces, devices, capabilities
resolve <ip|host>     ARP/NDP - the MAC, and where it came from
ping    <ip|host> [n] ICMP echo, pipelined
sweep   <cidr>        ARP + ICMP across a range
```

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

## Usage

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
empty results: macOS genuinely cannot observe passively, a Wi-Fi adapter that pcap cannot inject
through is reported capture-only, Windows falls back to on-link only if `iphlpapi` will not load,
and a `-1` TTL means "this backend cannot tell you", never "zero hops away".

## Platform matrix

| | Linux | macOS | Windows |
|---|---|---|---|
| Binding | libc (FFM) | libc (FFM) | Npcap `wpcap.dll` + `iphlpapi` (FFM) |
| ICMP | `SOCK_RAW` | `SOCK_DGRAM` (unprivileged) | crafted over pcap |
| ARP/NDP | `AF_PACKET` | kernel neighbor table via `sysctl` | crafted L2 frames |
| Passive observation | yes | **no** | yes (promiscuous) |
| TTL available | yes (IPv4) | no | yes |
| Off-link ICMP | yes | yes | yes (via `GetBestRoute2`) |
| Privilege | root | none | Npcap install |
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

## The macOS gate

`src/main/c/darwin_neighbor_abi_probe.c` exists because §7.3 marks the kernel neighbor-table ABI
`[VERIFY]` and forbids writing it from memory: `rt_msghdr` embeds `rt_metrics`, the `ROUNDUP`
padding rule has diverged between Darwin and the BSDs, and `RTF_LLINFO` semantics have shifted
across macOS releases.

```bash
cc -Wall -O0 -o probe src/main/c/darwin_neighbor_abi_probe.c && ./probe
```

It prints every offset and size the parser needs, then **dumps the live ARP and NDP tables using the
same walk the Java will use** — compare that against `arp -a`. Run it on **both** Intel and Apple
Silicon, confirm they agree, record the numbers in §7.3, and only then write the parser. Until that
happens `HostDiscoveryFactory` refuses macOS L2 with a message saying exactly this.
