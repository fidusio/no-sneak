# no-sneak

Assessment tooling for what a network endpoint actually exposes — its TLS posture, its
**post-quantum readiness**, and the services running on it — plus a desktop front-end and an
AI-assistant layer for interpreting the results.

The scanner's differentiator is PQC: alongside an SSL-Labs-style assessment it reports whether a
server negotiates ML-KEM hybrid key exchange today, which matters for CNSA 2.0 timeline
compliance and for harvest-now-decrypt-later exposure.

## Intended use

An assessment tool, for endpoints you own, administer, or are authorized to test. It observes —
handshakes, certificates, banners, liveness — and reports. It deliberately does **not** exploit
findings, guess credentials, flood or fuzz a target, or try to be hard to notice; those are
permanent design constraints, written out in `CLAUDE.md` → *Operating scope*. Scan output is
sensitive (it describes your network) and stays in the local encrypted store unless you send it
somewhere yourself.

## Modules

| Module | What it is |
|---|---|
| **`no-sneak-app`** | Swing desktop front-end — entry point, screens, navigation, and the session/access layer. See `CLAUDE.md`. |
| **`ai-assistant`** | Swing window that lets the subject send their own network data to third-party AI models and compare answers. Owns no API keys. See `CLAUDE.md`. |
| **`ai-model`** | The backend contract the assistant binds to: value DAOs and service interfaces, no provider or store implementations. See `CLAUDE.md`. |

The scanning engine is not in this repo. Since 2026-11-03 it lives in **io-xlogistx** and
`no-sneak-app` takes it as two jars:

| Module (io-xlogistx) | What it is |
|---|---|
| **`xlogistx-scan`** | The scanning engine (`io.xlogistx.scan`): TLS/PQC assessment, JSON-declared protocol probes, and a staged network scanner — all on one non-blocking state-machine core. Start with `io-xlogistx/xlogistx-scan/README.md`. |
| **`xlogistx-net`** | Host discovery below the port scan (`io.xlogistx.net`): ICMP/ICMPv6 liveness, ARP/NDP layer-2 identity, IP↔MAC cache, CIDR sweep. JDK 25 FFM, no packet library. See `io-xlogistx/xlogistx-net/README.md`. |

Dependency direction is one-way: `no-sneak-app → ai-assistant → ai-model`, and
`no-sneak-app → xlogistx-scan → xlogistx-net` (the scanner's host sweep and MAC vendor names come
from `xlogistx-net`; the app also loads `NSNetUtil.MAC_VENDORS` itself after login).

## Build

```bash
mvn clean install                         # this repo: no-sneak-app, ai-assistant, ai-model

# the engine, from the io-xlogistx checkout — install it first when it changed
mvn clean install -pl xlogistx-scan -am
```

Tests are skipped by the parent pom (`xlogistx-mvn`); run them with `-DskipTests=false`. See
`io-xlogistx/xlogistx-scan/README.md` for the caveat about locally installed TLS-intercepting proxies, which
break both Maven's HTTPS and certificate-trust results.

## Quick start

```bash
# what is running on this host:port, and how good is its TLS?
java io.xlogistx.scan.ProbeChecker example.com 443

# staged network scan with service/version/TLS identification
java io.xlogistx.scan.nmap.NMap example.com -p 22,80,443 -sV
```

## Status

`xlogistx-scan` was rebuilt from scratch on a single non-blocking core and the rebuild replaced the
original engine on 2026-09-12; the module is now one code base at `io.xlogistx.scan` that
produces service/version identification, TLS/PQC posture, certificate chain-trust, revocation,
protocol/cipher/group enumeration and grading. See `io-xlogistx/xlogistx-scan/CLAUDE.md`.

`xlogistx-net` **requires JDK 25** (FFM). Its API, codecs, cache, factory wiring, `HostScan` CLI
and all three backends — Windows, Linux and macOS (libpcap) — are done and verified against live
hardware, Linux IPv6/NDP included. The quickest way to see it work is `io.xlogistx.net.tools.HostScan`
(`hostscan list | resolve | ping | sweep`, or no argument for a shell that keeps one session open);
an application embeds `HostScanner`, the same session type the CLI drives. Its `README.md` in
io-xlogistx has the run recipe, the embedding example, and the per-platform status.

External dependencies: zoxweb (`org.zoxweb.*`) and the `io-xlogistx` modules (`common`, `core`,
`http`, `shiro`, `opsec`, `gui-audio`, `scan`, `net`). **Bouncy Castle is the only cryptographic library.**
`xlogistx-net` additionally requires [Npcap](https://npcap.com/) on Windows only, which is not
bundled and not redistributable under its free licence.

## License

See `LICENSE`.
