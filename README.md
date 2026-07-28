# no-sneak

Security tooling for assessing what a network endpoint actually exposes — its TLS posture, its
**post-quantum readiness**, and the services running on it — plus a desktop front-end and an
AI-assistant layer for interpreting the results.

The scanner's differentiator is PQC: alongside an SSL-Labs-style assessment it reports whether a
server negotiates ML-KEM hybrid key exchange today, which matters for CNSA 2.0 timeline
compliance and for harvest-now-decrypt-later exposure.

## Modules

| Module | What it is |
|---|---|
| **`no-sneak-core`** | The scanning engine: TLS/PQC assessment, JSON-declared protocol probes, and a staged network scanner — all on one non-blocking state-machine core. Start with its `README.md`. |
| **`no-sneak-net`** | Host discovery below the port scan: ICMP/ICMPv6 liveness, ARP/NDP layer-2 identity, IP↔MAC cache, CIDR sweep. JDK 25 FFM, no packet library. See its `README.md`. |
| **`no-sneak-app`** | Swing desktop front-end — entry point, screens, navigation, and the session/security layer. See `CLAUDE.md`. |
| **`ai-assistant`** | Swing window that lets the subject send their own network data to third-party AI models and compare answers. Owns no API keys. See `CLAUDE.md`. |
| **`ai-model`** | The backend contract the assistant binds to: value DAOs and service interfaces, no provider or store implementations. See `CLAUDE.md`. |

Dependency direction is one-way: `no-sneak-app → ai-assistant → ai-model`. `no-sneak-net` stands
alone — it answers "is this host there and what is its MAC", which comes *before* anything
`no-sneak-core` does, and the two are not yet wired together.

## Build

```bash
mvn clean install                        # everything
mvn clean install -pl no-sneak-core -am  # just the engine
```

Tests are skipped by the parent pom (`xlogistx-mvn`); run them with `-DskipTests=false`. See
`no-sneak-core/README.md` for the caveat about locally installed TLS-intercepting proxies, which
break both Maven's HTTPS and certificate-trust results.

## Quick start

```bash
# what is running on this host:port, and how good is its TLS?
java io.xlogistx.nosneak.v2.ProbeChecker example.com 443

# staged network scan with service/version/TLS identification
java io.xlogistx.nosneak.v2.nmap.NMap example.com -p 22,80,443 -sV
```

## Status

`no-sneak-core` is mid-migration to **v2** (`io.xlogistx.nosneak.v2`), a from-scratch rebuild on a
single non-blocking core. v2 is feature-complete against v1 and additionally produces certificate
chain-trust, revocation, protocol/cipher enumeration and grading; v1 is frozen and is deleted when
the maintainer merges. Vulnerability scanning, HTTP security-header analysis and CNSA 2.0
compliance rules are not implemented yet — see `no-sneak-core/ACTION-PLAN.md`.

`no-sneak-net` is new and **requires JDK 25** (FFM), unlike the rest of the reactor. Its API, codecs,
cache, factory wiring, `HostScan` CLI and both the Windows and Linux backends are done and verified
against live hardware — the Windows path including off-link routing through the gateway, and the
Linux path on **x86-64 and the aarch64 appliance**. Linux IPv6/NDP is written but has never been
exercised on a wire, and macOS layer-2 is deliberately unwritten pending an ABI probe. The quickest
way to see it work is `io.xlogistx.nosneak.net.tools.HostScan` (`hostscan list | resolve | ping |
sweep`); its `README.md` has the run recipe and the per-platform status.

External dependencies: zoxweb (`org.zoxweb.*`) and the `io-xlogistx` modules (`common`, `core`,
`http`, `shiro`, `opsec`, `datastore`). **Bouncy Castle is the only cryptographic library.**
`no-sneak-net` additionally requires [Npcap](https://npcap.com/) on Windows only, which is not
bundled and not redistributable under its free licence.

## License

See `LICENSE`.
