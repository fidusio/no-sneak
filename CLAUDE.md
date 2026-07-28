# no-sneak

Security tooling for assessing what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — plus a Swing front-end and an AI-assistant layer.

Five modules, one-way dependencies (`no-sneak-app → ai-assistant → ai-model`):

| Module | What it is | Orientation |
|---|---|---|
| **`no-sneak-core`** | The scanning engine (TLS/PQC + protocol probes + network scanner) | `no-sneak-core/CLAUDE.md` |
| **`no-sneak-net`** | Host discovery (ICMP/ARP/NDP over FFM) — built; Linux and Windows verified on live hardware | `no-sneak-net/CLAUDE.md` |
| **`no-sneak-app`** | Swing desktop front-end, session/security layer | `no-sneak-app/CLAUDE.md` |
| **`ai-assistant`** | Swing window to send network data to third-party AI models and compare | `ai-assistant/CLAUDE.md` |
| **`ai-model`** | The backend contract (DAOs + service interfaces, no implementations) | `ai-model/CLAUDE.md` |

`no-sneak-net`'s `CLAUDE.md` is two documents in one: an authoritative build spec (base package
`io.xlogistx.nosneak.net`, JDK 25 FFM, house libraries only) in §1–§12, and a running verification
log in §13. The code is real — three backends, a `HostScan` CLI, 189 green tests — so §13 is where
you learn what has actually touched a wire versus what merely compiles, and it is worth reading
before trusting any claim in the earlier sections.

**One gap is genuine and deliberate: macOS layer-2.** `HostDiscovery` throws there by design until
the kernel neighbour-table ABI is measured by the C probe in `no-sneak-net/src/main/c` — §7.3 marks
it `[VERIFY]` and forbids writing it from memory. macOS ICMP works. Linux IPv6/NDP is written but
has never been exercised on a wire.

## The one thing to know before touching `no-sneak-core`

That module exists **twice**. `io.xlogistx.nosneak.v2` is the rebuild that replaces it; the v1
packages (`nmap`, `probe`, `scanners`, `services`, `tools`) are **frozen and deleted when the
maintainer merges**, at which point v2's package path collapses to `io.xlogistx.nosneak` (hence no
v2 class carries a `v2` suffix — the names are final).

**So: never fix v1 bugs, and treat anything v1 has that v2 lacks as a regression rather than a
TODO.** Read `no-sneak-core/CLAUDE.md` first; it routes to the migration plan, the probe reference,
and the open-work list.

## Build and test

```bash
mvn clean install                        # everything
mvn clean install -pl no-sneak-core -am  # just the engine

# tests are skipped by the parent pom (xlogistx-mvn); override to run them
mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.v2.**'
```

External dependencies are zoxweb (`org.zoxweb.*`) and the `io-xlogistx` modules (`common`, `core`,
`http`, `shiro`, `opsec`, `datastore`). **Bouncy Castle is the only cryptographic library**, and
reusable crypto/utility helpers belong in `opsec/OPSecUtil`, not in this repo.

If a TLS-intercepting proxy is installed locally, Maven can't reach central and every scanned
certificate reads `UNTRUSTED_ROOT` — neither is a code defect. See `no-sneak-core/CLAUDE.md` →
*Build, test, verify*.
