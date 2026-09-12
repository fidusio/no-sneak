# no-sneak

> **Picking this project up?** `PENDING-ISSUES.md` at the repo root is the handoff index of open
> work — it points at every per-module open-items list and records the 2026-08-13 code-review
> findings against the then-uncommitted scan-panel and AI-assistant changes.

Assessment tooling for what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — plus a Swing front-end and an AI-assistant layer.

## Operating scope — read this before changing anything

no-sneak is **defensive assessment tooling**. It answers *"what does this endpoint expose, and how
good is its posture"* for an operator assessing infrastructure they own, administer, or have been
authorized to test. Everything it ships is observational: open a connection, complete an ordinary
protocol handshake, read what the peer volunteers, record it, report it.

**In scope** — TLS/PQC handshake assessment, certificate chain trust and revocation, protocol and
cipher enumeration, service/version identification through declared probes, ICMP/ARP/NDP host
discovery on a segment the operator controls, grading, and reporting.

**Out of scope, permanently.** These are design constraints, not backlog items:

- **No exploitation.** Vulnerability work here is *detection*: infer exposure from advertised
  versions, extension presence, negotiated parameters, and ordinary handshake behaviour. Never
  send input meant to read a peer's memory, corrupt its state, or execute code on it.
- **No credential attacks.** No password or key guessing, spraying, brute force, or capture.
- **No denial of service.** No flooding, amplification, resource exhaustion, or fuzzing of a live
  target. The rate limits, bounded concurrency, timeouts and soft-fails are safety properties —
  they are not overhead to optimise away.
- **No evasion.** Nothing is built to be hard to observe, log, or attribute. Traffic leaves under
  our own addresses. nmap's `-sS/-sF/-sX/-sN/-sA` flags and the word "stealth" appear in this repo
  only as **legacy nmap vocabulary** in pre-merge notes and CLI-compatibility text; the scanner rejects those flags
  with a clear error and those engine classes are deleted rather than implemented.
- **No persistence, C2, or exfiltration.** The tool runs, reports and exits. Results stay in the
  local encrypted store unless the operator deliberately sends them somewhere.

**Data handling.** Everything a subject produces is scoped to that subject in the encrypted H2
store. Scan reports carry network topology and are sensitive: they cross a trust boundary only when
the subject attaches one to a chat, under the subject's own provider credentials. Any path that
shows one subject's data to another is a defect, not a feature — see `PENDING-ISSUES.md` finding 1.

A change that would cross one of those lines is out of scope for this repo: say so, and propose the
detection-only or narrower-design version instead.

Five modules, one-way dependencies (`no-sneak-app → ai-assistant → ai-model`):

| Module | What it is | Orientation |
|---|---|---|
| **`no-sneak-core`** | The scanning engine (TLS/PQC + protocol probes + network scanner) | `no-sneak-core/CLAUDE.md` |
| **`no-sneak-net`** | Host discovery (ICMP/ARP/NDP over FFM) — built; Linux and Windows verified on live hardware | `no-sneak-net/CLAUDE.md` |
| **`no-sneak-app`** | Swing desktop front-end, session/access layer | `no-sneak-app/CLAUDE.md` |
| **`ai-assistant`** | Swing window to send network data to third-party AI models and compare | `ai-assistant/CLAUDE.md` |
| **`ai-model`** | The backend contract (DAOs + service interfaces, no implementations) | `ai-model/CLAUDE.md` |

`no-sneak-net`'s `CLAUDE.md` is two documents in one: an authoritative build spec (base package
`io.xlogistx.nosneak.net`, JDK 25 FFM, house libraries only) in §1–§12, and a running verification
log in §13. Anything in this repo that wants host discovery goes through **`HostScanner`** (§14.1) —
a session you open once and run many pings, resolves and sweeps through; `HostScan` is a CLI over
it. The code is real — three backends, that CLI, ~370 green tests in 39 classes — so §13 is where
you learn what has actually touched a wire versus what merely compiles, and it is worth reading
before trusting any claim in the earlier sections. **§13.21 is the open-items list, split per
platform** — start there if you are picking work up.

**Every platform now has a layer-2 backend**; macOS was the last, and goes through libpcap rather
than the kernel neighbour table §7.3 gated on — that ABI is retired, not measured (§13.14). macOS was
brought up on Apple Silicon on 2026-07-29 and now has runtime evidence like the others — active ARP,
sweep over wired and Wi-Fi, and passive observe all moved packets (§13.20). One claim still lacks a
wire and is the one to distrust: **Linux IPv6/NDP** (written, never on a wire).

## `no-sneak-core` is one code base now

Until 2026-09-12 the module carried two generations side by side: the original packages and a
from-scratch non-blocking rebuild under `io.xlogistx.nosneak.v2`. **The merge is done.** The
original packages (`nmap`, `probe`, `scanners`, `services`, `tools`) and their tests are deleted,
the rebuild lives at `io.xlogistx.nosneak`, and the bundled probes are at `/probes/`. There is no
`v2` package, no `v2` class name and no frozen code left. `no-sneak-core/V1-V2-MERGE-ANALYSIS.md`
is the record of what the deleted generation had, and how each of those things was carried across
before deletion; `no-sneak-core/ACTION-PLAN.md` is pre-merge history. Read `no-sneak-core/CLAUDE.md`
first; it routes to the plan log, the probe reference, and the open-work list.

## Build and test

```bash
mvn clean install                        # everything
mvn clean install -pl no-sneak-core -am  # just the engine

# tests are skipped by the parent pom (xlogistx-mvn); override to run them
mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.**'
```

External dependencies are zoxweb (`org.zoxweb.*`) and the `io-xlogistx` modules (`common`, `core`,
`http`, `shiro`, `opsec`, `datastore`). **Bouncy Castle is the only cryptographic library**, and
reusable crypto/utility helpers belong in `opsec/OPSecUtil`, not in this repo.

If a TLS-intercepting proxy is installed locally, Maven can't reach central and every scanned
certificate reads `UNTRUSTED_ROOT` — neither is a code defect. See `no-sneak-core/CLAUDE.md` →
*Build, test, verify*.
