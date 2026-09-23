# NoSneak Core (`no-sneak-core`)

The scanning engine: a **TLS/PQC posture scanner** and a **network scanner**, both driven by one
JSON-declared, fully non-blocking state machine. Everything else in the repo is a front-end over
this module.

> **Status (2026-09-12): merged, one generation.** This module was rebuilt from scratch on a
> single non-blocking core while the original packages stayed frozen beside it; on 2026-09-12 the
> original packages (`nmap`, `probe`, `scanners`, `services`, `tools`), their tests and their
> resources were deleted and the rebuild's package collapsed from `io.xlogistx.nosneak.v2` to
> `io.xlogistx.nosneak`. Everything the deleted generation had was carried across first —
> `V1-V2-MERGE-ANALYSIS.md` records what, and how. `ACTION-PLAN.md` is pre-merge history; its
> only live part is the vulnerability-scanning checklist.
>
> **Status (2026-09-20): the scan pipeline is fast and `-sV` is honest.** Adaptive deadlines,
> streamed probes on a priority lane, a gate that honours its caps, first-positive discovery,
> `--up-only`; `ParallelJoin` is now `CountdownMonitor`; the BCJSSE pin is gone; gated probes run
> OCSP/CRL again (they silently never had); `postgres-db` no longer claims SSH servers;
> `https-scan` also reads the `Server:` header. Design: *The scan pipeline* below; record:
> `PLAN.md` 2026-09-19/20; open items: repo-root `PENDING-ISSUES.md` → *Status check (2026-09-20)*.
>
> **Status (2026-09-22): the `tls-connect` tail no longer reverse-resolves its target.** The
> 2026-09-20 "TLS-1.2-only host" timeout was a 4.6 s reverse DNS lookup inside the probe's own
> deadline (zoxweb's `SSLContextInfo.newInstance()` calls `getHostName()` on the connect address);
> `ProbeSecureCallback.namedAddress` pins the host string on the resolved address so the lookup
> never happens. `https-scan` on that host 9.4–10.1 s → 4.8–5.3 s; the header `GET` is HTTP/1.1; a banner ends at its first binary byte (dropbear). 403 tests / 36 classes green.
> Record: `PLAN.md` 2026-09-22; open items: `PENDING-ISSUES.md` → *Status check (2026-09-22)*.

---

## Scope of the engine

Assessment only, and that bounds the code: a probe **connects, exchanges the minimum the protocol
needs, and records facts**. It does not exploit what it finds, guess credentials, fuzz, or try to
evade logging, and the scanner stays rate-limited and bounded because a scan must never become the
outage it was run to prevent. The vulnerability checklist in `ACTION-PLAN.md` is a *detection*
backlog — evidence from versions, extensions and negotiated parameters. Full rules: the repo root
`CLAUDE.md` → *Operating scope*.

## Where to read next

| Doc | Covers |
|---|---|
| `PLAN.md` | **Start here.** The dated engineering log: architecture decisions, each fix wave, and the running verification record |
| `PROBE-CONFIG.md` | The reference: action library, candidate selection, bundled probes, result fields, tests, deferrals |
| `PROBE-DEFINITION.md` | **The probe-definition guide — the file to hand an AI as a skill** to generate a `probe.json`: schema, every action incl. the deep-TLS ones, budgets, validation rules, recipes, worked examples, self-check |
| `V1-V2-MERGE-ANALYSIS.md` | History of the merge: the code-verified comparison of the two generations, what the deleted one had, and how each item was carried across (paths in it are pre-merge) |

| `ACTION-PLAN.md` | Pre-merge history and the SSL-Labs vulnerability-check backlog |
| `README.md` | Module overview + the full scanner requirements document |

## Architecture

One engine drives everything: a `StateMachine<ProbeContext>` (zoxweb `org.zoxweb.server.fsm`).
A JSON `ProbeDefinition` **builds** the machine — each declared state becomes a `State` carrying a
`ProbeActionConsumer` that runs one fixed, trusted **action**. The action reports an outcome
label; `ProbeContext.fire(label)` resolves the state's `on{}` map and publishes the next state's
trigger. **JSON selects and configures behaviour; JSON never executes code.**

```
ProbeChecker / NMapScanner ─▶ ProbeContext (live NIO connection, ProbeResult.Builder, watchdogs)
                                   ▼ builds + drives
                             ProbeEngine → StateMachine<ProbeContext>
                                   ▼ each state runs one Action
   connect · send · expect · starttls · tls-connect · tls-handshake · pqc-check · tls-facts
   cert-chain-validate · revocation-check · enumerate-versions · enumerate-ciphers · record · done/fail
                                   ▼
                             ProbeResult (facts only)  ──▶  grade.Grade (rules layer: letter,
                                                            PQC readiness, trust verdict)
```

Three concurrency layers, all on the shared pools:

- **Sequential** — `publishSync` on an inline executor, so a probe's steps stay on the selector or
  scheduler thread that `ProbeContext` already serialises with `synchronized`.
- **Fan-out** — `Fanout` + `CountdownMonitor`: a second `StateMachine` whose executor is
  `TaskUtil.defaultTaskProcessor()`, one `TriggerConsumer` per child, published in parallel. This
  is how version/cipher enumeration runs one connection per candidate.
- **Candidate sweep** — `ProbeChecker` launches every candidate probe at once and elects the
  highest-priority completion as soon as no better candidate can still win, then cancels the rest.

### The scan pipeline (`nmap/NMapScanner`, reworked 2026-09-20)

One scan is a chain of callback-linked stages on the caller's `NIOSocket` pools — discovery
(`no-sneak-net` `HostScanner` sweep for on-link CIDRs, TCP-ping/ICMP/ARP per host otherwise) →
reverse DNS → TCP connect scan → UDP scan → probes → one `finish`. Every stage boundary is a
`CountdownMonitor`, which is an atomic countdown, not a thread join: the last child to report runs the
continuation on its own thread. Nothing parks. What the 2026-09-20 pass changed, and why (the
measured record is `PLAN.md` → 2026-09-19/20; a `/24 × 1024 ports` went 136 s → 6 s):

- **Adaptive connect deadline.** `connectTimeoutMs` = 10 × the host's discovery RTT, clamped to
  [`--min-rtt-timeout` (500 ms default), `-t`]. A silently dropped port used to hold a slot for the
  full `-t`; on a LAN that *was* the scan. A swept host with no RTT (own address, passive-only
  neighbour) inherits the segment's median. No RTT at all (`-Pn`) keeps `-t`.
- **Probes streamed from the connect.** With `-sV` the `ProbeChecker` is built before the first
  connect and a port's sweep is launched from its connect callback as a further child of the host's
  barrier (`CountdownMonitor.addChild`: register, release the connect's gate slot, then launch), so
  identification overlaps the filtered-port timeouts. `probeStage` itself now covers only UDP.
  Candidate starts are admitted on the gate's **priority lane** (`ConnectionGate.submitFirst`):
  same window and pacer, but ahead of the queued port connects — without it the first `-sV` run
  showed every probe waiting 30–58 s behind ~20k queued connects.
- **`ScanGate` honours caps above 1000/s.** zoxweb `RateController` paces in whole milliseconds, so
  every cap ≥ 1000/s had collapsed to one launch per ms (`-T4`/`-T5` were no faster than `-T3`).
  The gate now spends a quantum of `maxPerSec/1000` launches per slot — still leaky, still
  `RateController`. `ScanGateThroughputTest` measures it (≈1990/s at 2000, ≈9900/s at 10000).
- **NIOSocket's connect monitor is released.** `addClientSocket` arms an `NIOChannelMonitor` that
  only a *successful* connect cancels; the port callback's shorter deadline fires first, so it
  hands `nio.abortClientSocket(key)` in via `PortScanCallback.releaseWith`. Two timers by design:
  the monitor is deliberately coarse (whole seconds — it is armed *before* `connect()` is
  initiated, so a millisecond monitor could race the connect itself), the callback's is the
  precise one. The probe path already did this through `ProbeTransport.abort`.
- **`--up-only`** lists only live hosts in every formatter (`ScanReport.hostsToRender()`); the
  run-level up/down/total counts still cover the range.
- **Per-host discovery decides at the first positive.** A non-CIDR target runs ARP, ICMP and the
  TCP-pings in parallel; the host is handed to the next stage the moment any of them says up (the
  outstanding TCP-pings are aborted), not when the slowest has timed out. A down verdict still
  waits for every unit. With `-sV`, a port that no tier-1 probe declares (53/tcp, say) still costs
  one full `-t` while every fallback candidate waits its `expect` timeout — inherent, `-t 2` on a LAN.

Recommended shape on a wired LAN: `10.0.0.0/24 -T5 --min-rtt-timeout 200 --max-inflight 4096
--up-only --open`, and `-sV` when identification is wanted.

Three distinct TLS paths — pick deliberately when writing a probe:

| Path | Mechanism | Use for |
|---|---|---|
| `tls-handshake` | Bouncy Castle on the already-open channel | PQC classification, cert facts, STARTTLS upgrades |
| `tls-connect` | JSSE (`ProbeSecureCallback`, trust-all, RSA-capable) | talking *through* TLS (e.g. reading an HTTPS `Server:` header) |
| `starttls` | plaintext → TLS mid-session, then BC | SMTP/IMAP/POP3/FTP-style upgrades |

Only the BC path can classify PQC — JSSE does not surface the negotiated key-exchange group.

## Non-negotiable rules

1. **One generation.** No class, package or resource path carries a generation suffix; the deleted engine is never reintroduced from history.
2. **Nothing blocks.** No `Thread.sleep`, no blocking sockets, no `future.join()/get()` on a live
   path. Every wait is a task on `TaskUtil.defaultTaskScheduler()`; every connection is on the
   shared `NIOSocket`. (The CLI/test convenience wrappers block by design and say so.)
3. **No `MonoStateMachine` anywhere.** Use the trigger-based `StateMachine`; for concurrency use
   its native `publish`/`publishSync` dispatch via `Fanout`, not hand-rolled threads.
4. **Bouncy Castle is the only crypto library**, and reusable crypto/utility helpers belong in
   `opsec/OPSecUtil` (a separate module that survives the merge) — not here.
5. **`ProbeResult` is facts-only.** Verdicts, grades and scores belong in `grade.Grade`, which
   reads recorded facts and makes no network calls.
6. **Tri-state facts serialize as strings, not booleans** — `GSONUtil.toJSONDefault` omits default
   values, so a `false` boolean silently vanishes and becomes indistinguishable from "not
   checked". Render with `toJSONGenericMap(m, true, true, false)` where you control the renderer.

## Layout

```
io.xlogistx.nosneak
├── ProbeChecker            library API + CLI: two-tier candidate selection, concurrent sweep
├── model/                  ProbeDefinition · ProbeState · PatternRule · ProbeDefinitionLoader (validates)
├── runtime/                ProbeContext (the engine's config object) · ProbeEngine · Fanout · CountdownMonitor (the countdown barrier, formerly ParallelJoin)
│                           ProbeTCPCallback (raw) · ProbeSecureCallback (JSSE) · ProbeUDPCallback
├── action/                 the fixed action library + ActionRegistry (name → singleton)
├── tls/                    PQCHandshakeStateMachine · PQCSessionConfig · PQCTlsClient (BC, ML-KEM groups)
├── analysis/               TLSProbeCallback base · Cipher/VersionProbeCallback · RevocationChecker
├── grade/                  Grade — letter, PQC readiness, TrustVerdict, advisories
├── result/                 ProbeResult (+ CertInfo, ConnectionTrace)
├── nmap/                   NMapScanner (staged; adaptive deadline, streamed probes) · NMap CLI · PortScanCallback (ms deadline
│                           + releaseWith) · UdpScanCallback · ReverseDnsCallback · ScanGate (window + per-slot quantum) · output/
├── service/                Checker — REST /check-qdz/{domain}/{detailed}
└── tools/                  DMTool · NoSneakUtil

src/main/resources/probes/   18 bundled + 2 unbundled probe definitions
src/test/java/io/xlogistx/nosneak/   403 tests in 36 classes, all green (2026-09-22) + NoSneakNIOHTTPServer harness. Pure and socket-free except
                                    nmap/NMapScannerEndToEndTest (a loopback listener) and nmap/ScanGateThroughputTest
                                    (measures the gate on real pools); model/ProbeDefinitionGuideTest pins
                                    PROBE-DEFINITION.md to the loader
```

## Build, test, verify

```bash
mvn clean install -pl no-sneak-core -am

# tests are skipped by the parent pom (xlogistx-mvn sets <skipTests>true</skipTests>)
mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.**'

# live check against a real endpoint
mvn -pl no-sneak-core dependency:build-classpath -Dmdep.outputFile=cp.txt -DincludeScope=runtime
java -cp "target/classes;$(cat cp.txt)" io.xlogistx.nosneak.ProbeChecker example.com 443
```

**Environment gotcha that will mislead you:** if a TLS-intercepting proxy is installed locally
(Avast, on the maintainer's machine), every scanned chain re-signs to the proxy's root and reads
`cert-chain-trust: UNTRUSTED_ROOT`, and Maven cannot reach central (`PKIX path building failed`).
Neither is a code defect. Import the proxy's root into a copy of the JDK `cacerts` and point
`javax.net.ssl.trustStore` at it (`MAVEN_OPTS` for Maven, `-D` for a CLI run) — that also lets you
exercise the `TRUSTED` path.

**The same product's mail shield fakes open ports.** Seen 2026-09-20: ports 25 110 119 143 465
563 587 993 995 reported `open` at 0 ms on *every* live host of a `/24`, printer and routers
included, because the shield completes the TCP handshake locally before any packet leaves the
box. The scanner reported what it observed — a completed handshake — and that is where it stays:
a heuristic to flag the pattern was proposed and **declined by the maintainer** (antivirus
problem, product-specific, more false positives; do not reopen). Scan with the shield off, or
from a box without one. Turning it off on Windows hands the box to Windows Firewall, whose stealth
mode drops rather than resets, so the scanning host's own closed ports then read `filtered`.

**BCJSSE (2026-09-20):** the P23 workaround — `tls-connect` minting its engine from `SunJSSE` by
name because the published `bctls-jdk18on` 1.86 could not create an `SSLEngine` on JDK ≥ 9 — is
**removed**, with its canary, at the maintainer's request after the canary fired on the local
repository's `bctls` 1.85. `ProbeSecureCallback.tlsContext` takes the JCA default (BCJSSE under
`SecUtil`'s registration); `TlsConnectContextTest` pins that it mints an engine and names the
provider on failure. If a broken `bctls` ever returns to the classpath, that test is where it shows.
The same test pins (2026-09-22) that the connect address the callback hands the framework carries
its host name — zoxweb mints the engine from `getHostName()`, which on a bare IP literal is a
reverse DNS lookup that cost this probe its whole deadline on the maintainer's segment. Never
build that address from `new InetSocketAddress(String, int)` again; go through `namedAddress`.

**Running the suite on the Windows box:** `mvn test` cannot (no surefire provider cached). Either
IntelliJ per class, or the hand-rolled JUnit launcher in `.claude/tools/` (`RunTests.java` +
`cp.txt`; whole suite ≈ 15 s). `cp.txt` is a snapshot and drifts — the launcher jar and the Bouncy
Castle versions both had to be repointed on 2026-09-19/20; a wave of `NoClassDefFoundError` from
the launcher means the snapshot, not the code.

Live verification is the primary gate for anything touching the network; the unit tests
deliberately touch no sockets, save the two named above (loopback and local pools only).

## Next up

1. **Vulnerability scanning** — the largest gap; nothing is implemented in either generation. The
   SSL-Labs parity checklist in `ACTION-PLAN.md` → *Pending Issues → item 1* (padding-oracle
   family, named-CVE probes, renegotiation, downgrade posture, DH/ECDH hygiene, intolerance) is
   still authoritative. It wants a new action (e.g. `vuln-check`) plus registry + validator entries.
2. **FSM traversal tests** — `ProbeContext` needs an injection seam to be driven by scripted
   callbacks so each branch (banner match, `nomatch`, `timeout`, STARTTLS, reconnect) is assertable
   without a live server. The only significant untested area.
3. **HTTP security headers + CNSA 2.0 compliance** — the remaining Sprint 4/5 features.
4. **Merge chores** — done 2026-09-12 (packages collapsed, `/probes/` bundled, docs at the module
   root, `http_server_config.json` on `service.Checker`).
5. **Smaller open items** — none left from the old list (C1, the `DMTool` Mongo default, closed
   2026-09-12: the URL now comes only from `db-url=`, `NOSNEAK_DB_URL` or `-Dnosneak.db.url`). The rest
   is done: named-group enumeration, network OCSP + CRL, weak/insecure cipher candidates (now
   per-probe toggles), UDP scan, timing templates, `--top-ports`; `-O` and raw SYN scans are
   rejected by policy, not deferred. **The v1 parity pass is complete (2026-09-12, see
   `V1-V2-MERGE-ANALYSIS.md` → *Status after the fix pass*)** — nothing v1 had is missing from v2,
   so the merge is now only the deletion/rename described there.

> **Host discovery is no longer nmap's gap (2026-07-29).** `no-sneak-core` depends on
> **`no-sneak-net`**. An on-link CIDR goes through **`HostScanner.sweep()`** — the module's
> purpose-built range sweep (ARP + ICMP per host, its own tuned pacing); everything else
> (hostnames, off-link IPs, dash-ranges) takes a per-host path of TCP-ping + `ping` + `resolve`.
> Either way a scan reports the remote **MAC address**, which no JDK API can provide and which
> `HostReport.mac` had declared but never populated. `-PR` is ARP-only, `-PE` ICMP-only. Verified
> on a live `/24`: 254 targets, 22 up, all with MACs, in **1.6 s**.
>
> The lesson worth keeping: hand-rolling that sweep out of per-host `resolve`/`ping` calls cost
> **55 s** for the same result. When `no-sneak-net` offers a primitive, use it rather than
> rebuilding it from its lower-level calls.
>
> Related: the executor and scheduler are **injected everywhere** (taken from the `NIOSocket`, or
> passed explicitly); only the CLI `main` methods and `Checker.checkQDZDirect` name
> `TaskUtil.default*`. The REST `/check-qdz` endpoint is fully async and has no blocking call.
> See `v2/PLAN.md` for the accompanying defect pass.
