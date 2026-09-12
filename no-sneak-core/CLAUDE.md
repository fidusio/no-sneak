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
- **Fan-out** — `Fanout` + `ParallelJoin`: a second `StateMachine` whose executor is
  `TaskUtil.defaultTaskProcessor()`, one `TriggerConsumer` per child, published in parallel. This
  is how version/cipher enumeration runs one connection per candidate.
- **Candidate sweep** — `ProbeChecker` launches every candidate probe at once and elects the
  highest-priority completion as soon as no better candidate can still win, then cancels the rest.

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
├── runtime/                ProbeContext (the engine's config object) · ProbeEngine · Fanout · ParallelJoin
│                           ProbeTCPCallback (raw) · ProbeSecureCallback (JSSE) · ProbeUDPCallback
├── action/                 the fixed action library + ActionRegistry (name → singleton)
├── tls/                    PQCHandshakeStateMachine · PQCSessionConfig · PQCTlsClient (BC, ML-KEM groups)
├── analysis/               TLSProbeCallback base · Cipher/VersionProbeCallback · RevocationChecker
├── grade/                  Grade — letter, PQC readiness, TrustVerdict, advisories
├── result/                 ProbeResult (+ CertInfo, ConnectionTrace)
├── nmap/                   NMapScanner (staged) · NMap CLI · PortScanCallback · ScanGate · output/
├── service/                Checker — REST /check-qdz/{domain}/{detailed}
└── tools/                  DMTool · NoSneakUtil

src/main/resources/probes/   18 bundled + 2 unbundled probe definitions
src/test/java/io/xlogistx/nosneak/   368 pure, no-network tests in 32 classes (2026-09-12) + NoSneakNIOHTTPServer harness;
                                    model/ProbeDefinitionGuideTest pins PROBE-DEFINITION.md to the loader
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

Live verification is the primary gate for anything touching the network; the unit tests
deliberately touch no sockets.

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
5. **Smaller open items** — `DMTool`'s stale hardcoded Mongo URL (C1). The rest of the old list
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
