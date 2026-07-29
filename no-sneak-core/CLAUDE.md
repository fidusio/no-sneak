# NoSneak Core (`no-sneak-core`)

The scanning engine: a **TLS/PQC posture scanner** and a **network scanner**, both driven by one
JSON-declared, fully non-blocking state machine. Everything else in the repo is a front-end over
this module.

> **Status (2026-07-26).** The module exists twice. **`io.xlogistx.nosneak.v2` is the module
> going forward** — a from-scratch rebuild on a single non-blocking core. When the maintainer
> merges, the v1 packages (`nmap`, `probe`, `scanners`, `services`, `tools`) are **deleted** and
> v2's package path collapses to `io.xlogistx.nosneak`. That is why **no v2 class carries a `v2`
> suffix** — the names are already final.
>
> **The consequence that matters: anything v1 has and v2 lacks is a regression, not a TODO.**
> Do not fix v1 bugs; v1 is frozen. Treat `ACTION-PLAN.md`'s findings as a coverage checklist
> against v2 (it now carries a table saying which are moot, open, or fixed).

---

## Where to read next

| Doc | Covers |
|---|---|
| `src/main/java/io/xlogistx/nosneak/v2/PLAN.md` | **Start here.** v2 migration status, phase log, architecture decisions, and the running verification record |
| `src/main/java/io/xlogistx/nosneak/v2/PROBE-CONFIG.md` | v2 reference: action library, candidate selection, bundled probes, result fields, tests, deferrals |
| `PROBE-CONFIG.md` | Probe-authoring tutorial (written for v1; the DSL is unchanged in v2) |
| `ACTION-PLAN.md` | v1 history, the open-defect checklist, and the SSL-Labs parity backlog |
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

1. **v2 never references v1**, and no v2 class name contains "v2".
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

## Layout (v2)

```
io.xlogistx.nosneak.v2
├── ProbeChecker            library API + CLI: two-tier candidate selection, concurrent sweep
├── model/                  ProbeDefinition · ProbeState · PatternRule · ProbeDefinitionLoader (validates)
├── runtime/                ProbeContext (the engine's config object) · ProbeEngine · Fanout · ParallelJoin
│                           ProbeTCPCallback (raw) · ProbeSecureCallback (JSSE) · ProbeUDPCallback
├── action/                 the fixed action library + ActionRegistry (name → singleton)
├── tls/                    PQCHandshakeStateMachine · PQCSessionConfig · PQCTlsClient (BC, ML-KEM groups)
├── analysis/               TLSProbeCallback base · Cipher/VersionProbeCallback · RevocationChecker
├── grade/                  Grade — letter, PQC readiness, TrustVerdict, advisories
├── result/                 ProbeResult (+ CertInfo, ConnectionTrace)
├── nmap/                   NMapScanner (staged) · NMap CLI · PortScanCallback · RateLimiter · output/
├── service/                Checker — REST /check-qdz/{domain}/{detailed}
└── tools/                  DMTool · NoSneakUtil

src/main/resources/v2/probes/   18 bundled probe definitions (becomes /probes/ at merge)
src/test/java/io/xlogistx/nosneak/v2/   79 pure, no-network tests
```

## Build, test, verify

```bash
mvn clean install -pl no-sneak-core -am

# tests are skipped by the parent pom (xlogistx-mvn sets <skipTests>true</skipTests>)
mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.v2.**'

# live check against a real endpoint
mvn -pl no-sneak-core dependency:build-classpath -Dmdep.outputFile=cp.txt -DincludeScope=runtime
java -cp "target/classes;$(cat cp.txt)" io.xlogistx.nosneak.v2.ProbeChecker example.com 443
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
4. **Merge chores** (do these when the maintainer merges, not before): `/v2/probes/` → `/probes/`
   with `ProbeDefinitionLoader.BUNDLED`; move `PLAN.md`/`PROBE-CONFIG.md` out of the source tree to
   the module root; repoint `src/test/resources/http_server_config.json` from
   `services.QDZChecker` to `v2.service.Checker`.
5. **Smaller open items** — named-group enumeration (A12), active/network OCSP (only stapled is
   implemented), weak-cipher candidates in the enumeration sweep, `DMTool`'s stale hardcoded Mongo
   URL (C1), and the nmap parity list (UDP scan, timing templates, `--top-ports`, `-O`, the
   Panama-FFM raw-socket layer for SYN scans and OS fingerprinting).

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
