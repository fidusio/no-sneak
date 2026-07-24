# NoSneak SSL/TLS & PQC Scanner - Action Plan

> Last Updated: 2026-07-23
> Status: **Phase 3 Complete** - Pure NIO Callback Architecture (No CompletableFuture/ForkJoinPool)

---

## Code Analysis — Known Issues & Findings (2026-07-23)

Full-module review of `no-sneak-core` (~13.2k LOC). Findings are grouped by
subsystem and ordered **most severe first** within each group. File:line refs
are as of this date. Nothing below has been fixed yet — these are recorded so
work can resume across sessions. Checkboxes track remediation.

### A. PQC/TLS scanner (`scanners/`, `services/QDZChecker`)

**Correctness / concurrency (high):**
- [ ] **A1 — Data race on shared `resultBuilder`.** `PQCScanCallback.onHandshakeComplete`
  (`PQCScanCallback.java:178`) is **not** synchronized, yet Phase-2 callbacks mutate
  the same `PQCScanResult.Builder` from three different threads: revocation
  (HTTP/scheduler thread, `onRevocationComplete` ~`:340`), cipher/version probes
  (selector thread), and the watchdog (scheduler thread, `onScanTimeout` ~`:151`).
  The `resultBuilder` reference is `volatile` but its internal fields are plain →
  visibility/ordering race. Fix: guard all builder mutations with the same monitor
  used for `deliverResult`/`onError`.
- [ ] **A2 — Watchdog delivers ERROR instead of the promised partial result.**
  `onScanTimeout` calls `resultBuilder.errorMessage(...)` (`PQCScanCallback.java:153`),
  but `Builder.errorMessage` sets `success=false, secure=false, overallStatus=ERROR`
  (`PQCScanResult.java:740-746`), and `build()` then forces `overallStatus=ERROR` for
  any `!success` (`:1020`). So a scan that completed the handshake but stalled in one
  Phase-2 probe is reported as a total failure, discarding good data. Fix: deliver a
  partial result that keeps the handshake status and only annotates the stalled stage.
- [ ] **A3 — `onCipherEnumerationDone` is not idempotent.** Guard only returns when
  *not* both TLS1.3+TLS1.2 phases are done (`PQCScanCallback.java:447`); once both are
  done, a second invocation falls through and calls `checkCompletion()` again →
  can over-decrement `pendingCount` and deliver early. Many call sites
  (`:378,382,409,413,437,441` + preference path). Fix: `AtomicBoolean` one-shot guard
  like `TLSProbeCallback.complete()`.

**Dead / legacy code (medium):**
- [ ] **A4 — `CipherSuiteEnumerator` and `ProtocolVersionTester` are blocking
  `java.net.Socket` reimplementations** (`CipherSuiteEnumerator.java:163-315`,
  `ProtocolVersionTester.java:120-232`), contradicting the pure-NIO mandate, and used
  only by `FeatureIntegrationTest`. The live path reimplements enumeration in
  `PQCScanCallback` + `CipherProbeCallback`/`VersionProbeCallback`. Only the nested
  `CipherInfo` class and static `getVersionName`/`getCipherSuiteName` helpers are used.
  Fix: extract the helpers, delete the dead blocking logic.
- [ ] **A5 — Redundant PQC key-group capture.** `PQCTlsClientProtocol` intercepts
  `process13ServerHello` and exposes `negotiatedNamedGroup`/`isPQCHybridKeyExchange()`
  (`PQCTlsClientProtocol.java:44-100`) that nothing reads — the orchestrator uses
  `tlsClient.getNegotiatedKeyExchangeName()` instead. Pick one mechanism.
- [ ] **A6 — Deprecated/superseded members.** `PQCNIOScanner.verifyCertificateChain`
  is a `@Deprecated` unused shim (`:243-255`); `Builder.certChainValid` superseded by
  `certChainTrust` (`PQCScanResult.java:865`); `revocationMethod/Error/Date/Reason`
  single setters superseded by `revocationResult` (`:887-923`);
  `NIORevocationChecker.DEFAULT_TIMEOUT_MS`/`shutdown()` vestigial (`shutdown` is no-op).

**Minor:**
- [ ] **A7 — `parseOCSPResponse` blind-casts** to `HTTPResponseData`
  (`NIORevocationChecker.java:251`) → `ClassCastException` risk (surfaces as UNKNOWN).
- [ ] **A8 — `keyExchangeKeySize` never populated** (always 0), even for PQC groups
  (`PQCScanResult.java:534`).
- [ ] **A9 — Swallow-but-print `catch` blocks** (`PQCNIOScanner.java:62`,
  `PQCSessionConfig.java:62`).
- [ ] **A10 — `PQCScanOptions.defaults()` enables `testTLS10`/`testTLS11`** (`:42-43`),
  so deprecated versions get probed whenever `testProtocolVersions` is on.

**Missing features (ACTION-PLAN Sprint 4/5, all unimplemented):**
- [ ] **A11 — No vulnerability scanning at all** (POODLE/BEAST/Heartbleed/ROBOT/DROWN/
  SWEET32, renegotiation RFC 5746, downgrade/`TLS_FALLBACK_SCSV`, CRIME, session
  resumption). See "Pending Issues → item 1" checklist.
- [ ] **A12 — No server-side cipher/named-group enumeration** — scanner only advertises
  its own groups (`PQCTlsClient.java:98`), never enumerates the server's accepted set.
- [ ] **A13 — No HTTP security-header analysis and no grading engine.**

### B. nmap scanner (`nmap/`)

**Correctness (high):**
- [ ] **B1 — `-sS` throws instead of scanning.** `-sS` sets `ScanType.SYN`, but
  `NMap.main` only registers TCP_CONNECT/UDP engines (`NMap.java:102-107`), so
  `engines.get(SYN)` is null and `scanStreaming` throws
  `IllegalStateException: No engine registered for scan type: SYN`
  (`NMapScanner.java:201-209`). The `!isAvailable()` fallback (`:211`) never fires
  because it needs a non-null engine. Fix: register a fallback or map SYN→TCP_CONNECT.
- [ ] **B2 — All raw/stealth engines are fake and mislabeled.** `SYNScanEngine`,
  `FINScanEngine`, `ACKScanEngine`, `XmasScanEngine`, `NullScanEngine`,
  `WindowScanEngine` are empty subclasses of `RawScanEngine`, which just does a TCP
  connect (Java NIO can't do raw sockets, `RawScanEngine.java:21-27`). Subclass Javadoc
  falsely claims "delegates to nmap -sS / requires root." `isAvailable()` always true
  while `requiresPrivileges()` reports true — contradictory. Fix: either implement via
  JNI/pcap, or remove these types and stop advertising them.
- [ ] **B3 — `service/` and `os/` packages are entirely dead code.** `ServiceDetector`
  + 6 probes (`HTTP/SSH/FTP/SMTP/TLS/GenericBanner`) and `OSDetector`/`OSFingerprint`
  are never instantiated by the scan pipeline. `-sV` only captures a raw banner string
  (`TCPPortScanCallback.java:90-105`) that never becomes a parsed `service` and only
  shows in JSON/CSV; `PortResult.hasService()` is always false so Normal/Grepable/XML
  SERVICE/VERSION columns are always blank. `osDetection` config flag does nothing.

**Correctness (medium):**
- [ ] **B4 — `ICMPPing` latency bug.** On `ConnectException` fallback, latency is set to
  `System.currentTimeMillis()` (epoch millis, not elapsed) → absurd values
  (`ICMPPing.java:107`).
- [ ] **B5 — TCP-only port spec scans nothing.** `getPortsForEngine` returns
  `getTcpPortList()` for TCP engines; a spec of only `U:` ports yields an empty TCP list
  and a `-sT` scan silently scans zero ports (`NMapScanner.java:345-361`).
- [ ] **B6 — Banner-grab stall risk.** With `grabBanner` true and a silent server,
  `connectedFinished()` returns without completing and relies on an externally-invoked
  `timeout()` (`TCPPortScanCallback.java:155`); if not called, that port future never
  completes.

**Design / consistency (low):**
- [ ] **B7 — `ARPPing` shells out** to `arp -a`/`arp -n` via `ProcessBuilder`
  (`ARPPing.java:143-201`), contradicting `NMapScanner`'s "no external commands" Javadoc
  (`NMapScanner.java:31`).
- [ ] **B8 — Blocking on async threads** — every engine does `Thread.sleep(probeDelayMs)`
  on the calling thread (`RawScanEngine.java:137`, `TCPConnectScanEngine.java:162`,
  `UDPScanEngine.java:184`); discovery uses blocking `java.net.Socket`.
- [ ] **B9 — `-oA` omits CSV** (`NMap.java:206-216`); unguarded `Integer.parseInt` on
  `--top-ports`/parallelism → uncaught `NumberFormatException`; `--top-ports` >100
  silently truncates (`PortSpecification.java:186-192`).
- [ ] **B10 — Declared-but-unimplemented scan types** — `MAIMON`, `IP_PROTOCOL`,
  `SCTP_INIT`, `SCTP_COOKIE` in `ScanType` with no engines/flags.
- [ ] **B11 — XML vs JSON confidence mismatch** — XML emits `conf=confidence/10`,
  JSON emits raw 0–100 (`XMLFormatter.java:186` vs `JSONFormatter.java:203`); moot while
  service is never set.
- [ ] **B12 — Dead members** — commented-out `NMapScanner.executor`
  (`:39,53`), `HostDiscovery.executor`, `UDPScanEngine.nioSocket`, unused
  `ScanEngine.asyncScan*`, unused `startTime` local (`NMap.java:110`).

### C. `tools/` (admin utilities, unrelated to scanning)

- [ ] **C1 — `DMTool` hardcodes a MongoDB default URL**
  (`mongodb://localhost:27017/...`, `DMTool.java:38`) though recent git history moved the
  datastore to local H2 — likely stale.
- [ ] **C2 — `NoSneakUtil.createDomainSecManager` latent NPE-return.** If `DATA_STORE`
  is cached but `DOMAIN_MANAGER` is not, `dsm` stays null and null is returned
  (`NoSneakUtil.java:36-57`) — the creation branch only runs when the datastore is also
  absent.

### D. Cross-cutting

- [ ] **D1 — README top line is wrong** — says the module is an empty placeholder; it is
  ~13.2k LOC across two working subsystems.
- [ ] **D2 — Documentation drift** — this ACTION-PLAN and class Javadoc still reference
  non-existent names (`PQCCallback`/`ScannerMotherCallback`; actual class is
  `PQCScanCallback`), a `PQCConnectionHelper.java`, and a `/check-qdz/{domain}/{port}/{timeout}`
  URI (actual is `/check-qdz/{domain}/{detailed}`, `QDZChecker.java:39`).
- [ ] **D3 — "Pure NIO / non-blocking" holds in the scan core but not at boundaries** —
  `NMapScanner.scan()` joins, `RawScanEngine` sleeps, `QDZChecker` calls
  `future.join()` (`QDZChecker.java:76`).

---

## Probe Framework — JSON-declared FSM protocol prober (2026-07-23)

A JSON-declared, state-machine **protocol-probe framework** in package
`io.xlogistx.nosneak.probe`. It drives multi-step, possibly multi-connection interrogations of
an open `ip:port` over the existing zoxweb NIO primitives and emits a **facts-only**
`ProbeResult` (for a future rules/record layer). Behavior is **data-driven** (JSON picks
states / transitions / payloads / patterns) but every executable primitive is a **fixed,
trusted Java class** — JSON never executes arbitrary code. Built, compiled, and **verified
live** against real servers (see "Verification").

### Package layout

```
io.xlogistx.nosneak.probe
├── ProbeChecker.java          identify a port by running probes; library API + CLI main()
├── ProbeDispatcher.java       nmap seam: open ip:port → select ProbeDefinition → run ProbeSession
├── ProbeResult.java           facts-only output (+ toNVGenericMap())
├── model/
│   ├── ProbeDefinition.java   GSON: name/service/transport/ports/priority/start/states
│   ├── ProbeState.java        GSON: action + on{} + config (payload/data/patterns/command/ready/mode/note/port)
│   ├── PatternRule.java       GSON: {regex, outcome} (lazy-compiled Pattern)
│   └── ProbeDefinitionLoader.java  load classpath /probes/*.json OR filesystem files + graph validation
├── runtime/
│   ├── ProbeStateMachine.java builds a zoxweb org.zoxweb.server.fsm.StateMachine from the JSON
│   ├── ProbeSession.java      execution context: NIO ingress, mode switch, result builder, watchdog
│   ├── ProbeTCPCallback.java  extends TCPSessionCallback; NIO events → session ingress
│   └── ProbeUDPCallback.java  deferred UDP seam (stub)
├── action/
│   ├── Action.java            interface (name + execute(session, state))
│   ├── ActionRegistry.java    name → singleton Action
│   ├── ProbeActionConsumer.java  TriggerConsumer bridge: one per state, runs the Action
│   ├── ConnectAction · SendAction · ExpectAction · StartTLSAction
│   ├── TLSHandshakeAction · PQCCheckAction · TLSFactsAction · RecordAction · ReconnectAction
│   └── TerminalAction         done / fail
└── discovery/
    └── HardenedHostDiscovery.java  parallel ICMP + NIO TCP-connect (RST = up)

src/main/resources/probes/
├── https-pqc.json          443/8443 direct-TLS, PQC classification
├── https-classical.json    443/8443 direct-TLS, fully classical handshake (mode:"jsse")
├── smtp-starttls-pqc.json  25/587 STARTTLS → PQC
├── smtp-starttls.json      25/587 STARTTLS, TLS facts only (no PQC)
├── imap-starttls-pqc.json  143 STARTTLS → PQC
├── imaps-pqc.json          993 implicit TLS → PQC
└── mongodb.json            27017-9 binary isMaster OP_QUERY handshake
   (BUNDLED = https-pqc, smtp-starttls-pqc, mongodb, imaps-pqc, imap-starttls-pqc;
    https-classical + smtp-starttls are standalone files, run via an explicit path.)
```

### Architecture / control flow

```
ProbeChecker / ProbeDispatcher ─▶ ProbeSession (live channel, ProbeResult.Builder, watchdog)
                                       ▼ builds + drives
                                 ProbeStateMachine  →  org.zoxweb.server.fsm.StateMachine
                                       │  each JSON state = a State (canonical id = state id)
                                       │  carrying a ProbeActionConsumer (TriggerConsumer)
                                       ▼  entering a state = publishSync(state, id, session)
                                 Action library (fixed Java)
                                 connect·send·expect·starttls·tls-handshake·pqc-check·tls-facts·record·reconnect·done·fail
                                       ▲  NIO events via ProbeTCPCallback → session.fire(outcome)
                                       │  tls-handshake/pqc-check reuse PQCSessionConfig·PQCSSLStateMachine·PQCTlsClient·OPSecUtil
                                       ▼
                                 ProbeResult (facts-only; toNVGenericMap())
```

An action reports an **outcome label** — synchronously (`send`, `record`, `pqc-check`,
`tls-facts`) or later from a NIO/scheduler event (`connect`, `expect`, `tls-handshake`) — via
`ProbeSession.fire(label)`. `ProbeStateMachine.fire` resolves the current state's `on{}` map and
`publishSync`es the next state's trigger. One `ProbeSession` outlives individual connections, so
`reconnect` swaps in a fresh `ProbeTCPCallback` while the machine + accumulated `ProbeResult`
persist — that is what makes multi-connection probes work.

**Mode switch on one channel:** `ProbeSession` tracks a `Mode` (`CONNECTING`/`EXPECT`/`TLS`).
Inbound bytes go to the plaintext `expect` matcher or into the reused BC handshake pump. The
STARTTLS upgrade works because `tls-handshake` starts the BC handshake on the **current
already-open channel** (`PQCSessionConfig.channel = currentCallback.getChannel()`).

**Concurrency:** all transitions run on the NIO selector or task-scheduler thread, serialised
through `fire()`/`deliver()`/ingress (all `synchronized`). Each async wait is guarded by an
`armed` CAS **plus an `armGen` epoch** so a stale timeout from a previous wait window can't
resolve a later one. Terminal delivery is exactly-once (`terminated` CAS + overall watchdog).

### JSON model & outcome labels

```jsonc
{ "name": "smtp-starttls-pqc", "service": "smtp", "transport": "tcp",
  "ports": [25, 587], "priority": 60, "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "banner", "error": "fail", "timeout": "fail" } },
    "banner":  { "action": "expect", "patterns": [{ "regex": "^220[ -]", "outcome": "ok" }],
                 "on": { "ok": "ehlo", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "done": { "action": "done" }, "fail": { "action": "fail" } } }
```

Outcome labels (map in `on{}`): `connect`/`reconnect` → `connected`·`error`·`timeout`;
`send` → `sent`·`error`; `expect` → any pattern `outcome`·`nomatch`·`error`·`timeout`;
`starttls` → `ready`·`nomatch`·`error`·`timeout`; `tls-handshake` → `handshaked`·`error`·`timeout`;
`pqc-check`/`tls-facts`/`record` → `done`.

Validation (`ProbeDefinitionLoader.validate`): start state exists, every `on` target resolves,
every action is known, ≥1 terminal (`done`/`fail`) reachable from start. Unknown JSON fields are
ignored (forward-compatible).

### Capabilities

- **Binary protocols** — `send` accepts a codec-prefixed **`data`** field: `hex:…`
  (`SharedStringUtil.hexToBytes`), `base64:…` (`SharedBase64.decode`), or `text:…`/unprefixed
  (templated UTF-8). `data` beats the legacy `payload` when both present. `expect` decodes the
  buffer as **ISO-8859-1** (lossless 0–255) so regexes on ASCII markers match inside binary
  responses (e.g. BSON `ismaster`/`maxWireVersion` in a Mongo reply).
- **TLS/PQC** — `tls-handshake` `mode:"pqc"` (default) advertises ML-KEM hybrids
  (X25519MLKEM768, …) + classical; `mode:"jsse"`/`"classical"` advertises **only classical**
  groups (fully classical handshake), via a `classicalOnly` flag through `PQCTlsClient` →
  `PQCSessionConfig`. `pqc-check` records TLS facts + classifies PQC/CLASSICAL/UNKNOWN;
  `tls-facts` records the same TLS facts **without** any PQC classification.
- **STARTTLS** — mid-session plaintext→TLS upgrade on the same channel (SMTP/IMAP/POP3/FTP-style).
- **Hardened host detection** — `HardenedHostDiscovery`: parallel ICMP + NIO TCP-connect on
  443/80/22, first positive wins, RST (connection refused) counts as up.

### ProbeChecker

Identifies the protocol on `host:port` by running probes (first to reach a clean `done` wins,
priority order). `matchPorts(true)` (default, bundled/dispatcher path) runs only probes whose
declared `ports` include the target port; `matchPorts(false)` runs **every** provided probe of
the matching transport regardless of declared ports (for nonstandard ports).

CLI: `java … ProbeChecker <host> <port> [timeoutSec] [probe1.json probe2.json …]`. Integer args
= timeout; other args = probe JSON **files** (filesystem). With files given it runs them ALL
(`matchPorts=false`); with none it uses the bundled probes (port-matched). No rebuild needed to
try a new probe definition.

### Verification (live)

- `mvn -pl no-sneak-core -am compile` / `test-compile` → BUILD SUCCESS.
- `ProbeChecker google.com 443` → `https / DIRECT_TLS / PQC`, X25519MLKEM768, TLSv1.3.
- `ProbeChecker … https-classical.json` (mode jsse) → `x25519` / `pqc-status:CLASSICAL`
  (proves the classical handshake vs the PQC one on the same host).
- `ProbeChecker smtp.gmail.com 587 … smtp-starttls.json` → `smtp / STARTTLS_UPGRADED`, TLS facts,
  `pqc:UNKNOWN` (no PQC assessment, as designed).
- Loading all bundled probes validates the five graphs; `ProbeDefinitionLoaderTest` (pure,
  no-network) asserts graph validity + rejects malformed graphs + tests pattern matching.
  (Executing that JUnit test in this environment is blocked only by a missing offline Surefire
  provider — not a code issue.)

### Design decision & constraint on record

- **Outer FSM on `org.zoxweb.server.fsm.StateMachine`** (trigger-based). The JSON *builds* the
  machine: each state → a `State` (canonical id = state id) + a `ProbeActionConsumer`
  (`TriggerConsumer`) bridging to the trusted `Action`. An **inline executor** keeps transitions
  on the calling thread (no new threading). Migrating to a different engine touches only
  `ProbeStateMachine` + `ProbeSession.fire`.
- **NO `MonoStateMachine` anywhere in this project** (decision 2026-07-23). The outer FSM is
  compliant. Remaining violation (tech debt): the inner TLS/PQC handshake reuses
  `scanners/PQCSSLStateMachine`, which `extends MonoStateMachine` — kept so the framework works
  end-to-end, marked `TODO(no-monostatemachine)` in `ProbeSession`, slated for replacement by a
  direct BC pump (`offerInput`/`readOutput` over `PQCSessionConfig`) or the trigger-based
  `StateMachine`. No new code may extend/instantiate `MonoStateMachine`.

### Deferred (probe framework)

- **UDP QUIC/DTLS actions** — `ProbeUDPCallback` seam exists; datagram actions + per-remote-address
  state keying not built.
- **PQC-READY via `reconnect`** — `pqc-check` reports PQC vs CLASSICAL; a reconnect-based
  re-offer-hybrids readiness test (→ `PQC_READY`) is a future JSON definition (`reconnect` supports it).
- **Wire the seam** — call `ProbeDispatcher`/`ProbeChecker` from `NMapScanner`'s service-detection
  path and/or a REST endpoint; retire the blocking `nmap/service/ServiceDetector`.
- **Real JSSE `SSLEngine` handshake** — `mode:"jsse"` today is a classical BC handshake; a literal
  JDK `SSLEngine` pump is optional future work if exact stock-Java behavior must be tested.
- **App-data over an established TLS session** — `send`/`expect` operate on the raw socket, not
  through the TLS layer (fine for detection; blocks post-handshake application probing).
- **No-network FSM test** — an injection seam to drive `ProbeSession` with scripted callbacks and
  assert traversal paths per branch.

---

## Recent Completed Work (2026-05-16)

### Feature: Certificate trust hardening — PKIX-to-Root, expiry detail, UNTRUSTED status

The scanner previously did **not** validate the chain to a trusted Root CA
(`verifyCertificateChain` only checked intra-chain signature linkage), did not
verify hostname, collapsed expiry into one opaque boolean, and `overall-status`
ignored certificate validity entirely (an expired/untrusted cert could still
report `READY`). Fixed:

- **W1 — PKIX chain validation (`OPSecUtil.validateChain`)**: JCA
  `CertPathValidator("PKIX")` against the JDK `cacerts` trust store
  (overridable via `javax.net.ssl.trustStore`), revocation disabled (handled
  separately, soft-fail). Returns `ChainTrustResult` /
  `ChainTrust` ∈ `TRUSTED | UNTRUSTED_ROOT | INCOMPLETE_CHAIN | SELF_SIGNED |
  EXPIRED_IN_CHAIN | INVALID_SIGNATURE | UNKNOWN`. Trust store unavailable →
  `UNKNOWN` (soft-fail, never throws/blocks).
- **W2 — Hostname check (`OPSecUtil.matchesHostname`)**: RFC 6125 SAN
  dNSName (single leftmost-label wildcard) / iPAddress, CN fallback.
  **Report-only.**
- **W3 — Expiry detail**: `cert-validity-state` ∈ `VALID | EXPIRED |
  NOT_YET_VALID`; `cert-chain-time-valid` covers intermediates/root.
- **W4 — `PQCStatus.UNTRUSTED`** (new; outranks READY/PARTIAL/NOT_READY,
  distinct from ERROR). `build()` forces UNTRUSTED on: leaf EXPIRED /
  NOT_YET_VALID, chain not trust-anchored, expired-in-chain, or
  `certRevoked==true` — **independent of PQC readiness**. Hostname mismatch is
  report-only (recommendation, no status change), per decision.
- **W5** — wired into `PQCScanCallback.onHandshakeComplete`; new
  `cert-*` keys in `toNVGenericMap` (additive, kebab-case) + `toString`;
  `PQCNIOScanner.verifyCertificateChain` is now a `@Deprecated` shim
  delegating to `OPSecUtil.validateChain`.
- **W4b** — new `RevocationStatus.NOT_SUPPORTED` (method `"NOT_SUPPORTED"`):
  cert has no OCSP URL and none stapled (CA design — Let's Encrypt). Distinct
  from `UNKNOWN` (issuer-missing/timeout, method `"NOT_CHECKED"`/`"TIMEOUT"`)
  so Sprint-5 grading won't penalize the normal LE case. `NIORevocationChecker`
  short-circuit split accordingly; `PQCScanResult` switch maps it explicitly.
- **W4c** — concise `trust-verdict` (`TrustVerdict` enum) + `trust-reason`
  computed in `Builder.build()` (reusing the UNTRUSTED conditions) and
  serialized, so the website/UI consumes one authoritative verdict instead of
  re-deriving trust from several keys.
- **W5c** — `cert-chain[]` now includes the **Root CA**: servers don't send
  it, so on a `TRUSTED` result the PKIX-matched trust anchor
  (`OPSecUtil.ChainTrustResult.getTrustAnchor()`, from the cacerts store) is
  appended by `PQCScanCallback` as the final `role:"root"` entry (skipped if
  the server already terminated with a self-signed root). Chain-time-validity
  now also covers the root. Verified live (cloudflare.com → 4 entries ending
  in self-signed GlobalSign Root CA).
- **W5b** — `cert-chain[]` per-certificate breakdown in `toNVGenericMap`
  (`index`, `subject`, `issuer`, `not-before`, `not-after`, `time-valid`,
  `validity-state`, `self-signed`, `is-ca`, `role`) so a detailed scan shows
  *which* link failed, not just the aggregate verdict.
- **W6** — `PQCCallbackTest.testCertificateTrust` (badssl.com:
  expired / self-signed / untrusted-root / wrong-host + valid control;
  network-unreachable cases are skipped, not failed).

**Decisions:** trust anchors = JDK cacerts; trust failure → new `UNTRUSTED`
state; hostname mismatch = report-only.

**Files:** `opsec/OPSecUtil.java`, `PQCScanResult.java`, `PQCScanCallback.java`,
`PQCNIOScanner.java`, `PQCCallbackTest.java`, docs.

**Out of scope (future):** intermediate revocation, CT/SCT/CAA, SSL-Labs grading
(this is its prerequisite).

---

## Recent Completed Work (2026-05-15)

### Fix: Revocation no longer hangs/slows the scan — stapled OCSP + fast soft-fail

**Problem:** Detailed scans of Let's Encrypt-style hosts (`xlogistx.io`, `upbound.io`)
hung, then (after a first round of timeout fixes) took a hard 10s. Root cause:
`NIORevocationChecker` had no timeout and, for certs with no usable OCSP, fell
through to a **CRL download** (Let's Encrypt CRLs are huge / often unreachable) —
a never-answering request that never invoked its callback, so the scan's
`pendingCount` never decremented. A plain TLS handshake (JSSE `SSLEngine`) does
**not** check revocation at all by default; our checker was the only thing
blocking on a third-party endpoint.

**Resolution order now (fastest first):**
1. **Stapled OCSP (zero network, instant)** — `PQCTlsClient` sends the RFC 6066
   `status_request` extension and captures any handshake-stapled OCSP response;
   `PQCScanCallback` passes the DER bytes to `NIORevocationChecker`, parsed
   in-memory. Method reported as `OCSP_STAPLED`.
2. **Short-circuit (instant)** — no staple + (no issuer **or** no OCSP URL) →
   immediate `UNKNOWN / NOT_CHECKED`. **CRL fetching removed entirely** (it was
   the black hole). Browser-equivalent soft-fail.
3. **Active OCSP (bounded soft-fail)** — only when stapling absent *and* an OCSP
   URL + issuer exist: one OCSP POST, **5s** soft-fail (was 10s), any failure →
   `UNKNOWN`, never `REVOKED`, never CRL. Runs in parallel with cipher/version
   enumeration so it adds ~0 wall time.

**Supporting robustness (same effort):**
- `TLSProbeCallback` — post-connect handshake timeout (scheduler-based) +
  exactly-once completion guard (selector vs scheduler race).
- `PQCScanCallback` — master scan watchdog (`overallTimeoutInSec`, default 90s)
  delivers a partial/error result naming the stalled stage; fixed a latent
  `deliverResult()`→`onError()` no-op hang (delivered flag set too early).
- `NIORevocationChecker` — one-shot guarded callback, in-flight `HTTPURLCallback`
  closed on resolve/timeout (fd-leak fix), register-or-close guard closing the
  timeout-vs-fallback race.

**Files:** `PQCTlsClient`, `NIORevocationChecker`, `PQCScanCallback`,
`TLSProbeCallback`, `QDZChecker`, `PQCCallbackTest`
(new `testDetailedScanMultipleHosts`).

---

## Recent Completed Work (2026-02-04)

### Refactor: Pure NIO Callback Architecture — Eliminated CompletableFuture/ForkJoinPool

Replaced the `CompletableFuture`-based scanner pipeline with a pure NIO callback architecture.
`PQCCallback` is now the main entry point, orchestrating child probes via callbacks on the NIO selector thread.

#### New Files Created
- [x] **ScanCallback.java** - Interface between PQCNIOScanner and PQCCallback
  - `onHandshakeComplete(PQCSessionConfig)` - Phase 1 complete
  - `onError(String)` - Error handling
- [x] **TLSProbeCallback.java** - Abstract base class for NIO TLS probes
  - Extends `TCPSessionCallback`, handles non-blocking TLS handshake
  - Subclasses implement: `createTlsClient()`, `onProbeSuccess()`, `onProbeFailure()`
- [x] **CipherProbeCallback.java** - NIO cipher enumeration probe
  - Iterative chain: connect → note selection → remove → repeat
  - Reports via `CipherProbeListener`
- [x] **VersionProbeCallback.java** - NIO protocol version probe
  - Tests individual TLS/SSL versions
  - Reports via `VersionProbeListener`
- [x] **PQCCallback.java** - Main orchestrator (renamed from ScannerMotherCallback)
  - Constructor: `(IPAddress, Consumer<PQCScanResult>, PQCScanOptions, HTTPNIOSocket)`
  - `start()` registers PQCNIOScanner with NIOSocket
  - Phase 2 tasks tracked via `AtomicInteger pendingCount`
  - Zero blocking — completion triggers `userCallback.accept(result)`
- [x] **PQCCallbackTest.java** - Tests for PQCCallback

#### Modified Files
- [x] **PQCNIOScanner.java** - Simplified
  - Now uses `ScanCallback` instead of `Consumer<PQCScanResult>`
  - Removed: options, httpNIOSocket, revocationChecker, cipherEnumerator, protocolTester
  - Only does Phase 1 (TLS handshake), Phase 2 handled by PQCCallback
- [x] **NIORevocationChecker.java** - Pure callback-based
  - Removed all `CompletableFuture` methods (`checkRevocationAsync`, `checkOCSPAsync`, `checkCRLAsync`)
  - Only callback-based: `checkRevocation(cert, issuer, Consumer<RevocationResult>)`
- [x] **QDZChecker.java** - Uses PQCCallback
  - Replaced `PQCNIOScanner` with `PQCCallback`
- [x] **PQCScannerTest.java** - Adapted tests
  - Uses `PQCCallback` for NIO scanner tests
  - Helper method tests use static `PQCNIOScanner.parseKeyExchangeType()` etc.

#### Architecture
```
User creates PQCCallback
         │
         ▼
    PQCCallback.start()
         │
         ▼ registers
    PQCNIOScanner (Phase 1: TLS Handshake)
         │
         ▼ calls
    ScanCallback.onHandshakeComplete()
         │
         ├─► NIORevocationChecker.checkRevocation() ──► callback
         ├─► CipherProbeCallback chain ──────────────► callback
         └─► VersionProbeCallback (parallel) ────────► callback
                                                          │
                                                          ▼
                                        pendingCount.decrementAndGet() == 0
                                                          │
                                                          ▼
                                               userCallback.accept(result)
```

---

## Previous Completed Work (2026-02-02)

### Refactor: Eliminated NIOHttpClient in favor of HTTPURLCallback + HTTPNIOSocket

Replaced the fake-async `NIOHttpClient` (blocking selector loop wrapped in `CompletableFuture`) with
the framework-native `HTTPURLCallback` + `HTTPNIOSocket` for truly event-driven, multiplexed HTTP.

#### Changes
- [x] **NIORevocationChecker** - Rewritten to use `HTTPNIOSocket` + `HTTPURLCallback`
  - Constructor takes `HTTPNIOSocket` instead of `int timeoutMs`
  - CRL downloads via `HTTPURLCallback` GET
  - OCSP requests via `HTTPURLCallback` POST with `HTTPMessageConfig.buildHMCI()`
  - No more thread-per-request blocking; multiplexed on shared NIO selector
- [x] **QDZChecker** - Uses `NIOHTTPServer.getHTTPNIOSocket()` to get shared `HTTPNIOSocket`
- [x] **NIOHTTPServer** - Added `getHTTPNIOSocket()` accessor; creates `HTTPNIOSocket` during `start()`
- [x] **NIOHttpClient.java** - DELETED (replaced entirely)

---

### Phase 2 Features - COMPLETED (2026-01-31)

#### Feature 1: CRL/OCSP Revocation Checking
- [x] **OPSecUtil.extractCRLDistributionPoints()** - Extract CRL URLs from certificate
- [x] **OPSecUtil.extractOCSPResponderURLs()** - Extract OCSP URLs from certificate
- [x] **OPSecUtil.extractCAIssuerURLs()** - Extract CA Issuer URLs from AIA extension
- [x] **OPSecUtil.checkCRL()** - Check certificate against CRL
- [x] **OPSecUtil.checkOCSP()** - Check certificate via OCSP responder
- [x] **OPSecUtil.checkRevocation()** - Combined check (OCSP first, CRL fallback)
- [x] **RevocationStatus enum** - GOOD, REVOKED, UNKNOWN, ERROR
- [x] **RevocationResult class** - Full result with method, date, reason
- [x] **PQCScanResult** - Added revocationMethod, revocationError, revocationDate, revocationReason fields

#### Feature 2: Cipher Suite Enumeration
- [x] **CipherSuiteEnumerator.java** - New class for cipher enumeration
  - Iterative enumeration algorithm (connect, note selection, remove, repeat)
  - TLS 1.3 and TLS 1.2 cipher suite support
  - Weak and insecure cipher testing (optional)
  - Server cipher preference detection
- [x] **CipherInfo class** - Cipher details (name, strength, key exchange, forward secrecy)
- [x] **EnumerationResult class** - List of supported ciphers with server preference flag
- [x] **OPSecUtil.CipherStrength enum** - STRONG, ACCEPTABLE, WEAK, INSECURE, UNKNOWN
- [x] **OPSecUtil.CipherComponents class** - Parsed cipher suite components
- [x] **OPSecUtil.classifyCipherSuiteStrength()** - Strength classification
- [x] **OPSecUtil.parseCipherSuite()** - Parse cipher name to components
- [x] **PQCScanResult** - Added supportedCipherSuites, serverCipherPreference fields

#### Feature 3: Protocol Version Testing
- [x] **ProtocolVersionTester.java** - New class for version probing
  - Tests TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSLv3
  - Individual version testing
  - Deprecated protocol detection
  - Security recommendations
- [x] **VersionTestResult class** - Supported versions with security analysis
- [x] **OPSecUtil.ProtocolSecurity enum** - SECURE, DEPRECATED, CRITICAL, UNKNOWN
- [x] **OPSecUtil.classifyProtocolVersionSecurity()** - Version security classification
- [x] **OPSecUtil.protocolSupportsPQC()** - Check if version supports PQC
- [x] **PQCScanResult** - Added supportedProtocolVersions, sslv3Supported, deprecatedProtocolsSupported

#### Feature 4: Scan Configuration
- [x] **PQCScanOptions.java** - Scan configuration builder
  - checkRevocation, revocationTimeoutMs
  - enumerateCiphers, includeWeakCiphers, includeInsecureCiphers
  - testProtocolVersions, testSSLv3, testTLS10, testTLS11
  - connectTimeoutMs, enumerationTimeoutMs
  - `PQCScanOptions.defaults()` and `PQCScanOptions.comprehensive()` factory methods

---

### PQC Scanner Core - COMPLETED (Phase 1)
- [x] **PQCNIOScanner** - Non-blocking TLS scanner with NIO integration
- [x] **PQCTlsClient** - BC TLS client advertising PQC hybrid algorithms (X25519MLKEM768, SecP256r1MLKEM768)
- [x] **PQCTlsClientProtocol** - Intercepts ServerHello key_share for PQC detection
- [x] **PQCSSLStateMachine** - State machine for async TLS handshake
- [x] **PQCScanResult** - Comprehensive result container
- [x] **QDZChecker** - REST endpoint `/check-qdz/{domain}/{port}/{timeout}`
- [x] **DNSRegistrar.resolve()** - Quick DNS resolution with caching

---

## Pending Issues / Next Steps

### Medium Priority
1. **Vulnerability Scanning Framework — SSL Labs parity checklist**

   Goal: parity with the SSL Labs / `testssl.sh` posture report. All probes
   must honor the no-sneak rules (pure NIO callbacks, BC TLS API, exactly-once
   completion, soft-fail/bounded, never hang the scan).

   **a. Padding-oracle & CBC family**
   - [ ] POODLE (SSLv3 padding oracle)
   - [ ] POODLE-TLS (TLS CBC padding oracle — distinct from SSLv3)
   - [ ] Zombie POODLE
   - [ ] GOLDENDOODLE
   - [ ] Sleeping POODLE
   - [ ] OpenSSL 0-Length padding-oracle
   - [ ] BEAST (TLS 1.0 CBC)
   - [ ] OpenSSL Padding Oracle (CVE-2016-2107)

   **b. Named-CVE / implementation probes**
   - [ ] Heartbleed (CVE-2014-0160) + Heartbeat extension presence
   - [ ] Ticketbleed (CVE-2016-9244)
   - [ ] OpenSSL CCS injection (CVE-2014-0224)
   - [ ] ROBOT (RSA PKCS#1 v1.5 oracle)
   - [ ] DROWN (SSLv2) + SSL 2 handshake compatibility
   - [ ] SWEET32 (64-bit block ciphers)

   **c. Renegotiation**
   - [ ] Secure renegotiation (RFC 5746) supported
   - [ ] Secure client-initiated renegotiation
   - [ ] Insecure client-initiated renegotiation

   **d. Protocol posture / downgrade**
   - [ ] Downgrade prevention (TLS_FALLBACK_SCSV)
   - [ ] SSL/TLS compression (CRIME)
   - [ ] RC4 as an explicit posture item
   - [ ] Forward Secrecy robustness rating
   - [ ] ALPN / NPN advertised
   - [ ] Session resumption (caching) / (tickets)
   - [ ] OCSP stapling as a posture item (yes/no; we already *consume*
         stapled OCSP for revocation — surface it here too)
   - [ ] TLS 1.3 0-RTT / early-data enabled

   **e. Key-exchange parameter hygiene**
   - [ ] Uses common DH primes
   - [ ] DH public server param (Ys) reuse
   - [ ] ECDH public server param reuse
   - [ ] Supported Named Groups *enumeration* (report the server's accepted
         set + preference; today we only advertise our groups)

   **f. Intolerance / robustness probes**
   - [ ] Long handshake intolerance
   - [ ] TLS extension intolerance
   - [ ] TLS version intolerance
   - [ ] Incorrect SNI alerts

   **g. Pinning & transport (overlaps HTTP headers item 2)**
   - [ ] HSTS + preload status
   - [ ] HPKP, HPKP report-only, static pinning (legacy/deprecated — detect & report)

2. **HTTP Security Headers Analysis**
   - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
   - Cookie security (Secure, HttpOnly, SameSite)

3. **Grading Engine** - SSL Labs compatible A+ to F grading

### Lower Priority
4. **CNSA 2.0 Compliance Checking** - Timeline-based compliance rules
5. **HTML Report Generation** - Rich visual reports
6. **Additional REST API Endpoints** - Beyond QDZChecker
7. **Performance Optimization** - Connection pooling, caching
8. **Integration Tests** - Test new features against real servers

---

## Architectural Decisions (IMPORTANT)

### Utility Functions Location
**All reusable utility functions MUST be created in the `opsec` module**, specifically in:
```
opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java
```

### Cryptography Library
**Bouncy Castle** is the primary cryptographic library. Use it for:
- Certificate parsing and validation
- TLS/SSL operations
- Post-Quantum Cryptography (ML-KEM, ML-DSA)
- Key exchange analysis
- Signature verification
- OCSP/CRL checking

**Do NOT** introduce alternative crypto libraries (e.g., liboqs) - Bouncy Castle covers all PQC requirements.

### TLS Implementation Strategy
**Bouncy Castle TLS API for all scanning**

| Use Case | Implementation | Reason |
|----------|----------------|--------|
| TLS 1.2/1.3 basic handshake | BC TLS API | PQC support needed |
| Certificate chain retrieval | BC TLS API | Already integrated |
| SSL 2.0/3.0 testing | BC TLS API | Disabled in Java SSLEngine |
| PQC/Hybrid key exchange | BC TLS API | Experimental cipher suites |
| Cipher enumeration | BC TLS API | Full control over cipher list |
| Protocol version testing | BC TLS API | Individual version control |
| Vulnerability testing | BC TLS API + raw bytes | Malformed packet testing |

---

## Current Package Structure

```
io.xlogistx.nosneak/
├── nmap/                          # Network scanning (NMap-like)
│   ├── NMapScanner.java           # Main scan orchestrator
│   ├── NMap.java                  # CLI entry point
│   ├── config/                    # Scan configuration
│   ├── discovery/                 # Host discovery (ARP/TCP/ICMP)
│   ├── scan/tcp/                  # TCP Connect scan engine
│   ├── scan/udp/                  # UDP scan engine
│   ├── service/                   # Service detection
│   │   └── probes/                # Protocol probes (TLS, HTTP, SSH)
│   ├── output/                    # Report formatters (JSON, XML, CSV)
│   └── util/                      # Scan results, port states
│
├── scanners/                      # PQC-specific scanning (ACTIVE)
│   ├── PQCCallback.java           # **MAIN ENTRY POINT** - NIO callback orchestrator
│   ├── ScanCallback.java          # Interface between PQCNIOScanner and PQCCallback
│   ├── PQCNIOScanner.java         # Phase 1 TLS handshake scanner
│   ├── PQCScanResult.java         # Result container
│   ├── PQCScanOptions.java        # Scan configuration
│   ├── TLSProbeCallback.java      # Base class for NIO TLS probes
│   ├── CipherProbeCallback.java   # NIO cipher enumeration probe
│   ├── VersionProbeCallback.java  # NIO protocol version probe
│   ├── NIORevocationChecker.java  # Stapled OCSP (instant) -> short-circuit -> 5s soft-fail active OCSP (no CRL)
│   ├── CipherSuiteEnumerator.java # Cipher info classes (CipherInfo, etc.)
│   ├── ProtocolVersionTester.java # Version name utilities
│   ├── PQCSessionConfig.java      # TLS session state
│   ├── PQCSSLStateMachine.java    # Handshake state machine
│   ├── PQCTlsClient.java          # BC TLS client with PQC
│   ├── PQCTlsClientProtocol.java  # BC TLS protocol handler
│   └── PQCConnectionHelper.java   # State machine interface
│
└── services/
    └── QDZChecker.java            # REST endpoint for PQC scanning
```

---

## Key Files

### PQC Scanner
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCCallback.java` - **MAIN ENTRY POINT**
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/ScanCallback.java` - Interface
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCNIOScanner.java` - Phase 1 handshake
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCScanResult.java`
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCScanOptions.java`
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/TLSProbeCallback.java` - Base probe class
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/CipherProbeCallback.java` - Cipher probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/VersionProbeCallback.java` - Version probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/NIORevocationChecker.java` - Revocation: stapled OCSP → short-circuit NOT_CHECKED → 5s soft-fail active OCSP (no CRL)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCTlsClient.java` - BC TLS client; PQC groups + RFC 6066 OCSP stapling capture
- `no-sneak/src/main/java/io/xlogistx/nosneak/services/QDZChecker.java`

### OPSec Utilities
- `opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java` - Extended with:
  - CRL/OCSP extraction and checking
  - Cipher suite classification
  - Protocol version security

### Tests
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCCallbackTest.java` - Main scanner tests
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCScannerTest.java` - Handshake and helper tests

---

## API Response Format (PQCScanResult.toNVGenericMap)

```json
{
  "host": "google.com",
  "port": 443,
  "scan-id": "uuid",
  "scan-time-in-ms": 150,
  "success": true,
  "secure": true,
  "tls-version": "TLSv1.3",
  "tls-version-pqc-capable": true,
  "key-exchange-type": "PQC_HYBRID",
  "key-exchange-algorithm": "X25519MLKEM768",
  "key-exchange-pqc-ready": true,
  "cipher-suite": "TLS_AES_256_GCM_SHA384",
  "cert-signature-type": "ECDSA",
  "cert-signature-algorithm": "SHA256withECDSA",
  "cert-public-key-type": "ECDSA",
  "cert-public-key-size": 256,
  "cert-pqc-ready": false,
  "cert-not-before": "2026-01-12 08:36:50.000 GMT",
  "cert-not-after": "2026-04-06 08:36:49.000 GMT",
  "cert-time-valid": true,
  "cert-validity-state": "VALID",
  "cert-chain-time-valid": true,
  "cert-chain-valid": true,
  "cert-chain-trust": "TRUSTED",
  "cert-hostname-valid": true,
  "cert-revoked": false,
  "cert-subject": "CN=*.google.com",
  "cert-issuer": "CN=WE2,O=Google Trust Services,C=US",
  "cert-chain": [
    {"index": 0, "subject": "CN=*.google.com", "issuer": "CN=WE2,O=Google Trust Services,C=US",
     "not-before": "...", "not-after": "...", "time-valid": true, "self-signed": false,
     "is-ca": false, "role": "leaf"},
    {"index": 1, "subject": "CN=WE2,O=Google Trust Services,C=US", "issuer": "CN=GTS Root R4,...",
     "time-valid": true, "self-signed": false, "is-ca": true, "role": "intermediate"}
  ],
  "revocation-method": "OCSP_STAPLED",
  "supported-cipher-suites": [
    {"name": "TLS_AES_256_GCM_SHA384", "strength": "STRONG", "forward-secrecy": true},
    {"name": "TLS_CHACHA20_POLY1305_SHA256", "strength": "STRONG", "forward-secrecy": true}
  ],
  "server-cipher-preference": true,
  "supported-protocol-versions": ["TLSv1.3", "TLSv1.2"],
  "sslv3-supported": false,
  "deprecated-protocols-supported": false,
  "overall-status": "READY",
  "recommendations": {
    "upgrade-to-pqc-certificate": "Consider migrating to PQC certificates (ML-DSA) for full quantum resistance"
  }
}
```

---

## Progress Tracking

- [x] **Sprint 1: PQC Scanner Foundation** - COMPLETE
  - [x] PQCNIOScanner with state machine
  - [x] PQCScanResult with all fields
  - [x] BC TLS client with PQC support
  - [x] Certificate chain verification
  - [x] REST endpoint (QDZChecker)
  - [x] DNS resolution integration

- [x] **Sprint 2: Certificate Deep Analysis** - COMPLETE
  - [x] OCSP checking
  - [x] CRL checking
  - [x] RevocationResult with status, method, date, reason

- [x] **Sprint 3: Protocol & Cipher Enumeration** - COMPLETE
  - [x] Protocol version testing (all versions)
  - [x] Full cipher suite enumeration
  - [x] Server cipher preference detection
  - [x] PQCScanOptions configuration

- [x] **Sprint 3.5: Pure NIO Callback Architecture** - COMPLETE (2026-02-04)
  - [x] PQCCallback orchestrator (replaces CompletableFuture)
  - [x] ScanCallback interface
  - [x] TLSProbeCallback base class
  - [x] CipherProbeCallback (NIO cipher enumeration)
  - [x] VersionProbeCallback (NIO version testing)
  - [x] NIORevocationChecker (callback-based, no CompletableFuture)
  - [x] PQCNIOScanner simplified (Phase 1 only)
  - [x] QDZChecker updated to use PQCCallback
  - [x] Zero blocking/waiting - pure event-driven

- [ ] **Sprint 4: Vulnerability Scanning** — see the full **SSL Labs parity
      checklist** under "Pending Issues / Next Steps → item 1" (groups a–g:
      padding-oracle family, named-CVE probes, renegotiation, protocol
      posture/downgrade, DH/ECDH param hygiene, intolerance probes, pinning)
  - [ ] Weak cipher detection
  - [ ] Certificate vulnerabilities

- [ ] **Sprint 5: Grading & Compliance**
  - [ ] SSL Labs compatible grading
  - [ ] CNSA 2.0 compliance
  - [ ] PCI DSS / NIST rules

- [ ] **Sprint 6: Reporting & API**
  - [ ] HTML reports
  - [ ] Extended REST API
  - [ ] Performance optimization

---

## Usage Examples

### Basic PQC Scan (Recommended - using PQCCallback)
```java
HTTPNIOSocket httpNIOSocket = new HTTPNIOSocket(nioSocket);
IPAddress address = new IPAddress("google.com", 443);

PQCCallback scanner = new PQCCallback(address, result -> {
    System.out.println("Status: " + result.getOverallStatus());
    System.out.println("TLS: " + result.getTlsVersion());
    System.out.println("Key Exchange: " + result.getKeyExchangeAlgorithm());
}, null, httpNIOSocket);

scanner.dnsResolver(DNSRegistrar.SINGLETON);
scanner.timeoutInSec(10);
scanner.start();  // Non-blocking, callback fires when complete
```

### Comprehensive Scan with Options
```java
PQCScanOptions options = PQCScanOptions.builder()
    .checkRevocation(true)
    .revocationTimeoutMs(5000)
    .enumerateCiphers(true)
    .includeWeakCiphers(true)
    .testProtocolVersions(true)
    .testTLS10(true)
    .testTLS11(true)
    .testSSLv3(false)
    .build();

PQCCallback scanner = new PQCCallback(address, result -> {
    // All Phase 2 results included
    System.out.println("Ciphers: " + result.getSupportedCipherSuites());
    System.out.println("Versions: " + result.getSupportedProtocolVersions());
    System.out.println("Revoked: " + result.isCertRevoked());
}, options, httpNIOSocket);

scanner.dnsResolver(DNSRegistrar.SINGLETON);
scanner.timeoutInSec(30);
scanner.start();
```

### Callback-based Revocation Checking
```java
// timeoutMs = soft-fail bound for the ACTIVE OCSP call only (default 5000)
NIORevocationChecker checker = new NIORevocationChecker(httpNIOSocket, 5000);

// stapledOCSP: DER bytes from PQCTlsClient.getStapledOCSPResponse() (may be null).
// If present  -> parsed in-memory, instant, method "OCSP_STAPLED".
// Else no OCSP URL / no issuer -> instant UNKNOWN/"NOT_CHECKED" (no CRL fetch).
// Else                          -> one 5s soft-fail active OCSP POST.
checker.checkRevocation(cert, issuerCert, stapledOCSP, result -> {
    System.out.println("Status: " + result.getStatus());   // GOOD/REVOKED/UNKNOWN
    System.out.println("Method: " + result.getMethod());    // OCSP_STAPLED / OCSP / NOT_CHECKED / TIMEOUT
});
// 3-arg checkRevocation(cert, issuer, cb) still works (stapledOCSP = null).
```

### Blocking Revocation Checking (OPSecUtil)
```java
OPSecUtil opsec = OPSecUtil.singleton();
RevocationResult result = opsec.checkRevocation(cert, issuerCert, 5000);
System.out.println("Status: " + result.getStatus());
System.out.println("Method: " + result.getMethod());
```

---

## Notes

- Full requirements document is in `README.md`
- This scanner differentiates NoSneak by offering PQC readiness assessment
- Focus on CNSA 2.0 timeline compliance as key selling point
- **All new utility functions go in `opsec/OPSecUtil.java`** - no exceptions
- **Bouncy Castle only** for all cryptographic operations
