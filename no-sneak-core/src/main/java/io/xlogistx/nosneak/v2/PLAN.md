# no-sneak-core v2 — Plan of Action

> **Status: ALL PHASES (0–10) DONE — v2 meets-or-exceeds v1, ready for the maintainer's merge.**
> Non-blocking on `NIOSocket` + trigger `StateMachine` (no `MonoStateMachine`), executor
> `TaskUtil.defaultTaskProcessor()`, scheduler `TaskUtil.defaultTaskScheduler()`. v1 untouched
> throughout. Remaining items are polish/deferrals noted per phase (active OCSP, nmap
> formatters/discovery, REST/tools runtime testing). Detail below.
>
> **Fix (HTTPS on nonstandard ports):** a plaintext HTTPS port (e.g. xlogistx.io:6443) was
> mis-identified as `http` because the plaintext `http` probe matched the server's "requires TLS"
> HTTP-400 error. Fixed two ways: (1) `https-version` priority 45→68 so the TLS probe is tried
> before the plaintext `http` probe in the fallback tier; (2) `http.json` now has an `istls` gate
> that fails on "requires TLS / plain HTTP sent to HTTPS / speaking plain HTTP to SSL" replies.
> Verified: 6443 → `https` in match-first and match-all; example.com:80 still `http`.
>
> **Fix (JSSE `tls-connect` TLS facts):** the `https-version` probe completed a full JSSE TLS
> handshake but reported `tls-state=NONE` (only the Bouncy-Castle path recorded TLS facts), so an
> HTTPS result read as `service=https tls=NONE`. Added `SSLSessionConfig.getSSLSession()` to
> zoxweb-core and `ProbeContext.recordSecureTlsFacts()`, invoked on secure-handshake completion:
> it sets `tls-state=DIRECT_TLS` and records the JSSE-negotiated `tls-version` / `cipher-suite`.
> PQC stays `UNKNOWN` on this path (JSSE does not surface the key-exchange group; the `https-scan`
> BC probe classifies PQC). Verified: xlogistx.io:6443 → `tls=DIRECT_TLS tls-version=TLSv1.3
> cipher=TLS_AES_256_GCM_SHA384`; example.com:80 still `tls=NONE`.
>
> **Investigation + fix (open-but-silent port → `checker-timeout`):** a full-run probe of
> `imap.gmail.com:143` returned `complete=false note=checker-timeout` after ~165s. A thread dump
> (`jstack`) plus a transition trace (ProbeEngine/ProbeContext loggers enabled) proved there is
> **no deadlock and no timeout bug** — a single probe fires its `arm()` timeout at exactly
> `timeoutSec` and delivers cleanly (`connect --connected--> banner`, then `banner --timeout-->
> fail` at +Ns). Root cause: on that host port 143 accepts the TCP connection but sends **no
> banner** in this environment (Avast MITM / transparent proxy), so tier-1 `imap-starttls-pqc`
> fails on a banner timeout and `ProbeChecker` then sweeps ~13 tier-2 fallback probes
> **sequentially**, each also waiting the full `timeoutSec` on the silent port; the cumulative
> time exceeded `maxWaitMs`, tripping the blocking backstop (`checker-timeout`). The genuine
> defect: match-first sized `maxWaitMs = (timeout*6+15)s` and **ignored candidate count**, while
> match-all already added `candidates*timeout`. Fixed `ProbeChecker.main` to size the match-first
> wait the same way, so an open-but-silent port now returns a clean, accurate
> `no-probe-identified; N probe(s) tried: ...` verdict instead of the misleading `checker-timeout`.
> Verified: `imap.gmail.com:143` → `no-probe-identified` (13 probes listed); example.com:443 →
> `https`, :80 → `http`, xlogistx.io:6443 → `https`, 127.0.0.1:27017 → `mongodb 7.0.21` all
> unchanged and fast.
>
> **Parallel candidate sweep + fast-path short-circuit (implemented):** `ProbeChecker` no longer
> runs candidates sequentially (`runFrom`/`runAll` removed). `check()` now launches every candidate
> concurrently (`FirstSweep`) and delivers the **highest-priority completed** result the instant no
> higher-priority candidate can still win — index `k` wins once indices `0..k-1` have all resolved
> incomplete and `k` completed; losers are torn down via a new `ProbeContext.cancel()` (idempotent
> teardown that never clobbers the winner). `checkAll()` (`AllSweep`) runs all concurrently and
> returns every completion. **Selection is identical to the old sequential priority sweep** — only
> latency (bounded by the winner, not the sum) and concurrency (one connection per candidate)
> change. Result-delivery is now ~winner time (example.com:80 http = 81ms) and an open-but-silent
> port resolves in ~`timeout` instead of `candidates*timeout` (imap.gmail.com:143: 165s → ~8s).
> A superseded `tls-connect` can keep its NIOSocket session-timeout pending up to `timeout`, which
> would make the CLI's busy-wait shutdown linger; `main` now `System.exit(0)`s once the result is
> printed (one-shot CLI — OS reclaims sockets). Verified: example.com:80/443, xlogistx.io:6443,
> 127.0.0.1:27017 all identify in ~1s; `--all` on :443 returns both https probes in ~8s (was
> ~`N*timeout`); imap:143 → clean `no-probe-identified` in ~8s.
>
> **Sweep runs on the native trigger-StateMachine parallel dispatch (not hand-rolled threads):**
> the candidate fan-out uses the same mechanism as the rest of v2 — a single `StateMachine`
> configured with an `Executor` supports `publishSync` (inline/sequential) and `publish`
> (executor-threaded/parallel) per call. `AllSweep` = `Fanout.run(children, onAllDone)` (parallel
> `publish` + `ParallelJoin` barrier); `FirstSweep` constructs all contexts then launches their
> starts via `Fanout.dispatch(...)` (barrier-free parallel `publish`) with the match-first election
> kept as a small `synchronized` block — the one genuine correctness necessity (concurrent
> completions race to elect the highest-priority winner; the mandated multi-threaded
> `defaultTaskProcessor` means `publishSync` can't serialize them). Deep-analysis-verified against
> zoxweb `StateMachine`/`TriggerConsumerHolder`/`ParallelJoin` sources; results are deterministic
> across repeats (443→https/PQC, 80→http, 27017→mongodb every time).
>
> **Superseded-probe connection reclamation (embedded path fixed):** empirically (logs + polling
> `defaultTaskScheduler().pendingTasks()`) a match-first winner left ~2 scheduler tasks pending for
> the full `timeout` after delivery — the `NIOChannelMonitor` connect-timeout appointments of
> loser probes cancelled *before* their TCP connect completed (`finishConnecting` only cancels that
> appointment on a successful connect; `ctx.cancel()` closed the channel but not the appointment).
> Added **`NIOSocket.abortClientSocket(SelectionKey)`**; `ProbeContext` now captures the
> `SelectionKey` from `addClientSocket`/`addDatagramSocket` and aborts it in `closeCurrent()`.
> Verified against the select loop (NIOSocket lines 640–646): closing the socket makes the selector
> cancel the key and the run loop clean it up — but that path does NOT release the pending
> appointment. So `abortClientSocket` cancels the still-attached `ScheduledAttachment` appointment
> (the one thing that lingers) and closes the socket, letting NIOSocket handle the key (no explicit
> `cancelSelectionKey` needed).
>
> **Deep-scan additions (cert validity + SSLv3):** with the Avast MITM disabled, `cert-chain-trust`
> on example.com:443 correctly reads `TRUSTED` (real `Cloudflare TLS Issuing ECC CA 3` chain, not
> the re-signed `UNTRUSTED_ROOT`). Added on top: (1) **cert validity** — `recordCertFacts` now emits
> `cert-not-before`, `cert-not-after`, and `cert-validity` (`VALID` / `EXPIRED` / `NOT_YET_VALID`
> via `X509Certificate.checkValidity()`); example.com → `VALID`, not-after 2026-08-29. This is
> captured on every cert-bearing path (`pqc-check` and `tls-facts`), so bundled https detection
> shows it too. (2) **SSLv3 enumeration** — `enumerateVersions` now also probes `ProtocolVersion.
> SSLv3` (weakest-last) so an insecure server is flagged; verified BC actually sends an SSLv3
> ClientHello and example.com correctly rejects it (`handshake_failure`), while TLS1.0/1.1 are
> genuinely accepted (Cloudflare default min TLS = 1.0) → grade `C`. NOTE: `cert-chain-trust` and
> the protocol/cipher enumeration come from the `https-scan` probe, which is present but NOT in the
> bundle — run it via `--all` (bundled) or as an explicit probe file; bundled https detection
> (`https-pqc`) still yields cert facts + validity + PQC but not chain-trust/version-enumeration.
>
> **`https-scan` is now BUNDLED and primary on TLS ports (the project's core objective).** Raised
> its priority 66→72 (above `https-pqc` 70 and `https-version` 68) and added it to
> `ProbeDefinitionLoader.BUNDLED`, so a default scan of 443/8443 delivers the full TLS assessment —
> `cert-chain-trust`, `cert-validity` (+ not-before/after), `pqc-status`, and the supported
> protocol-version / cipher enumeration — as the winning result (example.com:443 → `https-scan`,
> TRUSTED, VALID, PQC, grade C, ~4s). `https-pqc` (70) remains as the graceful TLS-handshake-failure
> fallback; `https-version` (68, non-portScoped) still handles shallow HTTPS on NONSTANDARD ports.
>
> **Deep TLS on ANY port via `tls-scan` (non-portScoped, service=`tls`).** Added a bundled
> `tls-scan` probe: same deep flow as `https-scan` (handshake→pqc→cert-chain→revocation→versions→
> ciphers) but `service: "tls"`, `ports: []` (never tier-1, always the fallback tier), priority 71,
> `portScoped: false`. So on a nonstandard TLS port it is the top fallback and delivers the full
> assessment labelled `tls` rather than mislabelling it `https`; on a non-TLS port its handshake
> just fails and the real probe wins (the losing connection is aborted immediately). Verified:
> xlogistx.io:6443 → `service=tls DIRECT_TLS pqc=CLASSICAL`, TRUSTED, VALID, grade A (PQC now
> classified, was UNKNOWN). Declared TLS ports keep their specific label via tier-1 (443→`https`
> via `https-scan`, 993→`imaps`); non-TLS ports (80/22/27017) unaffected and still ~1s.
>
> **Staged nmap scanner (host discovery → port scan → probe scan), non-blocking + embeddable.**
> New in `v2/nmap/`: `NMapConfig` (targets host/CIDR/range, ports, discovery/probe toggles, rate
> limits, probe subset), `RateLimiter` (non-blocking throttle: max-in-flight + per-second token
> bucket on `defaultTaskScheduler`), `NMapScanner` (staged pipeline: expand targets → discover
> (TCP-ping via `PortScanCallback`, up if OPEN|CLOSED, + optional executor-run ICMP) → per-host
> port scan → optional probe scan on open ports, all `ParallelJoin`-barriered and rate-limited),
> `ScanReport`/`HostReport`/`PortReport`, and a flag-driven `NMap` CLI (`-p -sV --probes -Pn -sn
> --no-icmp --max-inflight --max-rate -t`). Embed via `NMapScanner.scan(nio, cfg, cb)`. Verified:
> single-host `-sV` (mongodb/http/https-with-TLS-line), discovery-only over a range, CIDR
> expansion (`127.0.0.1/30` → usable hosts), and rate-limited multi-host scans. TLS ports render
> inline with `[DIRECT_TLS pqc=PQC cert=VALID/TRUSTED grade=C]`.
>
> **nmap parity port (in progress).** Inventoried the old `io.xlogistx.nosneak.nmap` app (~45
> files; its live path was only TCP-connect + UDP on NIO — `service/`, `os/`, and `raw/` SYN/FIN
> engines were dead/stub code). Porting the real features into v2. **Done this pass:** five output
> formats (`v2/nmap/output/` Normal/JSON/XML/CSV/Grepable + `OutputFormat`/`OutputFormatter`, CLI
> `-oN -oX -oG -oJ -oC -oA`, console=Normal — all carry the deep TLS/PQC/validity/grade, beyond the
> old banner-only), enriched `ScanReport`/`PortReport`/`HostReport` model, full `PortState`,
> `WellKnownPorts` (service table + TOP_100_TCP/TOP_20_UDP), and scan reasons/timing. Verified
> multi-format render on example.com. **Decisions:** raw scans → reject (real ones via a JDK-25
> Panama-FFM native layer later); OS detect → open-port heuristic; ARP/remote-MAC → deferred to the
> same FFM layer (no JDK API exposes a remote MAC — layer-2/ARP; won't ship the `arp`-command
> shell-out). **Remaining (see PROBE-CONFIG.md deferrals):** UDP scan `-sU`, timing templates
> `-T0..T5`, `T:`/`U:`/`--top-ports` port specs, `-sS` raw-scan rejection wiring, `-O` heuristic,
> and the FFM native layer (SYN scans + OS fingerprint + ARP/MAC).
>
> Verified: pending scheduler tasks drop to 0 right after delivery (example.com:80: was pending 8s,
> now `pendingSchedTasks=0` at +8ms; `isBusy` false at ~578ms) — so the REST `Checker` no longer
> holds cancelled connections for `timeout`. The one-shot CLI still `System.exit(0)`s after
> printing, since the only remaining threads are the shared non-daemon pools (DE/TSP), not any
> leaked connection (confirmed by thread dump). CLI exits: 80/443/6443/27017 all 0–1s.
> **Cross-module note:** this adds `NIOSocket.abortClientSocket` to zoxweb-core (alongside
> `SSLSessionConfig.getSSLSession()`); the module was rebuilt and installed to `.m2`.
>
> **Bundle:** all 16 probes copied to `/v2/probes/` and bundled — ssh, ftp, http, pop3, redis,
> mysql, mongodb (with `buildInfo` version capture), https-pqc, imaps-pqc, https-version,
> smtp-starttls-pqc, imap-starttls-pqc, postgres-db, postgres-version, postgres-tls, dns (udp).
>
> **Status (history):** **Phases 0–3 complete and green.** 0/1 = engine + raw-TCP
> (ssh/ftp/http). 2 = TLS/PQC handshake on the trigger `StateMachine` (no MonoStateMachine;
> X25519MLKEM768 on google/cloudflare/github:443). 3 = JSSE secure app-data channel
> (`tls-connect`, RSA-capable) — HTTPS `Server:` header over TLS (github/cloudflare), match-all
> returns PQC posture + version together, graceful failure on plaintext ports. Phases 4–10
> pending (see below for 4). v1 remains frozen and working.
>
> **Phase 4 complete and green:** `starttls` mid-session upgrade + Postgres SSLRequest —
> smtp.gmail.com:587 → smtp/STARTTLS_UPGRADED/PQC + banner; lax-2.xlogistx.io:5432 →
> postgresql/DIRECT_TLS/CLASSICAL.
>
> **Phase 5 complete and green:** parallel fan-out + join primitive (`Fanout` + `ParallelJoin`)
> on native `StateMachine` parallel dispatch (`TaskUtil.defaultTaskProcessor()`). Proven: 6
> children ran on 6 distinct pool threads concurrently (CyclicBarrier gate), join fired
> exactly once.
>
> **Phase 6 PARTIAL (6a done, 6b pending):** 6a = `cert-chain-validate` (opsec PKIX) +
> `enumerate-versions` (parallel version probes via `Fanout`, in `v2/analysis`) as FSM actions
> — verified: https-scan.json on cloudflare/google:443 records pqc, cert-chain-trust, and the
> supported-version set; TLS-1.3 correctly rejected by a TLS-1.2 server (discrimination works).
> Fixed a latent v1 bug (version probe now advertises `supported_groups` so ECDHE negotiates on
> strict servers).
>
> **Phase 6b done:** `enumerate-ciphers` (parallel per-cipher probes via `Fanout`) +
> `revocation-check` (handshake-stapled OCSP, in-memory). Verified: https-scan on cloudflare:443
> yields the full SSL-Labs-style fact set — pqc, cert-chain-trust, revocation, supported
> versions, and supported ciphers; the enumeration **discriminates** (ECDHE/GCM/ChaCha accepted,
> the RSA-key-exchange candidates correctly excluded). **Deferred: active/network OCSP+CRL**
> (needs the HTTP NIO stack → Phase 9).
>
> **Phase 7 complete and green:** UDP seam — `ProbeUDPCallback` on `UDPSessionCallback`
> (ephemeral datagram bind via `addDatagramSocket`, send/expect over UDP), `--udp` CLI, `dns.json`.
> Verified: DNS-over-UDP identified on 8.8.8.8 / 1.1.1.1 / 9.9.9.9:53.
>
> **Phase 8 core done:** NIO-native TCP-connect port scanner (`v2/nmap`: `PortScanCallback`,
> `PortScanner`, `NMap`) — concurrent connect scan via `Fanout`, then the probe engine
> identifies service+version on each OPEN port (the nmap→probe seam). Verified: scanme.nmap.org
> → 22 ssh OpenSSH_6.6.1p1, 80 http Apache/2.4.7; github.com → 22/80/443. **Deferred (polish):**
> output formatters (JSON/XML/CSV/grepable), host discovery, top-ports/`--open`/UDP-scan flags,
> full v1 NMap CLI parity.
>
> **Phase 9 done:** services + tools. `v2/service/Checker` (REST `/check-qdz/{domain}/{detailed}`
> on the v2 engine, bounded wait vs v1's unbounded `future.join()`); `v2/tools/DMTool` +
> `NoSneakUtil` (copied, **fixed v1 issue C2** — the domain manager is always built from the
> cached-or-new datastore). Compile-clean; DMTool usage verified. **Deferred: active/network OCSP**
> (needs an HTTPNIOSocket plumbed through ProbeContext; only meaningful in the HTTP-server context;
> stapled OCSP already covers the common case).
>
> **Phase 10 done:** grading layer (`v2/grade/Grade` — SSL-Labs-style letter + PQC readiness from
> recorded facts, shown in the CLI for TLS results) and the **parity gate**. Parity verified: v1
> and v2 produce identical service/version/tls/pqc across ssh, ftp, http, https/PQC, smtp
> STARTTLS, postgresql; v2 additionally emits cert-chain-trust, revocation, version+cipher
> enumeration, and grade (which v1's *probe* ProbeChecker never produced — unified from the
> separate v1 scanner). **v2 meets-or-exceeds v1.** Migration ready for the maintainer's merge
> (remaining deferrals are polish: active OCSP, nmap output formatters/discovery, REST/tools
> runtime testing).

## 1. What v2 is

`io.xlogistx.nosneak.v2` is **version 2 of `no-sneak-core`** — a from-scratch rebuild
of the whole module on a single **non-blocking, trigger-`StateMachine`** core. When it
is complete, **the maintainer (not the agent)** merges v2 and deletes the old code, so
v2 becomes the module. Until then, v1 (`io.xlogistx.nosneak.{nmap,probe,scanners,
services,tools}`) is **frozen and untouched**.

### Non-negotiable rules
1. **v1 is read-only.** v2 never modifies, deletes, or depends on v1 classes.
2. **Clean final names — no `v2` in any class name.** Separation comes only from the
   `io.xlogistx.nosneak.v2` package path. Classes keep their final names
   (`ProbeChecker`, `ProbeEngine`, `ProbeResult`, `PQCSessionConfig`, …) so that after
   the maintainer's merge/rename they are already correct. (This `PLAN.md` and other
   docs may say "v2"; class names may not.)
3. **Copy + rearchitect for anything inside `no-sneak-core` — never a blind copy.**
   Because v1 is deleted at merge, v2 must be self-contained: every no-sneak-core class v2
   needs is **copied into v2** and reworked to be **fully non-blocking**. Any blocking
   `java.net.Socket`, `Thread.sleep`, `future.join()`/`get()`, or blocking selector loop
   from v1 is replaced with `NIOSocket` + callbacks + scheduled tasks. No v2→v1
   references, ever.
4. **Reuse freely (call, don't copy) the surviving modules:** `zoxweb`
   (`org.zoxweb.*` — `NIOSocket`, `org.zoxweb.server.fsm.StateMachine`,
   `TCPSessionCallback`, `UDPSessionCallback`, `SSLContextInfo`, `HTTPNIOSocket`, …) and
   **opsec** (`io.xlogistx.opsec.OPSecUtil`). These are separate Maven modules that
   survive the merge.
5. **No `MonoStateMachine`** anywhere in v2. The TLS/PQC handshake uses the trigger-based
   `StateMachine` design (the proven `org.zoxweb.server.net.ssl.SSLStateMachine` /
   `SSLHandshakingState` pattern, adapted to Bouncy Castle).
6. **Always green.** Every phase compiles and runs; a working vertical slice comes first,
   then widens. No phase leaves the tree broken.

## 2. Core architecture

One engine drives everything: **`StateMachine<ProbeContext>`**. A JSON `ProbeDefinition`
builds the machine — each declared state becomes a `org.zoxweb.server.fsm.State` carrying
a `ProbeActionConsumer` (`TriggerConsumer`) that runs a fixed, trusted **action**. An
action reports an **outcome**; the engine resolves the state's `on{}` map and publishes
the next state's trigger. JSON selects behavior; JSON never executes code.

- **Sequential** = `publishSync` on an inline executor (`r -> r.run()`) — linear probes
  (connect → handshake → pqc → cert → starttls → version).
- **Parallel** = a fan-out state that `publish`es one trigger to **N registered consumers
  on a pool executor** (native `StateMachine` fan-out: `tcMap.get(id)` is a *set*, each
  dispatched via the executor). Each consumer spawns an **independent child sub-flow**
  (own connection + wait guard); a **join barrier** (`AtomicInteger` count, the proven
  `PQCScanCallback` pattern) fires the parent's next trigger at zero. This is how the
  scanner's cipher/version/revocation fan-out becomes data.
- **Transport:** TCP via `TCPSessionCallback` (raw + JSSE-secure subclasses) and UDP via
  `UDPSessionCallback` (`NIOSocket.addDatagramSocket`) for DNS/QUIC/DTLS-shaped probes.
- **TLS/PQC handshake:** a trigger-`StateMachine` driver over Bouncy Castle
  (`PQCSessionConfig` `offerInput`/`readOutput`/`isHandshaking`), replacing the v1
  MonoState `PQCSSLStateMachine`.

### Concurrency conventions (fixed, project-wide in v2)
Everything is non-blocking; no thread is ever parked on I/O. Standard wiring:
- **Executor** — `org.zoxweb.server.task.TaskUtil.defaultTaskProcessor()`. Used for the
  `StateMachine` **parallel** dispatch (fan-out states) and as the `NIOSocket` task
  processor (`new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler())`).
- **Scheduler** — `org.zoxweb.server.task.TaskUtil.defaultTaskScheduler()`. Used for all
  **timeouts / watchdogs / wait guards** (connect, handshake, expect deadlines, overall
  probe deadline) via `schedule(...)`.
- **Sequential** transitions use the inline executor `r -> r.run()` (no dispatch); only
  fan-out states use `TaskUtil.defaultTaskProcessor()`.
- No `Thread.sleep`, no `future.join()/get()` on a live path, no blocking sockets — ever.

## 3. Target package layout (v2)

```
io.xlogistx.nosneak.v2
├── model/        ProbeDefinition, ProbeState, PatternRule, ProbeDefinitionLoader
│                 (copied from probe/model; + portScoped, + parallel/fan-out fields)
├── runtime/      ProbeContext   (StateMachine config C: NIO conns, result builder, wait guards, child registry)
│                 ProbeEngine    (builds StateMachine<ProbeContext> from a definition; seq + parallel)
│                 ProbeTCPCallback (raw), ProbeSecureCallback (JSSE), ProbeUDPCallback (UDP)
├── action/       Action, ActionRegistry, ProbeActionConsumer,
│                 Connect, Send, Expect(+capture), StartTLS, TLSHandshake(BC/PQC), TLSConnect(JSSE),
│                 PQCCheck, CertInfo, TLSFacts, Record, Terminal, FanOut(+Join),
│                 Revocation, CertChain, CipherEnum, VersionEnum, VulnCheck (Sprint-4, later)
├── tls/          PQCConnectionHelper, PQCHandshakeStateMachine (trigger SM), PQCHandshakeStates,
│                 PQCHandshakeUtil (extracted BC handler helpers),
│                 PQCSessionConfig, PQCTlsClient, PQCTlsClientProtocol   (copied from scanners)
├── analysis/     RevocationChecker, CipherEnumerator, VersionEnumerator, ScanResult, ScanOptions
│                 (copied+rearchitected from scanners; PQCScanResult → ScanResult facts)
├── discovery/    HostDiscovery (copied from probe/discovery + nmap/discovery, unified on NIO)
├── nmap/         NMap, NMapScanner, config/, output/, scan/{tcp,udp}, util/
│                 (copied+rearchitected on NIOSocket; feeds ProbeEngine for service/version)
├── service/      Checker (REST endpoint; copied+adapted from services/QDZChecker)
├── tools/        DMTool, NoSneakUtil   (copied; known bugs fixed)
├── result/       ProbeResult, ProbeResult grading hook
└── ProbeChecker, ProbeDispatcher   (library API + CLI)

src/main/resources/probes/   (all 17 JSON copied verbatim; + parallel/full-scan definitions)
```

## 4. Migration of each v1 subsystem (all **by copy**)

| v1 subsystem | files | v2 destination & treatment |
|---|---|---|
| **probe** | 27 | **The core.** Copy `model`/`runtime`/`action`/`discovery` → v2 `model`/`runtime`/`action`. Add parallel fan-out; convert nothing to MonoState. This is the engine everything else plugs into. |
| **scanners** | 16 | Copy the reusable TLS engine: `PQCSessionConfig`, `PQCTlsClient`, `PQCTlsClientProtocol`, `PQCConnectionHelper` → v2 `tls`. **Convert** `PQCSSLStateMachine` (MonoState) → v2 `tls/PQCHandshakeStateMachine` (trigger SM). Copy+rearchitect `NIORevocationChecker`→`analysis/RevocationChecker`, `CipherProbeCallback`→`CipherEnum` action, `VersionProbeCallback`→`VersionEnum` action, `PQCScanResult`→`analysis/ScanResult`, `PQCScanOptions`→`analysis/ScanOptions`. **Retire** the bespoke `PQCScanCallback`/`PQCNIOScanner`/`ScanCallback`/`TLSProbeCallback` orchestration — replaced by FSM fan-out. **Drop** dead blocking `CipherSuiteEnumerator`/`ProtocolVersionTester` (keep only their static name/strength helpers). |
| **nmap** | 49 | Copy `config`/`discovery`/`output`/`scan/{tcp,udp}`/`util` → v2 `nmap`; rearchitect scan engines on `NIOSocket` (fix v1 blocking/fake-engine debt). **Wire the seam:** nmap port discovery hands open `ip:port`s to `ProbeEngine` for service+version identification. **Drop** the dead `nmap/service/*` + `nmap/os/*` (superseded by the probe engine) and the fake raw/SYN/stealth engines. |
| **services** | 1 | Copy `QDZChecker` → v2 `service/Checker`; adapt to call `ProbeEngine`/`ProbeChecker`; keep the REST endpoint, remove `future.join()` blocking. |
| **tools** | 2 | Copy `DMTool`, `NoSneakUtil` → v2 `tools`; fix the known bugs (stale mongo URL, latent NPE-return). |
| **resources/probes** | 17 JSON | Copy verbatim to v2 resources; add parallel/full-scan definitions. |

**Reused from surviving modules (never copied):** `org.zoxweb.*` and `io.xlogistx.opsec.OPSecUtil`.

## 5. Phased plan of action (each phase is green + verified)

| Ph | Deliverable | Copied/created | Verify |
|----|-------------|----------------|--------|
| **0** ✅ | Engine skeleton: `model` (copied), `ProbeEngine`, `ProbeContext`, `ProbeChecker`; trivial `connect → record → done` | probe/model, new runtime | BUILD SUCCESS; loads JSON; runs vs a host |
| **1** ✅ | Raw TCP: `Connect/Send/Expect(+capture)/Reconnect`, `ProbeTCPCallback`; ssh/ftp/http probes | probe/action+runtime | **DONE** — live: ssh `OpenSSH_6.6.1p1…`, ftp banner, http `Server: cloudflare`; no-match + match-all paths verified |
| **2** ✅ | **Handshake → trigger StateMachine**: `tls/*` (copied glue + new `PQCHandshakeStateMachine`), `TLSHandshake/PQCCheck/TLSFacts` | scanners TLS glue | **DONE** — google/cloudflare/github:443 → X25519MLKEM768 / TLSv1.3 / PQC, cert facts, v1-parity |
| **3** ✅ | JSSE secure app-data: `ProbeSecureCallback` + `TLSConnect` | new | **DONE** — HTTPS `Server:` header over TLS (github/cloudflare); match-all = PQC + version; clean failure on plaintext ports |
| **4** ✅ | `StartTLS` mid-session upgrade + Postgres SSLRequest | new | **DONE** — gmail:587 smtp/STARTTLS_UPGRADED/PQC + banner; lax-2:5432 postgresql/DIRECT_TLS |
| **5** ✅ | **Parallel** fan-out + join (`Fanout`+`ParallelJoin`) on native StateMachine pool-executor dispatch | new | **DONE** — 6 children on 6 distinct threads concurrently (barrier-gated), join exactly-once |
| **6** ✅ | Scanner analysis as actions: `CertChain`(opsec), `Revocation`(stapled OCSP), `VersionEnum` + `CipherEnum` (parallel via Fanout, `v2/analysis`) | scanners copied | **DONE** — https-scan on cloudflare:443 → full fact set (pqc, cert-chain-trust, revocation, versions, ciphers); enumeration discriminates. Active OCSP+CRL deferred to Phase 9 (HTTP stack) |
| **7** ✅ | UDP: `ProbeUDPCallback` + udp connect/send/expect, `--udp` CLI, `dns.json` | new (uses zoxweb UDP) | **DONE** — DNS-over-UDP on 8.8.8.8 / 1.1.1.1 / 9.9.9.9:53; QUIC/DTLS-ready seam |
| **8** ◑ | **nmap** core: NIO TCP-connect scanner (`PortScanCallback`/`PortScanner`/`NMap`) + port-scan → ProbeEngine seam. Deferred: output formatters, discovery, top-ports/UDP-scan flags | new (dead v1 nmap dropped) | **DONE** — scanme.nmap.org → 22 ssh OpenSSH_6.6.1p1, 80 http Apache/2.4.7; github 22/80/443 |
| **9** ◑ | **services + tools**: `service/Checker` (REST on v2 engine, bounded wait), `tools/*` (C2 NPE fixed) | services+tools copied | **DONE** — compile-clean, DMTool usage verified. Active OCSP deferred (needs HTTP-server context) |
| **10** ✅ | Grading layer (`v2/grade/Grade`) + full-scan definition + **parity gate** | new | **DONE** — v1≡v2 service/version/tls/pqc across 6 services; v2 adds cert-chain/revocation/enum/grade. **v2 ≥ v1** |

Ship order rationale: **0→1** = a working v2; **2** kills the MonoState debt; **5** unlocks all parallelism; **6** folds the scanner into definitions; **8** folds nmap in and wires the long-planned service-detection seam; **10** is the parity gate before the maintainer's merge.

## 6. Verification & parity strategy

- Each phase: `mvn -pl no-sneak-core -am compile test-compile` green, plus **live** runs
  against real endpoints (google/cloudflare/github, gmail SMTP/IMAP, the maintainer's
  Postgres, public FTP/SSH).
- No-network unit tests mirror v1's `ProbeDefinitionLoaderTest` (graph validity, capture
  wiring, wire-message byte checks). (Surefire execution is env-skipped today — same as
  v1 — so live verification is the primary gate.)
- **Parity harness (Phase 10):** run v1 and v2 against the same target set and diff the
  fact maps; v2 must meet-or-exceed v1 on service id, version, TLS/PQC facts, cert trust,
  revocation, cipher/version enumeration, and nmap port results.

## 7. Open items / notes

- Phase 6 reuses `io.xlogistx.opsec.OPSecUtil` (chain validation, cipher/version
  classification) by **calling** it — opsec survives the merge.
- The v1 nmap debt (fake raw/SYN engines, dead service/os packages, blocking sleeps) is
  **not** carried over; v2 nmap is NIO-native and defers to the probe engine for service
  detection.
- `MonoStateMachine` is eliminated project-wide within v2 (the v1 `TODO(no-monostatemachine)`
  is resolved by construction, not migration).
- Grading (SSL-Labs A–F, PQC readiness, CNSA 2.0) lands as a **post-`record` layer** over
  the unified `ProbeResult`, per the v1 roadmap — Phase 10.

## 8. First checkpoint

On go, I start **Phase 0 + 1** (engine skeleton + raw-TCP, green end-to-end with
ssh/ftp/http running live) and report back at the first green build before proceeding to
TLS/parallel/nmap.
