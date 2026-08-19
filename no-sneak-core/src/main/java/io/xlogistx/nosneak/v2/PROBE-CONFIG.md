# no-sneak v2 — Probe Configuration Reference

Reference for the `io.xlogistx.nosneak.v2` probe framework: the JSON probe DSL, the action
library, candidate selection, the bundled probes, and the result fields. (Migration status and
design rationale live in `PLAN.md`.)

> **Current as of 2026-07-29.** Since the last revision: cipher-suite names now come from Bouncy
> Castle's own constants rather than a hand-written switch; `Grade`'s weak-cipher rule was
> corrected and a letter is no longer awarded without enumeration evidence; the executor and
> scheduler are injected throughout; nmap host discovery moved onto **`no-sneak-net`** (ICMP echo,
> ARP/NDP MACs, and `HostScanner.sweep` for on-link ranges — a `/24` went 55 s → 1.6 s); the REST
> `/check-qdz` endpoint is fully asynchronous and runtime-tested for the first time; and
> `Checker.checkQDZDirect` gives a server-free entry point. Tests 79 → 88.

## Core objective

For a TLS endpoint, report **how valid it is and whether it is PQC-compliant / PQC-ready** —
certificate chain trust, certificate validity, negotiated + enumerated protocol versions and
cipher suites, key-exchange classification (classical vs PQC-hybrid), and a letter grade. The
non-TLS probes (ssh, ftp, http, databases, dns, …) identify the service and, where possible, its
version.

> **Probe scope.** Probes identify — connect, exchange the minimum the protocol needs, handshake,
> match, record. No credential guessing, no crash/overflow/fuzz input, no CVE exploitation, no
> resource exhaustion; a service that can only be identified that way gets no probe. The action
> library is fixed and trusted for exactly this reason: JSON selects and configures behaviour, it
> never executes code. See the repo root `CLAUDE.md` → *Operating scope*.

## How a scan runs

`ProbeChecker` probes a `host:port` by running JSON-defined probes concurrently on a shared
non-blocking `NIOSocket`, driven by zoxweb's trigger `StateMachine`.

- **Candidate ordering (two tiers).** Tier 1 = probes whose declared `ports` include the target
  (highest `priority` first); tier 2 = the remaining transport-compatible probes as a fallback
  (so a service on a nonstandard port is still detected). `portScoped` probes are excluded from
  tier 2. Tier 1 always outranks tier 2.
- **match-first** (`check`, default): every candidate runs concurrently; the **highest-priority
  probe that reaches a clean `done`** wins and is delivered the instant no higher-priority
  candidate can still complete (fast-path short-circuit); the rest are aborted.
- **match-all** (`checkAll`, `--all`): every candidate runs; all completions are returned in
  priority order.
- Concurrency uses the native `StateMachine` dispatch (`Fanout` → `publish` on
  `TaskUtil.defaultTaskProcessor()`); `publishSync` is used for inline sequential steps.

## Probe JSON schema

```jsonc
{
  "name": "https-scan",         // unique probe id
  "service": "https",           // service label stamped on the result
  "transport": "tcp",           // "tcp" | "udp"
  "ports": [443, 8443],         // declared ports → tier-1 match; [] = never tier-1 (fallback only)
  "priority": 72,               // higher wins in match-first
  "portScoped": true,           // true → runs ONLY on declared ports (excluded from fallback tier)
  "start": "connect",           // id of the start state
  "states": { /* id → state */ }
}
```

### State object

| Field | Used by | Meaning |
|---|---|---|
| `action` | all | one of the actions below (required) |
| `on` | non-terminal | outcome → next-state-id map (e.g. `{ "connected": "tls", "error": "fail" }`) |
| `payload` | `send` | templated UTF-8 text (`{probe.hostname}`, `{probe.port}`) |
| `data` | `send` | codec-prefixed payload: `hex:..` \| `base64:..` \| `text:..` (text if no prefix) |
| `patterns` | `expect` | list of `PatternRule` (see below) |
| `command` | `starttls` | protocol upgrade command to send (e.g. `"a2 STARTTLS\r\n"`) |
| `ready` | `starttls` | regex signalling the server is ready to upgrade (default `^220`) |
| `mode` | `tls-handshake` | `"pqc"` (default, Bouncy Castle) — classifies key exchange |
| `note` | `record` | free-form annotation merged into the result |
| `port` | `connect`/`reconnect`/`tls-connect` | alternate port to connect to |

### PatternRule (`expect`)

| Field | Meaning |
|---|---|
| `regex` | Java regex matched against the accumulated response (ISO-8859-1 decode, so binary matches work) |
| `outcome` | outcome fired on match (resolved via the state's `on` map) |
| `capture` | optional fact name; the captured group is stored as `service-<capture>` (`version` → headline `service-version`) |
| `group` | capture group index (default 1) |

Loading is fail-fast: a missing `start`, a dangling transition target, an unknown `action`, or
no reachable terminal (`done`/`fail`) is rejected at load time.

## Action library

| Action | Effect / outcomes |
|---|---|
| `connect` | open a raw TCP (or UDP) connection → `connected` / `error` / `timeout` |
| `reconnect` | open a fresh connection (new index) on the same/alternate port |
| `send` | write `payload`/`data` (raw, or over the secure channel if in TLS mode) → `sent` / `error` |
| `expect` | accumulate inbound bytes and match `patterns` → each rule's `outcome`, else `nomatch` / `timeout` / `error` |
| `starttls` | send `command`, wait for `ready` regex, mark the session as a STARTTLS upgrade → `ready` / `timeout` / `nomatch` / `error` |
| `tls-connect` | open a JSSE (RSA-capable, trust-all) TLS session so `send`/`expect` run over TLS → `connected` / `error` / `timeout`; records `tls-version` / `cipher-suite` / `DIRECT_TLS` |
| `tls-handshake` | Bouncy-Castle non-blocking handshake on the current channel (`mode:"pqc"`) → `handshaked` / `error` / `timeout` |
| `pqc-check` | record TLS facts **and** classify key exchange → `pqc-status` = `PQC` / `CLASSICAL` / `UNKNOWN`; also records cert facts + validity + leaf key/signature analysis + RFC 6125 hostname match |
| `tls-facts` | record TLS facts without PQC classification (same cert facts) |
| `cert-chain-validate` | PKIX chain validation → `cert-chain-trust` = `TRUSTED` / `UNTRUSTED_ROOT` / …, plus `cert-chain-trust-message`, the per-certificate `cert-chain[]` breakdown (trusted root appended), and `cert-chain-time-validity` |
| `revocation-check` | stapled-OCSP (RFC 6066) → `revocation-status` / `revocation-method` |
| `enumerate-versions` | probe TLSv1.3/1.2/1.1/1.0 **and SSLv3**, each a single-version handshake → `supported-protocol-versions` |
| `enumerate-ciphers` | probe cipher suites per version → `supported-cipher-suites` |
| `record` | merge `note` into the result |
| `done` / `fail` | terminal: deliver complete / incomplete |

## Bundled probes (18)

| Probe | Service | Ports | Prio | portScoped | Purpose |
|---|---|---|---|---|---|
| `https-scan` | https | 443,8443 | 72 | yes | **Primary TLS assessment**: PQC + cert-chain + validity + version/cipher enumeration |
| `tls-scan` | **tls** | [] (fallback) | 71 | no | Deep TLS assessment on **any** port (nonstandard TLS); labels `tls` to avoid mislabelling non-HTTP TLS |
| `https-pqc` | https | 443,8443 | 70 | yes | PQC + cert facts; graceful TLS-handshake-failure fallback |
| `https-version` | https | 443,8443 | 68 | no | Shallow HTTPS `Server:` header over JSSE; nonstandard-port HTTPS detection |
| `imaps-pqc` | imaps | 993 | 60 | — | IMAPS direct-TLS + PQC |
| `smtp-starttls-pqc` | smtp | 25,587 | 60 | — | SMTP STARTTLS → PQC |
| `imap-starttls-pqc` | imap | 143 | 60 | — | IMAP STARTTLS → PQC |
| `postgres-tls` | postgresql | 5432 | — | — | PostgreSQL SSLRequest → TLS/PQC posture |
| `postgres-db` | postgresql | 5432 | 66 | — | PostgreSQL SSL/PQC posture (probe **name** matches the filename, as `--probes` selects by name) |
| `postgres-version` | postgresql | 5432 | — | — | PostgreSQL plaintext StartupMessage version (trust-auth) |
| `ssh` | ssh | 22 | — | — | SSH banner (`SSH-2.0-…`) |
| `ftp` | ftp | 21 | — | — | FTP `220` banner |
| `http` | http | 80,8080,8000,8888 | 65 | no | HTTP `Server:` header (gated against TLS-required replies) |
| `pop3` | pop3 | 110 | — | — | POP3 `+OK` banner |
| `redis` | redis | 6379 | — | — | Redis `INFO server` → `redis_version` |
| `mysql` | mysql | 3306 | — | — | MySQL handshake packet version |
| `mongodb` | mongodb | 27017 | — | — | MongoDB `buildInfo` version |
| `dns` | dns | 53 | — | — | DNS over UDP |

> On a declared TLS port (443/8443) `https-scan` wins → `service=https` with full analysis. On a
> nonstandard TLS port `tls-scan` wins → `service=tls` with the same analysis. On a non-TLS port
> the deep probes fail the handshake and the service-specific probe wins.

## Result fields

`service`, `service-version`, `service-<name>` (captures), `tls-state`
(`NONE`/`DIRECT_TLS`/`STARTTLS_UPGRADED`), `pqc-status` (`PQC`/`CLASSICAL`/`UNKNOWN`),
`tls-version`, `cipher-suite`, `key-exchange-group`, `key-exchange-algorithm`,
`cert-subject`, `cert-issuer`, `cert-not-before`, `cert-not-after`,
`cert-validity` (`VALID`/`EXPIRED`/`NOT_YET_VALID`),
`cert-signature-type`, `cert-signature-algorithm`, `cert-public-key-type`,
`cert-public-key-size`, `cert-signature-pqc` (`PQC`/`CLASSICAL`),
`cert-hostname-match` (`MATCH`/`MISMATCH`) + `cert-hostname-message`,
`cert-chain-trust` + `cert-chain-trust-message`, `cert-chain-time-validity` (`VALID`/`INVALID`),
`cert-chain[]` (per-certificate: `index`, `subject`, `issuer`, `not-before`, `not-after`,
`time-valid`, `validity-state`, `self-signed`, `is-ca`, `role` = leaf/intermediate/root),
`revocation-status`, `revocation-method`, `supported-protocol-versions`,
`supported-cipher-suites`, `complete`, `note`, `duration-ms`, `connections[]`.

### Certificate trust (ported from the v1 scanner)

`ProbeResult` stays **facts-only**; the verdict is derived by the rules layer `grade.Grade`,
which exposes `letter()` (A/B/C/F/**T** for a trust failure), `pqc()`, and:

- **`verdict()`** — one authoritative `TrustVerdict`: `TRUSTED` / `EXPIRED` / `NOT_YET_VALID` /
  `UNTRUSTED_CHAIN` / `CHAIN_TIME_INVALID` / `REVOKED` / `UNKNOWN`, in that precedence (so a
  consumer reads one value instead of re-deriving trust from four facts). A trust failure
  outranks protocol/cipher posture and grades **T** (`REVOKED` grades **F**).
- **`reason()`** — the human-readable explanation.
- **`letter()` is only awarded on evidence.** `A` requires that `enumerate-versions` actually ran.
  A shallow probe that merely negotiated TLSv1.3 grades `null`, not `A`: one negotiation cannot
  show whether the server still accepts TLSv1.0, and a false clean bill of health is the worst
  failure mode this tool has. A *negotiated deprecated* version still downgrades (`TLSv1.0` → `C`),
  since that is positive evidence of a bad posture.
- **Weak-cipher detection is anchored, not a substring match.** `TLS_RSA_WITH_*` is static RSA (no
  forward secrecy) and caps at `B`; `TLS_ECDHE_RSA_WITH_*` is a healthy ephemeral suite that merely
  authenticates with an RSA certificate. The earlier `contains("_RSA_WITH")` test matched both, so
  it capped every modern ECDHE server at B while the genuinely weak suites went unflagged — they
  were rendered as `CIPHER_0x9d` because the cipher-name table was a hand-written 11-entry switch.
  `PQCTlsClient.getCipherSuiteName` now maps every code point Bouncy Castle knows (reflected over
  `CipherSuite`'s 328 constants), so the table cannot fall behind the BC version on the classpath.
- **`advisories()`** — report-only findings that never change the verdict: a **hostname
  mismatch** (per the recorded design decision) and a PQC-hybrid key exchange under a classical
  certificate signature.

`Grade.toNVGenericMap()` renders `grade` / `pqc-readiness` / `trust-verdict` / `trust-reason` /
`advisories`; the CLI prints it for TLS results and the REST `Checker` merges it into the
response, so `/check-qdz` returns one authoritative trust answer.

> **Tri-state facts are strings, not booleans, on purpose.** The framework's JSON serializer
> omits default values, so an `NVBoolean(false)` silently disappears and is indistinguishable
> from "not checked" — precisely the distinction these facts carry. Hence
> `cert-chain-time-validity`, `cert-hostname-match` and `cert-signature-pqc` are explicit
> strings. For the same reason the CLI renders via `GSONUtil.toJSONGenericMap(m, true, true,
> false)` (include-defaults) rather than `toJSONDefault`, which would drop `complete:false` and
> a connection's `index:0`.

## CLI

```
java io.xlogistx.nosneak.v2.ProbeChecker <host> <port> [timeoutSec] [--all|--first] [--tcp|--udp] [probe.json …]
```
- default = match-first over the bundled probes on the target's transport;
- `--all` = match-all; explicit `probe.json` files run those probes only (all in priority order).

## Executor / concurrency

**The executor and scheduler are injected, never looked up statically.** Everything downstream
takes them from the `NIOSocket` it is handed — `ProbeContext` reads `nio.getExecutor()` /
`nio.getScheduler()` in its constructor and passes them on to `Fanout.run`/`Fanout.dispatch`, the
version/cipher probe callbacks, `RateLimiter` and `PortScanCallback`. So a timeout can never be
armed on one pool while the I/O it guards runs on another, and an embedder that builds its
`NIOSocket` with its own pools gets the whole pipeline on them.

The only places that name `TaskUtil.defaultTaskProcessor()` / `defaultTaskScheduler()` are the
composition roots that own the process: the `ProbeChecker` and `NMap` CLI `main` methods, and
`Checker.checkQDZDirect` (which builds its own `NIOSocket` precisely because no server supplied
one).

Parallel dispatch is the native trigger-`StateMachine` `publish`; `publishSync` is the inline
sequential path. No `MonoStateMachine`, no hand-rolled threads (`new Thread` / `Executors.new`
appear nowhere in v2). Superseded probes are aborted immediately
(`NIOSocket.abortClientSocket`) so no connection or scheduler appointment lingers.

**`ParallelJoin` is the completion barrier for callback-driven fan-outs** — the children of
`Fanout.run` are `TriggerConsumer`s that report from a NIO/selector/scheduler callback and have no
future to compose on, so a one-shot counting barrier is the right primitive. That covers
`ProbeContext`'s version/cipher enumeration, `ProbeChecker`'s `AllSweep`, and the nmap stages,
whose `PortScanCallback` likewise reports through a callback. Where an operation already returns a
`CompletableFuture` (`HostScanner.sweep`/`ping`/`resolve`), it is composed on directly rather than
wrapped in a barrier.

**Nothing blocks on a live path.** `future.get` survives in exactly three deliberate places, all
documented as such: `ProbeChecker.checkBlocking`/`checkBlockingAll` (CLI/test convenience), the two
CLI `main` methods, and `Checker.checkQDZDirect`. The REST endpoint has none — see below for why
blocking there deadlocks the server rather than merely slowing it.

## REST endpoint (`/check-qdz/{domain}/{detailed}`)

`service/Checker` is **fully asynchronous**: the handler starts the sweep and returns without
waiting, and the response is written from the probe's completion callback.

This is a correctness requirement, not a style choice. `NIOHTTPServer` builds its `NIOSocket` on
`TaskUtil.defaultTaskProcessor()` and dispatches inbound request data to that executor, so the
handler already runs on one of those workers — while the probe sweep it would wait for needs the
*same* pool (`Fanout.dispatch` publishes candidate starts onto the socket's executor, and probe
reads are re-dispatched through it). A blocking `future.get` here therefore starves the pool:
enough concurrent requests and no worker is left to run the probes, so every request can only end
in `checker-timeout` while the rest of the server stalls behind it. Bounding the wait hides the
hang; it does not remove the starvation.

The async handshake with `NIOHTTPServer` has **two** halves and both are required:

1. **Return `Boolean.FALSE`** — the server then skips writing a response (`NIOHTTPServer:538`);
   the endpoint owns it.
2. **Install a `ProtoSession` via `hph.setConnectionSession(...)` whose `canClose()` is false**
   until the response has been written. Without it the server treats the request as finished the
   instant the method returns: `hph.reset()` (`NIOHTTPServer:587`) is skipped only when a
   connection session exists, and the `finally` block closes the connection as soon as
   `canClose()` is true. Once the response is written the session is marked responded and closed,
   releasing the connection.

A scheduled backstop answers `504` if the sweep never calls back, so a stuck candidate cannot hold
a connection open indefinitely. The body is rendered with the include-defaults renderer, because
the framework's JSON path uses `toJSONDefault` and would drop `complete:false`, a chain link's
`time-valid:false`, and a connection's `index:0`. Note the response must be built with the
status/headers-only `buildResponse` overload — the `(contentType, result, …)` one re-serializes an
already-rendered JSON document into a JSON *string*.

**Runtime-verified** (this path had never been exercised before): a single scan returns `200` with
the full fact set plus the `Grade` block, and **32 concurrent requests against an 8-thread pool all
returned `200` in ~6 s wall** — far more scans in flight than there are workers, which the blocking
version could not do.

### Server configuration

**Nothing special.** `keep-alive.time_out` does not have to accommodate the scan: it bounds the
*idle* gap between completed request/response cycles, not the time the server spends producing a
response, and the client has not received anything to act on yet. Verified — a **5.2 s** scan
returns `200` under a **1 s** keep-alive. An 8-thread pool serves 24–32 concurrent scans fine.

### Server-free entry point

`Checker.checkQDZDirect("google.com:443")` runs the whole check — target parsing, probe selection,
sweep, facts + verdict — with **no HTTP server, no `ResourceManager`, no Shiro**: just an
`NIOSocket` it owns and closes. It blocks by design, so it is safe from a `main` or a test but must
not be called from a worker of the pool the probes run on (that is what the REST path's async
handshake exists to avoid). `Checker.main` is a harness that prints the result and its timing.

Measured standalone (cold JVM, one process per run):

| Target | Result | Time |
|---|---|---|
| `google.com:443` | https, PQC_READY | 4542 ms |
| `google.com:443` detailed | + version/cipher enumeration | 3915 ms |
| `example.com:443` | https | 4518–4815 ms |
| `example.com:80` | http | 817 ms |
| `example.com:81` (nothing listening) | no-probe-identified, 14 probes tried | 10370 ms |

Over HTTP with the settings above and warm pools, real targets answer far quicker — 123 ms
(`example.com:80`) to 1825 ms (`github.com:443`) — and **24 concurrent requests all returned `200`
in 4.7 s**. The ~10 s figure is the worst case for a port with nothing listening, where every
candidate must run to its timeout.

## Network scan (nmap)

Staged, fully non-blocking scanner in `v2/nmap/` — embeddable (`NMapScanner.scan(NIOSocket,
NMapConfig, CallableConsumer<ScanReport>)`) and CLI (`NMap`):

1. **host discovery** (optional), which takes one of two routes per target:
   - **On-link CIDR → one `HostScanner.sweep()` per range.** This is no-sneak-net's purpose-built
     range sweep: ARP + ICMP per host, the on-link interface chosen for you, `HostRecord`s streamed
     as they arrive. Its `SweepOptions.defaults()` are tuned for exactly this — 256 in flight, a
     1 s per-host timeout, and a **single** ping probe, because ARP is the liveness oracle and
     extra probes only multiply wall time.
   - **Everything else** (hostnames, off-link IPs, dash-ranges) → the per-host path, running
     TCP-ping, `HostScanner.ping` and `HostScanner.resolve` concurrently; any one marks the host
     up. ICMP uses `observedOnWire()` rather than `reachable()`, so pinging one of our own
     addresses — answered from local configuration with no packet sent — does not count as a wire
     observation. ARP/NDP is attempted only for on-link addresses: it is link-local by definition,
     so asking beyond the segment would only return the router's MAC.
2. **port scan** of the selected ports on each live host (`PortScanCallback`, OPEN/CLOSED/FILTERED);
3. **probe scan** (optional, `-sV`) — runs the probe engine on open ports to identify
   service/version/TLS/PQC (all bundled probes, or a named subset via `--probes`).

> **Use the sweep for ranges — the per-host path is 25× slower.** Doing a `/24` host-by-host meant
> a `resolve()` at the 3 s default, a 2-probe `ping()`, and five TCP-connects per target, all
> funnelled through nmap's own limiter: **55 s**, where the sweep does the same work in **1.6 s**
> and finds the identical hosts. On-link, the TCP-connects add nothing at all — ARP already
> answered. `--max-inflight` is deliberately **not** forwarded to `SweepOptions`: that flag caps
> concurrent TCP connections in the port-scan stage, and forcing it onto the sweep's packet window
> throttled a `/24` to the point of not finishing in 100 s. `--max-rate` *is* forwarded, since it
> is a packet-rate policy.

The `HostScanner` session is opened **once per scan** and closed at the end — `open()` costs a pcap
handle or raw socket plus reader threads per interface, so per-host opening would be wrong. It
borrows the injected pools and never shuts them down, and it *never fails to open*: a box without
Npcap or root yields a usable session in a degraded `Mode` (`ICMP_ONLY` / `UNAVAILABLE`), which is
recorded in `ScanReport.warnings` so a silently ICMP-less or MAC-less scan is visible rather than
looking like a clean result.

The port and probe stages are paced by a non-blocking `RateLimiter` (`--max-inflight` concurrency
cap + `--max-rate` per-second). Targets accept host / IP / CIDR (`10.0.0.0/24`) / range
(`10.0.0.1-50`). CLI flags: `-p`, `-sV`, `--probes a,b`, `-Pn` (skip discovery), `-sn` (discovery
only), `-PR` (ARP/NDP only), `-PE` (ICMP only), `--no-icmp` / `--no-arp` / `--no-tcp-ping`,
`--icmp-probes N`, `--max-inflight N`, `--max-rate N`, `-t <sec>`. A missing or non-numeric flag
value is a clear error plus usage and exit 2, not a stack trace; a failed run exits 1.

Every run ends with a stats line:

```
NMap done: 254 target(s) scanned, 22 host(s) up (22 with MAC) in 1.56 seconds
NMap done: 1 target(s) scanned, 1 host(s) up (1 with MAC), 3 open port(s) on 1 host(s) in 6.43 seconds
```

Verified live on a `10.0.0.0/24` LAN: 254 targets → 22 up in **1.6 s**, **every live host with a
MAC address**. `-PR` and `-PE` each resolve two hosts in ~0.5 s; an off-link target (example.com)
reports its resolved IP and no MAC, as it must. TLS ports render inline with state/PQC/validity/
trust/grade (e.g. `443 open https [DIRECT_TLS pqc=PQC cert=VALID/TRUSTED grade=C]`).

**Output formats.** Five renderers in `v2/nmap/output/` — `NormalFormatter`, `JSONFormatter`,
`XMLFormatter` (nmap-compatible), `CSVFormatter`, `GrepableFormatter` — behind `OutputFormat` /
`OutputFormatter`. CLI: `-oN -oX -oG -oJ -oC <file>` and `-oA <base>` (all formats to
`base.<ext>`); console always prints Normal. All formats carry the deep TLS assessment
(state/PQC/cert-validity/trust/grade), not just a banner. Model: `ScanReport` (run metadata +
`HostReport`{up, reason, mac, osGuess, ip} + `PortReport`{protocol, state, reason, rtt, ttl,
banner, probe}), `PortState` (full nmap set incl. OPEN_FILTERED), `WellKnownPorts` (service table
+ TOP_100_TCP / TOP_20_UDP).

### nmap parity — feature-mapping decisions (porting the old `io.xlogistx.nosneak.nmap` app)

The old app's live path was only TCP-connect + UDP (both NIO); its `service/` and `os/`
subsystems and `raw/` SYN/FIN/… engines were dead/stub code. v2 decisions:
- **Service/version = v2 JSON probes** (`-sV`), strictly superior to the old banner grab → done.
- **Raw scans** (`-sS/-sF/-sN/-sX/-sA`/Window): **reject with a clear error**; real raw scans
  come later via a native raw-socket layer (JDK 25 Panama FFM, no external lib). The flag names
  are nmap's; what a raw layer buys here is *accurate port state* (open vs filtered) on networks
  the operator is authorized to scan — not evasion, which stays out of scope.
- **OS detection** (`-O`): open-port **heuristic only** (best-effort, low confidence). True
  TCP/IP-stack fingerprinting needs raw packets → same FFM layer.
- **ARP ping / remote MAC**: **DONE — no longer deferred.** The old reasoning was right about the
  JDK (no API through JDK 25 exposes a remote host's MAC; `NetworkInterface.getHardwareAddress()`
  is local-NIC only, and the `arp`-command shell-out was correctly refused), but the conclusion is
  obsolete: **`no-sneak-net` shipped the FFM layer-2 backend**, so `HostScanner.sweep`/`resolve`
  give a real ARP/NDP MAC and `HostScanner.ping` a real ICMP echo. nmap discovery calls them
  directly — see the discovery stage above. `ScanReport.HostReport.mac` was declared and never
  populated until this landed.
- **Host discovery is no-sneak-net's job, not nmap's.** When that module offers a primitive, use
  it rather than reimplementing it out of its lower-level calls — the 25× regression above came
  entirely from hand-rolling a range sweep out of per-host `resolve`/`ping`.

## Tests

88 pure, no-network tests under `src/test/java/io/xlogistx/nosneak/v2/` — `model/
ProbeDefinitionLoaderTest` (16), `grade/GradeTest` (25), `result/ProbeResultTest` (12),
`runtime/FanoutTest` (11), `nmap/NMapScannerTest` (19), `nmap/RateLimiterTest` (5).

The newer ones pin defects that were silent in production:
- `GradeTest` — an ECDHE suite that merely *authenticates* with RSA is not weak (only
  `TLS_RSA_WITH_*` static key exchange is), and a scan that never enumerated versions gets no
  letter rather than an unearned `A`.
- `RateLimiterTest` — the in-flight counter can never go negative (once negative, `--max-inflight`
  silently stops capping), and 20 000 synchronously-completing launches must not recurse the drain
  loop into a `StackOverflowError` (what a loopback scan does).

```
MAVEN_OPTS="-Djavax.net.ssl.trustStore=<store>.jks -Djavax.net.ssl.trustStorePassword=changeit" \
  mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.v2.**'
```

Two environment gotchas, neither a code problem:
- the **parent pom** (`xlogistx-mvn`) sets `<skipTests>true</skipTests>` globally, so
  `-DskipTests=false` is required or surefire reports "Tests are skipped";
- if a **TLS-intercepting proxy** is active locally (Avast here), Maven cannot reach central
  (`PKIX path building failed`) and scans report `cert-chain-trust: UNTRUSTED_ROOT` for every
  public host. Fix both by importing the proxy's root into a copy of the JDK `cacerts` and
  pointing `javax.net.ssl.trustStore` at it (`MAVEN_OPTS` for Maven, `-D` for the CLI).

**Not covered yet:** the FSM traversal itself. `ProbeContext` needs an injection seam to drive it
with scripted callbacks (no sockets) so each branch — banner match, `nomatch`, `timeout`,
STARTTLS upgrade, reconnect — can be asserted without a live server.

## Known deferrals

**nmap parity (remaining, next passes):**
- **UDP scan** (`-sU`) — port `UDPScanCallback` + `PacketDataConst` (DNS/SNMP probes) into v2.
- **Timing templates** (`-T0..T5`) → map to rate-limit/parallelism/timeout.
- **Port-spec richness** — `T:`/`U:` protocol prefixes, `--top-ports` (data exists in `WellKnownPorts`).
- **Raw-scan rejection** wiring (`-sS` etc. → clear "not supported / planned" error).
- **OS-detection heuristic** (`-O`) — open-port/service-based guess.
- **Native raw-socket layer (Panama FFM)** — real SYN/FIN/… scans and TCP/IP OS fingerprinting
  (gated on privileges). **ARP → remote MAC is no longer part of this deferral**: it shipped in
  `no-sneak-net` and nmap discovery uses it.

**Other:**
- Active/network OCSP (only stapled-OCSP is implemented).
- `Checker`'s private-IP guard is weak (`isPrivateIP` string-matches literal `10.`/`192.168.`/
  `172.16-31.` prefixes only), so `127.0.0.1`, `169.254.169.254`, `[::1]` and any hostname that
  resolves inward still pass. The endpoint chooses the port too, so it remains an unauthenticated
  internal prober — **fix before exposing it**.
- Weak-cipher enumeration (only the TLS1.2/1.3 suite sets are swept). *Weak-cipher grading itself
  is implemented* — see the `Grade` note below.
- End-to-end runtime testing of the Mongo/DM tools. (`/check-qdz` **is** now runtime-tested — see
  *REST endpoint* below.)
- zoxweb-core additions this line of work depends on: `SSLSessionConfig.getSSLSession()`,
  `NIOSocket.abortClientSocket(SelectionKey)`, `NIOSocket.getExecutor()/getScheduler()`.
- Cross-module dependency: `no-sneak-core` now depends on **`no-sneak-net`** (managed in the root
  pom) for ICMP and layer-2 discovery.
