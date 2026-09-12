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
| `revocation-check` | stapled OCSP (RFC 6066) when the server stapled one; otherwise an **active OCSP** request to the leaf's AIA responder and, failing a definitive answer, its **CRL** — both non-blocking on the probe's own `NIOSocket`, bounded by the state's `revocationTimeoutMs` (default 5000), soft-fail to `UNKNOWN` → `revocation-status` / `revocation-method` (`stapled` \| `ocsp` \| `crl` \| `none` \| `<method>-unreachable`) / `revocation-date` / `revocation-reason`. Asynchronous: fires `done` when the answer is in |
| `enumerate-versions` | probe TLSv1.3/1.2/1.1/1.0 **and SSLv3**, each a single-version handshake → `supported-protocol-versions` |
| `enumerate-ciphers` | one handshake per candidate suite (opsec's 5 TLS 1.3 + 39 TLS 1.2 strong/weak/insecure suites, offered singly — an ordinary ClientHello) → `supported-cipher-suites` (flat names) and `supported-cipher-suite-details[]` (`name`, `version`, `strength`, `key-exchange`, `forward-secrecy`); then two more handshakes offering every accepted suite in our order and reversed → `server-cipher-preference` + `-mode` (`server` \| `client` \| `only-one-accepted`) |
| `enumerate-groups` | one TLS 1.3 handshake per candidate named group, each offering only that group (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, x25519, x448, secp256r1, secp384r1, secp521r1, ffdhe2048, ffdhe3072) → `supported-groups` (hybrids first) and `server-group-preference` (the group the main handshake negotiated when all were offered). A TLS 1.2-only server accepts none — key shares are a TLS 1.3 mechanism |
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
`revocation-status`, `revocation-method`, `revocation-date`, `revocation-reason`,
`supported-protocol-versions`, `supported-cipher-suites`,
`supported-cipher-suite-details[]` (`name`, `version`, `strength`, `key-exchange`,
`forward-secrecy` = `YES`/`NO` — a string, for the same reason as the other tri-states),
`server-cipher-preference` + `server-cipher-preference-mode`, `supported-groups`,
`server-group-preference`, `complete`, `note`, `duration-ms`, `connections[]`.

**Enumeration budget (2026-09-11).** A deep probe (`https-scan`, `tls-scan`) opens at most
5 (versions) + 44 (ciphers) + 2 (cipher preference) + 10 (groups) = **61 child connections**, each
bounded by its own handshake timeout and all inside the probe's overall watchdog;
`ProbeContext.MAX_ENUMERATION_CHILDREN` (64) truncates any candidate list that would grow past
it. Every child is a `Fanout` task on the injected executor — nothing blocks. Offering a weak
suite or an old group is an ordinary ClientHello; nothing beyond a handshake is ever sent.

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
- **Cipher tiers (2026-09-11, `Grade.CipherPosture`), in the order SSL Labs applies them.** Once
  `enumerate-ciphers` began offering opsec's weak and insecure sets, the old any-CBC rule dropped
  every ECDHE-CBC server from A to B (xlogistx.io among them) — SSL Labs keeps A there, because the
  CBC defect is MAC-then-encrypt, not the key exchange. The rule is now three tiers:
  **insecure** (RC4, NULL, EXPORT, single DES, anonymous kx) caps at **C** with an advisory;
  **weak** (static-RSA / static-ECDH key exchange, i.e. no forward secrecy, or 3DES / SWEET32)
  caps at **B**; **forward-secret CBC** (ECDHE/DHE + AES-CBC) is an **advisory only**
  ("CBC suites accepted: …; prefer AEAD"), letter unchanged. Forward secrecy comes from
  `supported-cipher-suite-details` when present and is inferred from the name otherwise
  (`*DHE*` and TLS 1.3 suites ephemeral; `TLS_RSA_WITH_*`, `TLS_ECDH_*` not). Pinned by
  `GradeTest.forwardSecretCbcIsAnAdvisoryNotACap`, `liveXlogistxShapeGradesA` (A, one advisory)
  and `liveGoogleShapeGradesC`.
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
version/cipher probe callbacks, `ScanGate` and `PortScanCallback`. So a timeout can never be
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

The port and probe stages are paced by a non-blocking `ScanGate` (`--max-inflight` concurrency
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

**Port-scan classification and what a connect scan can see (2026-09-11).** `PortScanCallback`
reports a `Result(state, reason, rttMs, banner)`; the scanner never guesses a reason from a state.
The table is v1's: connection refused → `CLOSED/conn-refused`; reset → `CLOSED/reset`;
unreachable or no route → `FILTERED/no-route`; deadline → `FILTERED/timeout`; **any other
exception → `FILTERED/error:<Class>`** (it used to read CLOSED, which reported a reachable closed
port for a generic error); a completed connect → `OPEN/connected` (the old `syn-ack` string was
false — this is a full connect). `rttMs` is measured from construction to `connectedFinished`.
After connecting, the socket stays open for min(1 s, timeout) on the injected scheduler and the
first bytes the server volunteers (≤ 1024, ISO-8859-1, CR/LF collapsed) become `PortReport.banner`;
TLS and HTTP ports volunteer nothing and pay exactly the window. TTL is unobservable on a connect
scan and stays −1. Live on 2026-09-11: xlogistx.io:443 open, rtt 1 ms; google.com:80/443 open,
rtt 25 ms; no banner on either, as expected. The renderers below do not yet show per-port
`reason`/`rttMs` (`PENDING-ISSUES.md` P20).

**Output formats.** Five renderers in `v2/nmap/output/` — `NormalFormatter`, `JSONFormatter`,
`XMLFormatter` (nmap-compatible), `CSVFormatter`, `GrepableFormatter` — behind `OutputFormat` /
`OutputFormatter`. CLI: `-oN -oX -oG -oJ -oC <file>` and `-oA <base>` (all formats to
`base.<ext>`); console always prints Normal. All formats carry the deep TLS assessment
(state/PQC/cert-validity/trust/grade), not just a banner. Model: `ScanReport` (run metadata +
`HostReport`{up, reason, mac, osGuess, ip} + `PortReport`{protocol, state, reason, rtt, ttl,
banner, probe}), `PortState` (full nmap set incl. OPEN_FILTERED), `WellKnownPorts` (service table
+ TOP_100_TCP / TOP_20_UDP).

**JSON is not hand-written (2026-09-12).** `JSONFormatter` is two lines: `ScanReport.toNVGenericMap()`
rendered by `GSONUtil.toJSONGenericMap(m, true, true, false)` — the same serialiser `ProbeResult`
and the REST endpoint use. The v1-ported writer with its own string escaper is gone. The shape is
declared once, on the report: absent facts are absent keys (no `null`, no `-1`); each port carries
the flattened probe summary (`version`, `tls`, `pqc`, `certValidity`, `certChainTrust`, `grade`)
*and* the full `ProbeResult` map under `probe`; hidden states sit under `notShown`. `printNull`
must stay `true`: with it off Gson also drops default-valued primitives, and `cancelled: false` /
`up: false` would vanish — the tri-state trap. `FormattersTest` parses the output back rather than
string-matching it. Consumers: the `-oJ` file, the app's stored report, and the assistant's chat
attachment; a report saved before this date has the old flat shape.

Since 2026-09-11 every format renders the per-port **`reason`** and, when the connect completed,
the **round-trip time**: Normal has `REASON` and `RTT` columns; JSON has `reason` always and
`rttMs` only when measured (never `-1`); XML keeps nmap's `<state state reason/>` and adds
`rttms` on `<port>` plus nmap's `<extraports state count/>` for collapsed states; CSV appends
`reason,rttms` as the last two columns; grepable puts the reason in nmap's `owner` slot and the
RTT in the `rpc` slot (`443/open/tcp/connected/25ms//https//`). **Which ports are listed is one
rule for all five**, `HostReport.portsToRender(cfg)`: with `--open` only potentially-open ports;
otherwise nmap's habit — a non-open state is listed port by port up to
`RenderSelection.COLLAPSE_THRESHOLD` (10) entries, which is where `conn-refused` versus
`no-route` versus `timeout` is worth reading, and collapsed into the "Not shown: N closed, M
filtered" count beyond that. Potentially-open states are never collapsed. Pinned by
`FormattersTest`.

**Probe catalog: one definition per name.** `NMapScanner.buildChecker` merges bundled and
subject-authored (`extraProbes`) definitions by name: a stored probe that reuses a bundled name
**replaces** it (the subject wrote it deliberately; running both was two connections per open
port for one answer) and a warning names the shadowed bundled probe; a second stored definition
with an already-used name is ignored with a warning. `ExtraProbeCatalogTest` pins both.

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

145 pure, no-network tests in 11 classes under `src/test/java/io/xlogistx/nosneak/v2/` (recounted
2026-09-11; the earlier "88 in 6" was stale by three classes) — `model/ProbeDefinitionLoaderTest`
(16), `model/ProbeDefinitionParseTest` (6), `grade/GradeTest` (25), `result/ProbeResultTest` (12),
`runtime/FanoutTest` (11), `nmap/NMapScannerTest` (19), `nmap/NMapParseCommandTest` (27),
`nmap/ExtraProbeCatalogTest` (5), `nmap/ScanGateTest` (7), `nmap/PortScanCallbackTest` (17),
`nmap/UnitTest` (2). Maven cannot run them on the Windows dev box (surefire's JUnit provider is
not cached and the TLS proxy blocks the download); run them class-by-class through IntelliJ.

The newer ones pin defects that were silent in production:
- `GradeTest` — an ECDHE suite that merely *authenticates* with RSA is not weak (only
  `TLS_RSA_WITH_*` static key exchange is), and a scan that never enumerated versions gets no
  letter rather than an unearned `A`.
- `ScanGateTest` — the in-flight counter can never go negative (once negative, `--max-inflight`
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

**Testing the FSM (2026-09-11).** `ProbeContext` now talks to the wire only through a
package-private `ProbeTransport` seam (`NioProbeTransport` in production, over the injected
`NIOSocket`); the scheduler and executor are constructor parameters. `runtime/ScriptedTransport`
records every connection, every byte written and every handshake start, and pushes the peer's side
back into the context; `runtime/ManualScheduler` never fires on its own, so a test fires a connect,
expect or overall deadline by hand. `runtime/ProbeContextTest` (18) drives the bundled `ssh`, `http`,
`ftp` and `smtp-starttls-pqc` definitions through banner match with capture, a banner split across
two reads, `nomatch`, `error`, both wait timeouts, the overall watchdog, an unmapped outcome, a failed
write, `reconnect` to an alternate port, STARTTLS `ready` → handshake start, cancel mid-flight,
exactly-once delivery, a stale timer from an earlier `arm()` generation, and — the P10 fix — that the
user's callback never runs while the context monitor is held (`Thread.holdsLock` inside the
callback). `ProbeCheckerTest` (14) drives the two-tier ordering and the match-first election with
the same transport: a lower-priority completion waits for the higher-priority candidate, the
highest wins at once and the rest are cancelled, all-fail → none-identified with the well-known
name and `probes-tried`, `checkAll` in priority order. `runtime/SendBytesTest` (7) pins the
`hex:`/`base64:`/`text:`/bare/`payload` codecs and that only text is templated;
`model/MongoPayloadTest` (3) decodes the two hand-written MongoDB hex payloads against the OP_QUERY /
OP_MSG wire format. What still needs a live server: the Bouncy Castle handshake itself, the
enumeration children, and `tls-connect` over JSSE.

## Known deferrals

**nmap parity (remaining, next passes):**
- ~~**UDP scan** (`-sU`) — port `UDPScanCallback` + `PacketDataConst` (DNS/SNMP probes) into v2.~~
  **Done 2026-09-11**: `nmap/UdpScanCallback` — one *connected* ephemeral datagram socket per
  host:port on the shared `NIOSocket`, one datagram, one retransmit at half the budget, then:
  any reply → `open`/`udp-response` (RTT + banner); ICMP port-unreachable (a
  `PortUnreachableException`, or Windows' "forcibly closed" reset on a connected UDP socket) →
  `closed`/`port-unreach`; other unreachables → `filtered`/`no-route`; silence for the budget →
  `open|filtered`/`no-response`. Payloads (`nmap/UdpProbePayloads`): a recursive A query for a
  fixed name on 53, an NTPv4 client request on 123, an empty datagram everywhere else — **no
  SNMP probe**, because a GET carries a community string and sending `public` to see who answers
  is a credential guess. `-sU` alone is UDP-only over `WellKnownPorts.TOP_20_UDP`; `-p U:…` names
  the ports (and is scanned even without `-sU`); `T:` ports or `--top-ports` alongside scan both
  stacks. The probe stage runs the UDP probes (`dns.json`) only on UDP ports that *answered* — an
  open|filtered port is one nobody spoke to. Every datagram socket goes through the same
  `ScanGate` as the TCP connects. Live 2026-09-11: see `PENDING-ISSUES.md` P7.
- **Probe-stage pacing (P4), done 2026-09-11**: `ProbeChecker(nio, probes, ConnectionGate)` paces
  the probe engine through the scan's `ScanGate` (which implements `runtime/ConnectionGate`)
  via `runtime/GatedProbeTransport.Registry`. Two things are counted, two ways: a **candidate
  probe** holds one slot from the moment its `start()` is admitted until it delivers or is
  cancelled — an unadmitted candidate is simply *not started*, so none of its timers run and it
  cannot time out while waiting; and a deep probe's **enumeration children** (5 versions + 12
  ciphers) are admitted at once through `submitNow` and counted until aborted or the parent
  finishes — a probe never waits on itself, and while its children are counted no new candidate
  is admitted. A cancelled context delivers nothing, so `FirstSweep` tells the factory
  (`ContextFactory.cancelled`) and the registry hands the slot back; losers are cancelled lowest
  priority first so a queued start is marked dead before an earlier loser's slot frees. The nmap
  probe stage's per-port unit is a barrier only: holding a slot there as well would let the ports
  fill the cap and starve the very connections they wait on. Pinned by `ProbePacingTest` (two
  slots, three candidates: never more than two started; a cancelled candidate that never started
  owes nothing; every slot back at the end) and `GatedProbeTransportTest` (child accounting).
  Live: `google.com -p 80,443 -sV --max-inflight 2` identifies both ports with full TLS detail in
  19 s versus ~6 s uncapped — the cost is latency, never a lost answer.
- ~~**Timing templates** (`-T0..T5`) → map to rate-limit/parallelism/timeout.~~ **Done 2026-09-11**:
  `NMapConfig.Timing` (T0 1/1/15s … T3 256/2000/5s default … T5 1024/10000/2s); an explicit
  `--max-inflight`/`--max-rate`/`-t` after the template overrides that one knob.
- ~~**Port-spec richness** — `T:`/`U:` protocol prefixes, `--top-ports`.~~ **Done 2026-09-11**:
  `NMap.parsePortSpec`, `--top-ports N` over `WellKnownPorts.topTcp`, `--open` recorded on
  `NMapConfig.openOnly` (the formatters do not honour it yet — rendering gap, tracked in
  `PENDING-ISSUES.md`).
- ~~**Raw-scan rejection** wiring.~~ **Done 2026-09-11**: `-sS -sF -sX -sN -sA -sW -sM -O --stealth`
  are refused with `NMap.rejectionMessage(flag)`, which names the flag and the operating-scope
  rule; `NMapParseCommandTest` walks every one.
- **OS-detection heuristic** (`-O`) — open-port/service-based guess. `-O` itself is now
  *rejected* (it is nmap's raw-fingerprint flag); a heuristic, if ever built, needs its own
  flag name so it cannot be mistaken for fingerprinting.
- **Bounded defaults**: `NMapConfig` now defaults to 256 in flight / 2000 per second, matching
  `no-sneak-net`'s `SweepOptions.defaults()`; `0` still means unlimited when set explicitly.
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
