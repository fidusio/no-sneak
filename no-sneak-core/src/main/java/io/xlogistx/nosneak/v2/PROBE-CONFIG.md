# no-sneak v2 — Probe Configuration Reference

Reference for the `io.xlogistx.nosneak.v2` probe framework: the JSON probe DSL, the action
library, candidate selection, the bundled probes, and the result fields. (Migration status and
design rationale live in `PLAN.md`.)

## Core objective

For a TLS endpoint, report **how valid it is and whether it is PQC-compliant / PQC-ready** —
certificate chain trust, certificate validity, negotiated + enumerated protocol versions and
cipher suites, key-exchange classification (classical vs PQC-hybrid), and a letter grade. The
non-TLS probes (ssh, ftp, http, databases, dns, …) identify the service and, where possible, its
version.

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
| `pqc-check` | record TLS facts **and** classify key exchange → `pqc-status` = `PQC` / `CLASSICAL` / `UNKNOWN`; also records cert facts + validity |
| `tls-facts` | record TLS facts without PQC classification |
| `cert-chain-validate` | PKIX chain validation → `cert-chain-trust` = `TRUSTED` / `UNTRUSTED_ROOT` / … |
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
| `postgres-db` | postgresql | 5432 | — | — | PostgreSQL SSL/PQC posture |
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
`cert-validity` (`VALID`/`EXPIRED`/`NOT_YET_VALID`), `cert-chain-trust`,
`revocation-status`, `revocation-method`, `supported-protocol-versions`,
`supported-cipher-suites`, `complete`, `note`, `duration-ms`, `connections[]`.
For TLS results the CLI also prints a `grade` (letter + PQC readiness) via `grade.Grade`.

## CLI

```
java io.xlogistx.nosneak.v2.ProbeChecker <host> <port> [timeoutSec] [--all|--first] [--tcp|--udp] [probe.json …]
```
- default = match-first over the bundled probes on the target's transport;
- `--all` = match-all; explicit `probe.json` files run those probes only (all in priority order).

## Executor / concurrency

`TaskUtil.defaultTaskProcessor()` (parallel `publish`) and `TaskUtil.defaultTaskScheduler()`
(timeouts). No `MonoStateMachine`. Superseded probes are aborted immediately
(`NIOSocket.abortClientSocket`) so no connection or scheduler appointment lingers.

## Network scan (nmap)

Staged, fully non-blocking scanner in `v2/nmap/` — embeddable (`NMapScanner.scan(NIOSocket,
NMapConfig, CallableConsumer<ScanReport>)`) and CLI (`NMap`):

1. **host discovery** (optional) over the target range — TCP-ping (up if a discovery port
   connects or is refused) + optional ICMP (`InetAddress.isReachable`, best-effort);
2. **port scan** of the selected ports on each live host (`PortScanCallback`, OPEN/CLOSED/FILTERED);
3. **probe scan** (optional, `-sV`) — runs the probe engine on open ports to identify
   service/version/TLS/PQC (all bundled probes, or a named subset via `--probes`).

Paced by a non-blocking `RateLimiter` (`--max-inflight` concurrency cap + `--max-rate`
per-second). Targets accept host / IP / CIDR (`10.0.0.0/24`) / range (`10.0.0.1-50`). CLI flags:
`-p`, `-sV`, `--probes a,b`, `-Pn` (skip discovery), `-sn` (discovery only), `--no-icmp`,
`--max-inflight N`, `--max-rate N`, `-t <sec>`. TLS ports render inline with state/PQC/validity/
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
  come later via a native raw-socket layer (JDK 25 Panama FFM, no external lib).
- **OS detection** (`-O`): open-port **heuristic only** (best-effort, low confidence). True
  TCP/IP-stack fingerprinting needs raw packets → same FFM layer.
- **ARP ping / remote MAC**: **deferred to the FFM native layer** (with `-sS`). Rationale: no JDK
  API (through JDK 25) exposes a remote host's MAC — MAC is layer-2/ARP; `NetworkInterface.
  getHardwareAddress()` is local-NIC only. The only paths are the OS `arp` command (external
  process, platform-specific) or native raw ARP. Decided NOT to ship the `arp`-command shell-out;
  discovery stays pure-NIO (TCP-ping ± ICMP, no MAC) until the FFM ARP work.

## Known deferrals

**nmap parity (remaining, next passes):**
- **UDP scan** (`-sU`) — port `UDPScanCallback` + `PacketDataConst` (DNS/SNMP probes) into v2.
- **Timing templates** (`-T0..T5`) → map to rate-limit/parallelism/timeout.
- **Port-spec richness** — `T:`/`U:` protocol prefixes, `--top-ports` (data exists in `WellKnownPorts`).
- **Raw-scan rejection** wiring (`-sS` etc. → clear "not supported / planned" error).
- **OS-detection heuristic** (`-O`) — open-port/service-based guess.
- **Native raw-socket layer (Panama FFM)** — real SYN/FIN/… scans, TCP/IP OS fingerprinting, and
  **ARP → remote MAC** (all gated on privileges). Replaces the deferred ARP-command approach.

**Other:**
- Active/network OCSP (only stapled-OCSP is implemented).
- Weak-cipher enumeration/grading (only TLS1.2/1.3 suite sets are swept).
- End-to-end runtime testing of the REST endpoint (`/check-qdz`) and Mongo/DM tools.
- zoxweb-core additions this line of work depends on: `SSLSessionConfig.getSSLSession()`,
  `NIOSocket.abortClientSocket(SelectionKey)`.
