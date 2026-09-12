# Probe Definition Guide (`probe.json`)

> **Scope note (2026-09-12).** This guide is the complete, self-contained specification of a
> NoSneak probe definition. It covers every action and every field a definition may use,
> including the deep TLS assessment actions (§4.2) and their budgets (§3). Nothing here depends
> on how the engine is implemented; a probe is data, and this document is the whole contract for
> that data. The engineering reference for the engine itself is `PROBE-CONFIG.md` next to this
> file; a probe author does not need it.

> **Purpose / how to use this file.** This is a complete specification for authoring a NoSneak
> **protocol probe** as a single JSON document. Give this file to an AI as a skill, then ask it:
> *"Write a probe.json that detects &lt;protocol&gt; on port &lt;N&gt;."* The AI must output **one valid
> JSON object** that conforms to the schema and rules below. A probe is a small **state machine**:
> it connects to a `host:port`, optionally exchanges a few messages, optionally upgrades to TLS,
> and records structured facts (service, TLS state, PQC status, cert) — all driven by data, using
> a fixed library of trusted actions. **JSON never runs code**; it only selects and configures
> the built-in actions listed here.

---

> **What a probe may do — binding on every probe, hand-written or model-written.** A probe
> **identifies** a service. It may connect, send the minimum the protocol needs to elicit a banner
> or reach a handshake, upgrade to TLS, match patterns, and record facts. It may **not**: guess or
> send credentials, send input designed to crash, hang, corrupt or overflow the peer, fuzz, loop to
> exhaust a resource, or carry an exploit for any CVE. If a protocol can only be identified by
> doing one of those, the correct answer is "no probe" — say so instead of writing it. Probes run
> against endpoints the operator is authorized to assess; keeping them innocuous is part of what
> makes that true.

## 1. What a probe does

A probe is a directed graph of **states**. Entering a state runs its one **action**. The action
produces an **outcome label** (e.g. `connected`, `sent`, `ready`, `handshaked`, `nomatch`,
`timeout`, `error`, or a custom label from a pattern match). The engine looks up that label in the
state's `on{}` map to find the next state, and repeats until a terminal state (`done` or `fail`).

The probe emits a facts-only result: `service`, `tls-state` (`NONE` / `DIRECT_TLS` /
`STARTTLS_UPGRADED`), `pqc-status` (`PQC` / `CLASSICAL` / `UNKNOWN` / …), `tls-version`,
`cipher-suite`, `key-exchange-group`, `cert-subject`, `cert-issuer`, `complete` (reached `done`),
and a `note`.

---

## 2. Top-level schema (`ProbeDefinition`)

The document is a JSON object with these keys:

| Key | Type | Required | Meaning |
|-----|------|----------|---------|
| `name` | string | yes | Unique probe id, e.g. `"imap-starttls-pqc"`. |
| `service` | string | yes | Service label recorded in the result, e.g. `"imap"`. |
| `transport` | string | no (default `"tcp"`) | `"tcp"` or `"udp"`. On `"udp"` the engine binds an ephemeral datagram socket: `connect` fires `connected` at once, `send` writes one datagram, `expect` matches the reply. **TLS actions need `"tcp"`.** The bundled `dns` probe is the UDP example (§11.6). |
| `ports` | array of int | yes | Ports this probe is associated with, e.g. `[143]`. Used to auto-select the probe per port (a checker may also run it regardless of ports). |
| `priority` | int | no (default `50`) | Higher = preferred when several probes match a port. Specific protocols high, generic TLS catch-alls low. |
| `portScoped` | bool | no (default `false`) | If `true`, the probe runs **only on its declared `ports`**, never as a generic fallback on other ports. Set it on ungated "any-TLS" catch-alls (e.g. `https-pqc`, `imaps-pqc`) that would otherwise mislabel an unrelated TLS service (Postgres-over-TLS, etc.). |
| `overallTimeoutSec` | int | no | Watchdog for one run of this probe, in seconds. Default `max(4 × per-step timeout, 30)`, which suits a banner grab. **Declare it on any probe that uses the enumeration actions** (§4.2) — the bundled deep scans use `90`. Must be `> 0`. |
| `start` | string | yes | The state id where execution begins. |
| `states` | object | yes | Map of **state id → state object** (see §3). Keys are arbitrary strings you choose. |

Unknown top-level keys are ignored (forward-compatible), but do not rely on that — emit only the
keys above.

---

## 3. State schema (`ProbeState`)

Each value in `states` is an object:

| Key | Type | Used by | Meaning |
|-----|------|---------|---------|
| `action` | string | all | The action to run (see §4). **Required.** |
| `on` | object | all non-terminal | Map of **outcome label → next state id**. Terminal states (`done`/`fail`) omit it. |
| `payload` | string | `send` | Templated UTF-8 **text** to send (see templating §6). |
| `data` | string | `send` | Codec-prefixed payload, incl. **binary** (see §5). Takes precedence over `payload`. |
| `patterns` | array | `expect` | List of `{ "regex": "...", "outcome": "..." }` rules (see §4 `expect`). |
| `command` | string | `starttls` | The protocol upgrade command to send, e.g. `"STARTTLS\r\n"` (templated text). |
| `ready` | string | `starttls` | Regex that signals the server is ready to upgrade, e.g. `"^220"`. Default `"^220"`. |
| `mode` | string | `tls-handshake` | `"pqc"` (default) or `"classical"` (see §4 `tls-handshake`). |
| `note` | string | `record` | Free-text annotation merged into the result's `note`. |
| `port` | int | `connect`, `reconnect`, `tls-connect` | Connect to this port instead of the target port. |
| `revocationTimeoutMs` | int | `revocation-check` | Bound on the active OCSP/CRL fetch. Default `5000`. Must be `> 0`. |
| `includeSSLv3` | bool | `enumerate-versions` | Also offer SSLv3. Default `true` (observe everything). |
| `includeTLS10` | bool | `enumerate-versions` | Also offer TLS 1.0. Default `true`. |
| `includeTLS11` | bool | `enumerate-versions` | Also offer TLS 1.1. Default `true`. TLS 1.3 and 1.2 are always offered. |
| `includeWeak` | bool | `enumerate-ciphers` | Also offer the weak TLS 1.2 suites (no forward secrecy, 3DES). Default `true`. |
| `includeInsecure` | bool | `enumerate-ciphers` | Also offer the insecure TLS 1.2 suites (RC4, NULL, EXPORT, single DES, anonymous). Default `true`. |
| `rankServerPreference` | bool | `enumerate-ciphers` | After a `server`-ordered verdict, derive the server's ranking with up to 10 extra sequential handshakes. Default `false`. |
| `maxInFlight` | int | `enumerate-*` | Child handshakes in flight at once against the target. Default `8`. Must be `> 0`. |

Only the fields relevant to a state's action are read; others are ignored. The boolean toggles are
tri-state: **omit** a toggle to take the engine default, or set it explicitly so the choice is
visible in the definition (the bundled `https-scan`/`tls-scan` set every toggle explicitly).

---

## 4. Action reference

Every action below is built in. An action **must** ultimately cause exactly one `fire(outcome)`
(handled for you) or a terminal delivery. For each action: what it does, its config fields, and
the **outcome labels** you must map in `on{}`.

### `connect`
Opens a new TCP connection to `port` (the state's `port`, else the target port).
- **Config:** `port` (optional).
- **Outcomes:** `connected` · `error` · `timeout`.

### `send`
Writes a payload to the current channel. Resolves bytes from `data` (codec-prefixed, §5) if
present, else `payload` (templated text). A failed/absent channel or bad payload fires `error`.
- **Config:** `data` (preferred, binary-capable) or `payload` (text).
- **Outcomes:** `sent` · `error`.

### `expect`
Accumulates inbound bytes and tests them against `patterns` in order. On the first regex that
matches, fires that rule's `outcome` and clears the buffer. Matching is done over an **ISO-8859-1**
decode of the raw bytes (see §7), using `find()` (substring; anchor with `^` if needed).
- **Config:** `patterns`: array of `{ "regex": "<regex>", "outcome": "<label>",
  "capture": "<fact-name>" (optional), "group": <int> (optional) }`.
- **Service-version / banner capture (optional):** a rule may add `capture` to record a fact
  extracted from the match — see §7.5. Use `capture:"version"` to populate the result's headline
  `service-version`, or any other name (`product`, `banner`, …) for an additional `service-<name>`.
- **Outcomes:** each rule's `outcome` · `nomatch` (peer closed after sending data, no rule matched)
  · `error` (peer closed before any data) · `timeout` (deadline reached, still no match).

### `starttls`
Sends `command` (templated text), then waits for the `ready` regex on the reply. Marks the session
as a STARTTLS upgrade, so a following `tls-handshake` records `STARTTLS_UPGRADED`.
- **Config:** `command` (the upgrade command), `ready` (regex, default `"^220"`).
- **Outcomes:** `ready` · `nomatch` · `error` · `timeout`.

### `tls-connect`
Opens a **new** connection to `port` (the state's `port`, else the target port) and completes a
**classical TLS handshake** on it, accepting any certificate (trust-all — this is detection, not
validation). On success the session is in **secure mode**, so the subsequent `send`/`expect`
actions exchange **application data through the established TLS session** — this is how you read
an HTTPS `Server:` header or any implicit-TLS banner. It records the negotiated TLS version and
cipher but **cannot classify PQC** and **cannot feed the deep assessment actions** (§4.2).
Distinct from `tls-handshake`, which upgrades the channel that is already open and exposes the
full handshake for PQC classification, certificate facts and the deep actions. Use `tls-connect`
when you need to *talk* through TLS; use `tls-handshake` when you need facts about the TLS itself.
`connected` fires only after the handshake completes.
- **Config:** `port` (optional).
- **Outcomes:** `connected` · `error` · `timeout`.

### `tls-handshake`
Performs a TLS handshake on the **current already-open channel** (a mid-session upgrade if reached
after `starttls`, otherwise a direct handshake on connect). `mode` selects what the ClientHello
advertises:
- `"pqc"` (default) — PQC hybrid groups (X25519MLKEM768, …) **plus** classical.
- `"classical"` — **only classical** groups (a fully classical handshake, no PQC).
- **Config:** `mode` (optional).
- **Outcomes:** `handshaked` · `error` · `timeout`.

### `pqc-check`
Records TLS facts (state, version, cipher, key-exchange group, cert) **and** classifies the
negotiated key exchange as `pqc-status`: `PQC` (a hybrid group was negotiated), `CLASSICAL`
(TLS 1.3 with a classical group — upgradeable), `NOT_READY` (TLS 1.2 or older — no PQC path), or
`UNKNOWN` (nothing negotiated). Use after `tls-handshake` when you want PQC assessment.
- **Config:** none.
- **Outcomes:** `done`.

### `tls-facts`
Records the same TLS facts as `pqc-check` but **without** any PQC classification (`pqc-status`
stays `UNKNOWN`). Use when you only need to confirm TLS/STARTTLS, not assess post-quantum.
- **Config:** none.
- **Outcomes:** `done`.

### 4.2 Deep TLS assessment actions

These five actions turn an identification probe into a posture scan. **All of them require a
prior `tls-handshake` in the same run** — `tls-connect` does not qualify, because it keeps the
handshake internal and exposes only the application-data session — and all of them fire only `done`: they never fail
the probe, they soft-fail into facts (`UNKNOWN`, an empty list) so the run still completes. Put
them after `pqc-check` and before `record`, in the order below; each later one is more expensive.
Declare `overallTimeoutSec` on the definition when you use any enumeration.

#### `cert-chain-validate`
PKIX chain-to-root validation of the presented chain against the JVM trust store, plus the
per-certificate breakdown with the matched root appended. Records `cert-chain-trust`
(`TRUSTED`, `UNTRUSTED_ROOT`, `EXPIRED`, …), `cert-chain-trust-message`,
`cert-chain-time-validity` (`VALID`/`INVALID`) and the `cert-chain[]` list.
- **Config:** none.
- **Outcomes:** `done`.
- **Cost:** none on the wire (local computation).

#### `revocation-check`
Revocation status of the leaf: the handshake-stapled OCSP response when one was stapled and
parses; otherwise an active OCSP request to the leaf's AIA responder, then its CRL if OCSP is not
definitive — both bounded by `revocationTimeoutMs`, soft-failing to `UNKNOWN`. A
CRL cannot be verified without the issuer certificate, so a chain of one is `UNKNOWN`, never
`GOOD`. Records `revocation-status` (`GOOD`/`REVOKED`/`UNKNOWN`/`NOT_SUPPORTED`/`ERROR`),
`revocation-method` (`stapled`/`ocsp`/`crl`/`none`), and on `REVOKED` the `revocation-date` and
`revocation-reason`.
- **Config:** `revocationTimeoutMs` (optional, default 5000).
- **Outcomes:** `done` (asynchronous — fires when the answer is in or the budget expires).
- **Cost:** at most two HTTP fetches.

#### `enumerate-versions`
One extra handshake per candidate protocol version, each offering only that version, run in
parallel `maxInFlight` at a time. TLS 1.3 and 1.2 are always offered; `includeSSLv3`,
`includeTLS10`, `includeTLS11` add the legacy ones. Records `supported-protocol-versions`
(best first). The grade only awards **A** when this action ran — without the evidence a clean
bill of health is not earned.
- **Config:** `includeSSLv3`, `includeTLS10`, `includeTLS11`, `maxInFlight` (all optional).
- **Outcomes:** `done`.
- **Cost:** up to 5 connections.

#### `enumerate-ciphers`
One extra handshake per candidate cipher suite, each offering only that suite (5 TLS 1.3 suites
plus the TLS 1.2 strong set, and the weak/insecure sets unless toggled off), `maxInFlight` at a
time, then two more handshakes offering the accepted set forward and reversed to learn whether the
server or the client picks. Records `supported-cipher-suites`, `supported-cipher-suite-details`
(name, version, strength, key exchange, authentication, encryption, MAC, forward secrecy),
`server-cipher-preference` (the top pick) and `server-cipher-preference-mode`
(`server`/`client`/`only-one-accepted`). With `rankServerPreference: true` and a `server` verdict,
up to 10 further sequential handshakes derive `server-cipher-ranking`.
- **Config:** `includeWeak`, `includeInsecure`, `rankServerPreference`, `maxInFlight` (all optional).
- **Outcomes:** `done`.
- **Cost:** up to ~46 connections (+10 with ranking). This is the expensive one.

#### `enumerate-groups`
One extra TLS 1.3 handshake per candidate named group (the ML-KEM hybrids, the X25519/X448 and
NIST curves, the FFDHE groups), each offering only that group, `maxInFlight` at a time. Records
`supported-groups` and `server-group-preference` (what the server chose when everything was
offered). This is how a scan learns *which* PQC groups a server accepts, not only the one it
negotiated.
- **Config:** `maxInFlight` (optional).
- **Outcomes:** `done`.
- **Cost:** up to 10 connections.

**Policy reminder.** These actions complete ordinary handshakes and read what the server
volunteers. Do not chain them on ports where a service identification probe would do — a deep
scan against every port of a host is the load the rate limits exist to prevent. Bundle them in a
`portScoped` probe on the TLS ports (as `https-scan` does) or in a non-port-scoped fallback with
`"ports": []` (as `tls-scan` does), never both.

### `record`
Merges `note` into the result. Use to tag a confirmed identification or a branch outcome.
- **Config:** `note` (optional).
- **Outcomes:** `done`.

### `reconnect`
Closes the current channel and opens a fresh one (to `port`, else the target port), while the state
machine and accumulated result persist. This is how a probe uses **multiple connections** (e.g.
connect once to read the default, reconnect to test something else).
- **Config:** `port` (optional).
- **Outcomes:** `connected` · `error` · `timeout` (same as `connect`).

### `done` (terminal)
Ends the probe as **complete** (`complete: true`). No `on`.

### `fail` (terminal)
Ends the probe as **incomplete** (`complete: false`). No `on`.

---

## 5. Sending binary data (`data` codecs)

`send` (and only `send`) can emit **arbitrary bytes** via the `data` field, using a codec prefix:

| Form | Meaning |
|------|---------|
| `"hex:3a0000…"` | Raw bytes decoded from hex. Even number of hex chars, **no spaces or newlines**, case-insensitive, optional leading `0x`. |
| `"base64:OiwA…"` | Raw bytes decoded from base64. |
| `"text:EHLO {probe.hostname}\r\n"` | Templated UTF-8 text (explicit). |
| `"…"` (no prefix) | Templated UTF-8 text (default). |

`data` takes precedence over `payload` when both are present. Use `hex:`/`base64:` for binary
protocols (MongoDB, DNS-over-TCP, Redis binary, etc.). For a request/response binary protocol,
`send` the request bytes, then `expect` a regex on ASCII markers in the reply (see §7).

**Building a hex payload:** compute the exact wire bytes of the protocol's request message and
encode as one continuous lowercase/uppercase hex string. Double-check the byte count. Example
(MongoDB legacy `isMaster` `OP_QUERY` to `admin.$cmd`, 58 bytes):
`"hex:3a0000000000000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069734d6173746572000100000000"`.

---

## 6. Templating

In **text** payloads (`payload`, text `data`, and `starttls.command`), these tokens are expanded
at send time:

| Token | Expands to |
|-------|-----------|
| `{probe.hostname}` | The target host (as given). |
| `{probe.port}` | The current connection's port. |

Templating does **not** apply to `hex:`/`base64:` data.

---

## 7. How `expect` / regex matching works

- Inbound bytes are accumulated and decoded as **ISO-8859-1** (lossless for bytes 0–255). This
  means an ASCII marker inside a **binary** response still matches — e.g. `maxWireVersion` /
  `ismaster` inside a MongoDB BSON reply, or `+PONG` from Redis.
- Each rule's `regex` uses **Java-dialect regular-expression syntax** (`\\d`, `(?i)`, `.*?`,
  named groups) and matches **anywhere** in the accumulated buffer. Use `^` to anchor to the start,
  `$` for end.
- Rules are tried **in array order**; the first match wins.
- **JSON escaping:** backslashes must be doubled. To match a literal `*` write `"\\*"`; a digit
  class is `"\\d"`; a CR/LF in a `payload` is written `\r\n`.
- If nothing matches yet, the probe keeps waiting for more bytes until `timeout` or the peer
  closes (`nomatch` if data was seen, `error` if not).

---

## 7.5. Capturing service facts (version detection)

A probe can extract the **running service version** (or any banner-derived fact) by adding a
`capture` to a matched `expect` pattern rule. When that rule matches, the engine pulls a regex
capture group out of the match and records it on the result as a **service fact**.

| Field | Type | Meaning |
|-------|------|---------|
| `capture` | string | The fact name to record, e.g. `"version"`, `"product"`, `"banner"`. Omit ⇒ no extraction. |
| `group` | int | The capture-group index to extract (default `1`; `0` = the whole match). |

Rules:
- The value is taken from `matcher.group(group)`, **trimmed**, has CR/LF collapsed to spaces, and is
  **capped at 256 chars**. Extraction is best-effort — a missing group or out-of-range index simply
  records nothing and never fails the probe.
- The reserved name **`version`** becomes the result's headline `service-version` (also exposed via
  `ProbeResult.getServiceVersion()`). **Any other name** is emitted as `service-<name>` (e.g.
  `capture:"product"` → `service-product`). All captured facts also appear in
  `getServiceFacts()`.
- Put **one** capture group per fact in the regex and point `group` at it. To record several facts,
  either use several rules across chained `expect` states, or a single regex with multiple groups
  plus one `capture` per rule (first-match-wins still applies to the branch `outcome`).
- Because a matched `expect` **clears the accumulation buffer**, a second `expect` on the *same*
  response starts empty and waits for more bytes. Capture the fact you need in the rule that first
  matches the banner.

Typical version sources: SSH server-id line (`SSH-2.0-OpenSSH_9.6p1 …`), SMTP/IMAP/POP3/FTP
greetings, an HTTP `Server:` response header (send a request first, then capture), Redis `INFO`
`redis_version:`. Implicit-TLS banners (e.g. IMAPS on 993) arrive *inside* TLS, so they cannot be
captured by a plaintext `expect` — capture the pre-`STARTTLS` greeting instead where one exists.

---

## 8. Validation rules (the probe must pass all)

A probe is rejected at load time unless:
1. `start` names a state that exists.
2. Every value in every `on{}` map names a state that exists (no dangling transitions).
3. Every `action` is one of: `connect`, `send`, `expect`, `starttls`, `tls-connect`,
   `tls-handshake`, `pqc-check`, `tls-facts`, `cert-chain-validate`, `revocation-check`,
   `enumerate-versions`, `enumerate-ciphers`, `enumerate-groups`, `record`, `reconnect`, `done`,
   `fail`.
4. At least one terminal state (`done` or `fail`) is **reachable** from `start`.
5. Every declared budget is positive: `overallTimeoutSec`, `maxInFlight`, `revocationTimeoutMs`.

**JSON must be strict:** no comments, no trailing commas, all strings double-quoted. Do **not** add
comment keys inside `states` (the map is typed — a stray key breaks parsing).

---

## 9. Design rules (make a *good* probe, not just a valid one)

- **Gate identification behind a protocol-specific check.** Only reach a `record`/`done` through
  something that proves the protocol: a banner regex, an `expect` match on a protocol marker, or a
  successful TLS handshake (for implicit-TLS ports). Non-matching input should route to `fail`.
  This lets a checker run the probe against the wrong port and get a clean `fail` instead of a
  false positive.
- **Always map `error` and `timeout`** on `connect`, `expect`, `starttls`, and `tls-handshake`
  (to `fail` or a graceful `record` branch). Map `error` on `send`.
- **Choose the TLS terminal action:** `pqc-check` if you want PQC classification; `tls-facts` if
  you only need TLS confirmation without a PQC judgement.
- **Choose the handshake mode:** `mode:"pqc"` (default) to detect PQC; `mode:"classical"` for a
  guaranteed classical handshake.
- **Include both `done` and `fail`** terminals.
- **Record a useful `note`** on each terminal `record` (e.g. `"imap"`, `"imap-no-starttls"`).
- **Priority:** specific protocol probes higher (e.g. 60–70); generic TLS catch-alls lower (e.g. 50).

---

## 10. Recipes (state-graph skeletons)

**Direct/implicit TLS (e.g. 443 HTTPS, 993 IMAPS):**
`connect → tls-handshake(mode:pqc) → pqc-check → record → done` ; `connect.error/timeout → fail`,
`tls-handshake.error/timeout → fail`.

**Fully classical TLS (no PQC):** same, but `tls-handshake` `mode:"classical"` (and optionally
`tls-facts` instead of `pqc-check`).

**Deep TLS assessment (posture scan on a TLS port):**
`connect → tls-handshake(mode:pqc) → pqc-check → cert-chain-validate → revocation-check →
enumerate-versions → enumerate-ciphers → enumerate-groups → record → done` ; only `connect` and
`tls-handshake` can fail. Set `overallTimeoutSec` (90 for the full chain), `portScoped: true` on
declared TLS ports, and every toggle explicitly. Drop `enumerate-groups` / `enumerate-ciphers` for a
cheaper scan; keep `enumerate-versions` if you want the grade to be able to reach A.

**Secure app-data / version over TLS (e.g. HTTPS `Server:` header, implicit-TLS banners):**
`tls-connect → send(app request) → expect(marker, capture:"version") → record → done`;
`tls-connect.error/timeout → fail`. `tls-connect` completes a classical, trust-all handshake
and puts the session in secure mode, so `send`/`expect`/`capture` operate *through* TLS. Gate on a
protocol marker (e.g. an HTTP status line) so a non-HTTP TLS service routes to `fail` rather than a
false positive.

**STARTTLS (e.g. 25 SMTP, 143 IMAP, 110 POP3, 21 FTP):**
`connect → expect(banner) → send(greeting cmd) → expect(capability marker) → starttls(command,ready)
→ tls-handshake → pqc-check → record → done`, with graceful branches: no banner → `fail`; no
STARTTLS capability → `record(note:"…-no-starttls") → done`; handshake fails →
`record(note:"…-handshake-failed") → done`.

**Banner / text request-response (e.g. Redis, SSH, plain SMTP id):**
`connect → [expect(banner) | send(cmd) → expect(reply marker)] → record → done`; no match → `fail`.
Add `capture` to the banner rule to record the running version (see §7.5), e.g. SSH:
`expect(regex:"^SSH-\\d+\\.\\d+-([^\\r\\n]*)", capture:"version") → record → done`.

**Binary request-response (e.g. MongoDB):**
`connect → send(data:"hex:…") → expect(regex on ASCII markers) → record → done`; no match/closed →
`fail`. To also grab a **version** from a binary reply, chain a second request whose response
carries it and `capture` on a field marker — e.g. MongoDB: detect via `isMaster`, then
`send(buildInfo OP_MSG) → expect("\\x02version\\x00[\\s\\S]{4}([0-9][^\\x00]*?)\\x00",
capture:"version")`, routing `nomatch`/`timeout`/`error` back to a plain `record` so the service is
still reported when the version is unavailable (e.g. auth-gated). Many DB versions are only
disclosed post-authentication (PostgreSQL `server_version` after SCRAM; MongoDB `buildInfo` when
access control is on) — capture best-effort and never hang the probe.

**Multi-connection:** insert a `reconnect` between phases (it re-enters a `connect`-style state
while keeping the result).

---

## 11. Full examples

### 11.1 IMAPS (implicit TLS, PQC) — port 993
```json
{
  "name": "imaps-pqc",
  "service": "imaps",
  "transport": "tcp",
  "ports": [993],
  "priority": 65,
  "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "tls", "error": "fail", "timeout": "fail" } },
    "tls":     { "action": "tls-handshake", "mode": "pqc", "on": { "handshaked": "pqc", "error": "fail", "timeout": "fail" } },
    "pqc":     { "action": "pqc-check", "on": { "done": "record" } },
    "record":  { "action": "record", "note": "imaps", "on": { "done": "done" } },
    "done":    { "action": "done" },
    "fail":    { "action": "fail" }
  }
}
```

### 11.2 SMTP STARTTLS (TLS facts, no PQC) — ports 25/587
```json
{
  "name": "smtp-starttls",
  "service": "smtp",
  "transport": "tcp",
  "ports": [25, 587],
  "priority": 60,
  "start": "connect",
  "states": {
    "connect":     { "action": "connect", "on": { "connected": "banner", "error": "fail", "timeout": "fail" } },
    "banner":      { "action": "expect", "patterns": [{ "regex": "^220[ -]", "outcome": "ok" }],
                     "on": { "ok": "ehlo", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "ehlo":        { "action": "send", "payload": "EHLO {probe.hostname}\r\n", "on": { "sent": "ehloResp", "error": "fail" } },
    "ehloResp":    { "action": "expect", "patterns": [{ "regex": "STARTTLS", "outcome": "cap" }],
                     "on": { "cap": "starttls", "nomatch": "recordPlain", "timeout": "recordPlain", "error": "recordPlain" } },
    "starttls":    { "action": "starttls", "command": "STARTTLS\r\n", "ready": "^220",
                     "on": { "ready": "tls", "nomatch": "recordPlain", "timeout": "recordPlain", "error": "fail" } },
    "tls":         { "action": "tls-handshake", "mode": "pqc",
                     "on": { "handshaked": "facts", "error": "recordNoTls", "timeout": "recordNoTls" } },
    "facts":       { "action": "tls-facts", "on": { "done": "record" } },
    "record":      { "action": "record", "note": "smtp-starttls", "on": { "done": "done" } },
    "recordPlain": { "action": "record", "note": "smtp-no-starttls", "on": { "done": "done" } },
    "recordNoTls": { "action": "record", "note": "smtp-starttls-handshake-failed", "on": { "done": "done" } },
    "done":        { "action": "done" },
    "fail":        { "action": "fail" }
  }
}
```

### 11.3 MongoDB (binary handshake) — ports 27017–27019
```json
{
  "name": "mongodb",
  "service": "mongodb",
  "transport": "tcp",
  "ports": [27017, 27018, 27019],
  "priority": 55,
  "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "hello", "error": "fail", "timeout": "fail" } },
    "hello":   { "action": "send",
                 "data": "hex:3a0000000000000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069734d6173746572000100000000",
                 "on": { "sent": "reply", "error": "fail" } },
    "reply":   { "action": "expect",
                 "patterns": [{ "regex": "ismaster|maxWireVersion|topologyVersion|maxBsonObjectSize", "outcome": "mongo" }],
                 "on": { "mongo": "record", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "record":  { "action": "record", "note": "mongodb", "on": { "done": "done" } },
    "done":    { "action": "done" },
    "fail":    { "action": "fail" }
  }
}
```

### 11.3a HTTPS `Server:` header over TLS (secure app-data) — port 443
```json
{
  "name": "https-version",
  "service": "https",
  "transport": "tcp",
  "ports": [443, 8443],
  "priority": 45,
  "start": "connect",
  "states": {
    "connect": { "action": "tls-connect", "on": { "connected": "get", "error": "fail", "timeout": "fail" } },
    "get":     { "action": "send",
                 "data": "text:GET / HTTP/1.0\r\nHost: {probe.hostname}\r\nUser-Agent: no-sneak\r\nConnection: close\r\n\r\n",
                 "on": { "sent": "resp", "error": "fail" } },
    "resp":    { "action": "expect",
                 "patterns": [
                   { "regex": "(?i)Server:\\s*([^\\r\\n]+)", "outcome": "server", "capture": "version" },
                   { "regex": "^HTTP/.*?\\r\\n\\r\\n", "outcome": "noserver" }
                 ],
                 "on": { "server": "record", "noserver": "recordNoServer", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "record":         { "action": "record", "note": "https-server-header", "on": { "done": "done" } },
    "recordNoServer": { "action": "record", "note": "https-no-server-header", "on": { "done": "done" } },
    "done":           { "action": "done" },
    "fail":           { "action": "fail" }
  }
}
```
`tls-connect` completes the classical handshake; the `GET` and its response then ride
through TLS. The `Server:` rule captures the version; the `^HTTP/.*?\r\n\r\n` rule (end of headers)
is the graceful no-`Server` branch and also gates identification to genuine HTTP (a non-HTTP TLS
service produces neither and routes to `fail`). Verified live: github.com → `service-version:
github.com`.

### 11.4a SSH (banner grab + version capture) — port 22
```json
{
  "name": "ssh",
  "service": "ssh",
  "transport": "tcp",
  "ports": [22, 2222],
  "priority": 65,
  "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "banner", "error": "fail", "timeout": "fail" } },
    "banner":  { "action": "expect",
                 "patterns": [{ "regex": "^SSH-\\d+\\.\\d+-([^\\r\\n]*)", "outcome": "ssh", "capture": "version" }],
                 "on": { "ssh": "record", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "record":  { "action": "record", "note": "ssh", "on": { "done": "done" } },
    "done":    { "action": "done" },
    "fail":    { "action": "fail" }
  }
}
```
Against a stock server this yields `service-version: "OpenSSH_9.6p1 Ubuntu-3ubuntu13"` (etc.).

### 11.4 Redis (text request-response) — port 6379
```json
{
  "name": "redis",
  "service": "redis",
  "transport": "tcp",
  "ports": [6379],
  "priority": 55,
  "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "ping", "error": "fail", "timeout": "fail" } },
    "ping":    { "action": "send", "payload": "PING\r\n", "on": { "sent": "pong", "error": "fail" } },
    "pong":    { "action": "expect", "patterns": [{ "regex": "\\+PONG", "outcome": "ok" }, { "regex": "-NOAUTH|-ERR", "outcome": "ok" }],
                 "on": { "ok": "record", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "record":  { "action": "record", "note": "redis", "on": { "done": "done" } },
    "done":    { "action": "done" },
    "fail":    { "action": "fail" }
  }
}
```

---

### 11.5 HTTPS deep posture scan — ports 443/8443 (the bundled `https-scan`)

```json
{
  "name": "https-scan",
  "service": "https",
  "transport": "tcp",
  "ports": [443, 8443],
  "priority": 72,
  "portScoped": true,
  "overallTimeoutSec": 90,
  "start": "connect",
  "states": {
    "connect":    { "action": "connect", "on": { "connected": "tls", "error": "fail", "timeout": "fail" } },
    "tls":        { "action": "tls-handshake", "mode": "pqc", "on": { "handshaked": "pqc", "error": "fail", "timeout": "fail" } },
    "pqc":        { "action": "pqc-check", "on": { "done": "certchain" } },
    "certchain":  { "action": "cert-chain-validate", "on": { "done": "revocation" } },
    "revocation": { "action": "revocation-check", "on": { "done": "versions" } },
    "versions":   { "action": "enumerate-versions", "includeSSLv3": true, "includeTLS10": true, "includeTLS11": true, "maxInFlight": 8, "on": { "done": "ciphers" } },
    "ciphers":    { "action": "enumerate-ciphers", "includeWeak": true, "includeInsecure": true, "rankServerPreference": false, "maxInFlight": 8, "on": { "done": "groups" } },
    "groups":     { "action": "enumerate-groups", "maxInFlight": 8, "on": { "done": "record" } },
    "record":     { "action": "record", "note": "https-scan", "on": { "done": "done" } },
    "done":       { "action": "done" },
    "fail":       { "action": "fail" }
  }
}
```

Why it looks like this: priority 72 beats the shallow `https-pqc` (70) and `https-version` (68)
so a default scan of 443 delivers the full assessment; `portScoped` keeps it off ports where the
label `https` would be wrong (the non-port-scoped twin `tls-scan`, service `tls`, `"ports": []`,
covers those); the toggles are written out so a reader sees the whole surface is observed.

### 11.6 DNS over UDP — port 53 (the bundled `dns`)

```json
{
  "name": "dns",
  "service": "dns",
  "transport": "udp",
  "ports": [53],
  "priority": 60,
  "start": "connect",
  "states": {
    "connect": { "action": "connect", "on": { "connected": "query", "error": "fail", "timeout": "fail" } },
    "query":   { "action": "send",
                 "data": "hex:123401000001000000000000076578616d706c6503636f6d0000010001",
                 "on": { "sent": "resp", "error": "fail" } },
    "resp":    { "action": "expect",
                 "patterns": [{ "regex": "^\\x12\\x34[\\x80-\\xff]", "outcome": "dns" }],
                 "on": { "dns": "record", "nomatch": "fail", "timeout": "fail", "error": "fail" } },
    "record":  { "action": "record", "note": "dns", "on": { "done": "done" } },
    "done":    { "action": "done" },
    "fail":    { "action": "fail" }
  }
}
```

The payload is a fixed A query for `example.com` with transaction id `0x1234`; the pattern
accepts a reply that echoes the id with the QR bit set. Same actions, same rules — only the
transport differs.

---

## 12. Author self-check (before returning the JSON)

- [ ] Output is a **single strict JSON object** — no comments, no trailing commas, all keys/strings quoted.
- [ ] `name`, `service`, `ports`, `start`, `states` present; `transport` is `"tcp"` unless the protocol is genuinely UDP.
- [ ] `start` names an existing state.
- [ ] Every `on{}` target names an existing state.
- [ ] Every `action` is from the allowed list (§8 rule 3).
- [ ] Both `done` and `fail` exist and are reachable; every non-terminal path can reach a terminal.
- [ ] `connect`/`expect`/`starttls`/`tls-handshake` map `error` and `timeout`; `send` maps `error`.
- [ ] Identification is gated behind a protocol-specific check (banner/expect/handshake); wrong input → `fail`.
- [ ] Regex backslashes are doubled (`\\*`, `\\d`); CR/LF in text is `\r\n`.
- [ ] Any `data:"hex:…"` is even-length, continuous, no spaces; byte count verified.
- [ ] If capturing a version/banner, the `capture` rule's regex has a group at `group` (default 1),
      and `capture:"version"` is used for the headline `service-version` (see §7.5).
- [ ] Chose `pqc-check` vs `tls-facts` and `mode` (`pqc` vs `classical`) deliberately.
- [ ] Any `cert-chain-validate` / `revocation-check` / `enumerate-*` state comes **after a
      `tls-handshake`** in the same run (never after `tls-connect`), maps only `done`, and the
      definition declares `overallTimeoutSec` when an `enumerate-*` action is present.
- [ ] A deep-scan probe is either `portScoped` on declared TLS ports or a `"ports": []` fallback,
      not a broad catch-all — it opens dozens of connections per port.

---

## 13. Output contract for the AI

When asked to create a probe, respond with **only the JSON object** (optionally in a single fenced
```json block), nothing else — no prose, no comments inside the JSON. The result must load and pass
the validation in §8 as-is. Application data *through* an established TLS session **is** supported
for **implicit/direct TLS** via `tls-connect` (then `send`/`expect`/`capture` ride the TLS session).
UDP request/response is supported (`"transport": "udp"`, §11.6). If the protocol needs a
capability still not covered by the actions in §4 (e.g. QUIC/DTLS, a
**mid-session STARTTLS upgrade followed by application data** — `tls-connect` only does a fresh
direct handshake — or a response whose bytes must be computed from earlier server bytes), state that
limitation briefly **outside** the JSON instead of inventing a field or action.
