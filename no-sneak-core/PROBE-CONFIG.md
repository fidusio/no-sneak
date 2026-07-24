# Probe Definition Authoring Guide (`probe.json`)

> **Purpose / how to use this file.** This is a complete specification for authoring a NoSneak
> **protocol probe** as a single JSON document. Give this file to an AI as a skill, then ask it:
> *"Write a probe.json that detects &lt;protocol&gt; on port &lt;N&gt;."* The AI must output **one valid
> JSON object** that conforms to the schema and rules below. A probe is a small **state machine**:
> it connects to a `host:port`, optionally exchanges a few messages, optionally upgrades to TLS,
> and records structured facts (service, TLS state, PQC status, cert) — all driven by data, using
> a fixed library of trusted actions. **JSON never runs code**; it only selects and configures
> the built-in actions listed here.

---

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
| `transport` | string | no (default `"tcp"`) | `"tcp"` or `"udp"`. **Use `"tcp"`** — UDP actions are not implemented yet. |
| `ports` | array of int | yes | Ports this probe is associated with, e.g. `[143]`. Used to auto-select the probe per port (a checker may also run it regardless of ports). |
| `priority` | int | no (default `50`) | Higher = preferred when several probes match a port. Specific protocols high, generic TLS catch-alls low. |
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
| `mode` | string | `tls-handshake` | `"pqc"` (default) or `"jsse"`/`"classical"` (see §4 `tls-handshake`). |
| `note` | string | `record` | Free-text annotation merged into the result's `note`. |
| `port` | int | `connect`, `reconnect` | Connect to this port instead of the target port. |

Only the fields relevant to a state's action are read; others are ignored.

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
- **Config:** `patterns`: array of `{ "regex": "<java-regex>", "outcome": "<label>" }`.
- **Outcomes:** each rule's `outcome` · `nomatch` (peer closed after sending data, no rule matched)
  · `error` (peer closed before any data) · `timeout` (deadline reached, still no match).

### `starttls`
Sends `command` (templated text), then waits for the `ready` regex on the reply. Marks the session
as a STARTTLS upgrade, so a following `tls-handshake` records `STARTTLS_UPGRADED`.
- **Config:** `command` (the upgrade command), `ready` (regex, default `"^220"`).
- **Outcomes:** `ready` · `nomatch` · `error` · `timeout`.

### `tls-handshake`
Performs a TLS handshake on the **current already-open channel** (a mid-session upgrade if reached
after `starttls`, otherwise a direct handshake on connect). `mode` selects what the ClientHello
advertises:
- `"pqc"` (default) — PQC hybrid groups (X25519MLKEM768, …) **plus** classical.
- `"jsse"` / `"classical"` — **only classical** groups (a fully classical handshake, no PQC).
- **Config:** `mode` (optional).
- **Outcomes:** `handshaked` · `error` · `timeout`.

### `pqc-check`
Records TLS facts (state, version, cipher, key-exchange group, cert) **and** classifies the
negotiated key exchange: `PQC` (hybrid), `CLASSICAL`, or `UNKNOWN`. Use after `tls-handshake` when
you want PQC assessment.
- **Config:** none.
- **Outcomes:** `done`.

### `tls-facts`
Records the same TLS facts as `pqc-check` but **without** any PQC classification (`pqc-status`
stays `UNKNOWN`). Use when you only need to confirm TLS/STARTTLS, not assess post-quantum.
- **Config:** none.
- **Outcomes:** `done`.

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
- Each rule's `regex` is a **Java regular expression**, applied with `find()` (matches anywhere in
  the buffer). Use `^` to anchor to the start, `$` for end.
- Rules are tried **in array order**; the first match wins.
- **JSON escaping:** backslashes must be doubled. To match a literal `*` write `"\\*"`; a digit
  class is `"\\d"`; a CR/LF in a `payload` is written `\r\n`.
- If nothing matches yet, the probe keeps waiting for more bytes until `timeout` or the peer
  closes (`nomatch` if data was seen, `error` if not).

---

## 8. Validation rules (the probe must pass all)

A probe is rejected at load time unless:
1. `start` names a state that exists.
2. Every value in every `on{}` map names a state that exists (no dangling transitions).
3. Every `action` is one of: `connect`, `send`, `expect`, `starttls`, `tls-handshake`,
   `pqc-check`, `tls-facts`, `record`, `reconnect`, `done`, `fail`.
4. At least one terminal state (`done` or `fail`) is **reachable** from `start`.

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
- **Choose the handshake mode:** `mode:"pqc"` (default) to detect PQC; `mode:"jsse"` for a
  guaranteed classical handshake.
- **Include both `done` and `fail`** terminals.
- **Record a useful `note`** on each terminal `record` (e.g. `"imap"`, `"imap-no-starttls"`).
- **Priority:** specific protocol probes higher (e.g. 60–70); generic TLS catch-alls lower (e.g. 50).

---

## 10. Recipes (state-graph skeletons)

**Direct/implicit TLS (e.g. 443 HTTPS, 993 IMAPS):**
`connect → tls-handshake(mode:pqc) → pqc-check → record → done` ; `connect.error/timeout → fail`,
`tls-handshake.error/timeout → fail`.

**Fully classical TLS (no PQC):** same, but `tls-handshake` `mode:"jsse"` (and optionally
`tls-facts` instead of `pqc-check`).

**STARTTLS (e.g. 25 SMTP, 143 IMAP, 110 POP3, 21 FTP):**
`connect → expect(banner) → send(greeting cmd) → expect(capability marker) → starttls(command,ready)
→ tls-handshake → pqc-check → record → done`, with graceful branches: no banner → `fail`; no
STARTTLS capability → `record(note:"…-no-starttls") → done`; handshake fails →
`record(note:"…-handshake-failed") → done`.

**Banner / text request-response (e.g. Redis, SSH, plain SMTP id):**
`connect → [expect(banner) | send(cmd) → expect(reply marker)] → record → done`; no match → `fail`.

**Binary request-response (e.g. MongoDB):**
`connect → send(data:"hex:…") → expect(regex on ASCII markers) → record → done`; no match/closed →
`fail`.

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

## 12. Author self-check (before returning the JSON)

- [ ] Output is a **single strict JSON object** — no comments, no trailing commas, all keys/strings quoted.
- [ ] `name`, `service`, `ports`, `start`, `states` present; `transport` is `"tcp"`.
- [ ] `start` names an existing state.
- [ ] Every `on{}` target names an existing state.
- [ ] Every `action` is from the allowed list (§8 rule 3).
- [ ] Both `done` and `fail` exist and are reachable; every non-terminal path can reach a terminal.
- [ ] `connect`/`expect`/`starttls`/`tls-handshake` map `error` and `timeout`; `send` maps `error`.
- [ ] Identification is gated behind a protocol-specific check (banner/expect/handshake); wrong input → `fail`.
- [ ] Regex backslashes are doubled (`\\*`, `\\d`); CR/LF in text is `\r\n`.
- [ ] Any `data:"hex:…"` is even-length, continuous, no spaces; byte count verified.
- [ ] Chose `pqc-check` vs `tls-facts` and `mode` (`pqc` vs `jsse`) deliberately.

---

## 13. Output contract for the AI

When asked to create a probe, respond with **only the JSON object** (optionally in a single fenced
```json block), nothing else — no prose, no comments inside the JSON. The result must load and pass
the validation in §8 as-is. If the protocol needs a capability not covered by the actions in §4
(e.g. UDP/QUIC/DTLS, application data sent *through* an established TLS session, or a response whose
bytes must be computed from earlier server bytes), state that limitation briefly **outside** the
JSON instead of inventing a field or action.
