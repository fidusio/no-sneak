# Pending issues — handoff

*Written 2026-08-13. This is the index of known open work at handoff time. The per-module lists
below stay authoritative for their areas; the "Code review findings" section records issues found
in the uncommitted working tree on this date (scan panel + AI assistant changes, post-`bf072b9`)
that are not written down anywhere else.*

> **Before picking anything up:** the repo root `CLAUDE.md` → *Operating scope* states what this
> tooling does and does not do (assessment and detection only — no exploitation, credential
> attacks, DoS, or evasion). Finding 1 below is a data-boundary defect, which is the other half of
> the same rule set.

> **Status check 2026-09-09** at the bottom of this file: build/test state on the dev box, and
> confirmation that all ten findings below were still open at `c082f11`. **All ten were fixed on
> 2026-09-11** (wave 1, group ζ) — see the priority matrix at the bottom for what is still open.

## Where the existing open-work lists live

| Area | Authoritative list |
|---|---|
| Scanning engine | `no-sneak-core/ACTION-PLAN.md` → *Pending Issues / Next Steps* (item 1, vulnerability-check checklist, is the largest remaining gap) |
| Probe engine reference / deferrals | `no-sneak-core/PROBE-CONFIG.md` → *Known deferrals* |
| Host discovery | `no-sneak-net/CLAUDE.md` §13.21 — open items split per platform. **As of 2026-09-11 every code item there is fixed** (§13.22 sweep admission; §13.23-A/B/C the rest); what remains is M1/M9/L1 (need a Mac / the appliance / a v6 segment — **Linux IPv6/NDP has still never touched a wire**) and S6 (by design). Next steps for this module are rows N1–N5 in the priority matrix at the bottom of this file. |
| App loading/session | `no-sneak-app/LOADING.md` |

## Code review findings (2026-08-13, uncommitted working tree)

Ten verified findings from a full review of the pending scan-panel and AI-assistant changes.
Nine confirmed, one plausible. Ordered by severity; the first two are the ones to fix before
anything ships.

### no-sneak-app — ScanPanel

1. **Cross-subject data leak on logout** — `ScanPanel.java:98` *(confirmed)*
   The `onAuthChange` handler only calls `reloadScanResults()`/`reloadProbes()`. It never clears
   `resultText`, `viewScanTextArea`, `nameText`/`commandText`, `lastScanName`, `selectedScan`, or
   `tickedProbes`, and `sendResultToChatButton` stays enabled once set (line 180). Subject A runs a
   scan and logs out; subject B logs in, sees A's full JSON network report, and one click sends A's
   network topology into B's chat and persists it there. `AppShell.java:58-64` resets only the
   assistant on logout — ScanPanel needs a `resetPanel()` like SubjectPanel/AssistantPanel have.

2. **Scan report saved to the encrypted store on the EDT** — `ScanPanel.java:186` *(confirmed)*
   `ctx.session().saveScanResult(r)` runs inside the Run action's done-consumer, which
   `SwingWorker.done()` invokes on the EDT (`BackgroundTask.java:44-58`; `onDone.accept` is outside
   the try/catch). A ~53 KB /24 report is AES-encrypted and inserted while the UI is frozen, and if
   the subject logged out mid-scan, `getSubjectGUID()` is null and the save throws — an uncaught EDT
   exception with no dialog, and the `reloadScanResults()` on line 187 never runs. Violates the
   module rule that all blocking Session calls go through `BackgroundTask.runCatching`; every other
   Session call in this file does it correctly.

3. **Probe names with spaces/commas become scan targets** — `ScanPanel.java:224` *(confirmed)*
   `ProbeDefinitionLoader.validate` only rejects null/empty names (`ProbeDefinitionLoader.java:141-143`),
   and probes now arrive from the AI assistant's editor, where a model writing
   `"name": "Redis TLS handshake"` is ordinary. `effectiveCommand` splices the name into
   `--probes ...`; `NMap.parseCommand` splits on whitespace (`NMap.java:141-145`), so `TLS` and
   `handshake` become scan **targets** — the scanner probes hosts the user never asked for — and a
   comma fans out into bogus probe names. The mangled string is also persisted as the report's
   description and `command` property, so the saved report claims a scan that never ran. Fix at
   depth: apply ticks to the parsed `NMapConfig` directly (`cfg.probeScan(true)`, `cfg.probe(name)`)
   and derive the command string for display only — or forbid whitespace/commas in `validate()`.

4. **Tick state keyed by bare probe name conflates duplicates** — `ScanPanel.java:207` *(confirmed)*
   `tickedProbes` is a `Set<String>` spanning both selector sections, and `fillProbe` accepts a
   stored probe named identically to a bundled one. Ticking either checkbox selects both
   definitions; unticking either deselects both while the other box still looks checked. Worse:
   with 18 bundled probes plus one duplicate-named stored probe, ticking only the 18 bundled boxes
   makes `selected.size() == bundledProbes.size() + countNamedProbes()` (line 223), so the
   all-ticked shortcut emits bare `-sV` and the engine runs the **entire catalog** against a live
   network — probes the user never ticked, with the stored command not reflecting it. Renames also
   orphan ticks (`fillProbe` rewrites the name from the JSON), and the set is never pruned on
   reload or logout.

5. **Re-saving a probe always inserts, and duplicates then run twice per port** — `ScanPanel.java:505` *(confirmed)*
   `saveProbeFromEditor` has no lookup by name or GUID; `Session.saveProbe` inserts whenever the
   GUID is empty. Ask the model to fix a probe and pick "Save as: probe" a second time: the Probe
   Library shows two rows with one name, one tick selects both (lines 210-217), `effectiveCommand`
   emits `--probes X,X`, `buildChecker`'s subset gains both catalog entries
   (`NMapScanner.java:556-563`), and FirstSweep launches both concurrently — two
   connections/handshakes per open port. There is also currently no way to *update* an
   assistant-authored probe at all.

6. **Scan timeout surfaces as `Unexpected error: null`** — `ScanPanel.java:558` *(confirmed)*
   `future.get(timeout, ms)` on a CompletableFuture throws a `TimeoutException` with a null
   message; `BackgroundTask.done()` renders every non-SecurityException as
   `"Unexpected error: " + cause.getMessage()` (`BackgroundTask.java:50-55`) and nothing in
   ScanPanel translates it. Run `10.0.0.0/24 -sV` on a slow network: after the full wait budget the
   subject gets `Unexpected error: null` with no hint it timed out — and the scan keeps running
   unreferenced in the background (no cancel path exists). **Fixed 2026-09-11 (waves 1 + 4): the timeout now shows a clear message AND cancels the scan through `ScanHandle` (row P6); a Stop button cancels on demand.**

### ai-assistant

7. **`ProvidersPanel.reloadIssues` is raced by overlapping reloads** — `ProvidersPanel.java:282` *(confirmed)*
   `Session.loginUsernamePassword` fires `authenticated` synchronously from inside LoginPanel's
   BackgroundTask callable (`Session.java:162`), so AppShell's listener calls `reloadProviders()` —
   and `reloadIssues.clear()` — on the login worker thread, not the EDT. If a provider is blocked
   in `getModelCatalog().refresh()` (HTTP timeout) from the startup reload, a login starts a second
   pass: the `clear()` wipes issues the first pass collected (the "credential no longer available"
   warning is lost), the first `done()` can show the second pass's issues, and two threads
   appending to a plain ArrayList can throw `ArrayIndexOutOfBoundsException` out of the Callable —
   BackgroundTask then skips `onDone`, so `ctx.clearProviders()`/registration never runs and the
   subject signs in with **zero providers**.

8. **Editor commits its baseline before the save target accepts** — `MDFileViewer.java:518` *(confirmed)*
   `onSave` runs validator → `commit()` (sets dirty=false, line 540) → `onCommit`. On the
   "Save as: probe" branch, `ScanPanel.fillProbe` can show "Not a valid probe" and return with
   nothing persisted, but the editor already reads clean. The skill branch compensates with
   `skillEditor.markDirty()` on failure (`SkillsPanel.java:153-156`); the probe branch has no
   equivalent, so the next "Save as skill" from a chat bubble sees `isDirty()` false
   (`SkillsPanel.java:183`), skips the "Discard the unsaved skill edits?" prompt, and silently
   overwrites the rejected-but-unsaved probe draft. Related: selecting "probe" while editing an
   existing *skill* routes the skill's edits to the probe handler and discards the skill changes
   with no message.

9. **Every chat send persists the whole chat twice on unordered workers** — `ChatPanel.java:504` *(confirmed)*
   The new pre-dispatch save at line 399 makes the pre-existing unconditional save at line 504
   strictly redundant (same object, no intervening mutation — the response is persisted separately
   in `AssistantCallback.java:46`). The entire AIMessage/AIRequest/AIResponse graph (53 KB+ with a
   scan report attached) is written twice per turn on two independent SwingWorkers with no ordering;
   for a chat whose GUID is still empty, both can take `AssistantContext.saveChat`'s insert branch —
   a **duplicated chat row**, not just doubled I/O. Fix: delete the line-504 save.

10. **Skill validator blocks "Save as: probe" with a misleading error** — `SkillsPanel.java:116` *(plausible)*
    `MDFileViewer.onSave` runs `validateSkill` (line 517) before the save-target dispatch, and it
    rejects a blank Name with "Give the skill a name before saving." / title "Skill" regardless of
    the selected target. A valid probe JSON saved via "Save as: probe" with Name empty is refused
    with a skill-worded error — even though `fillProbe` passes the typed name to
    `ProbeDefinitionLoader.parse` only as an error-message label and always stores the name from
    the parsed JSON, so the forced input is used for nothing.

## Also known at handoff (pre-existing, tracked elsewhere)

- ~~v1 packages in `no-sneak-core` are frozen~~ **Merged 2026-09-12; the old packages are gone.** (was: never fix v1 bugs; anything v1 has that v2 lacks
  is a regression. See `no-sneak-core/CLAUDE.md` for the routing.
- **Vulnerability scanning (A11)** is still the largest v2 gap — checklist in
  `ACTION-PLAN.md` → *Pending Issues / Next Steps* item 1.
- ~~Named-group enumeration (A12)~~ **Done** — `enumerate-groups` ships (`supported-groups`, `server-group-preference`).
- **Stale Mongo default (C1)** — `tools/DMTool:38` keeps `mongodb://localhost:27017/…` as
  `DB_URL`; overridable, stale default rather than a bug.
- **Linux IPv6/NDP** in `no-sneak-net` compiles and has tests but has never been verified on real
  hardware — distrust it until it moves packets (§13.21).
## Status check (2026-09-09, commit `c082f11`)

A read of the tree against this file and the per-module lists, with the code grepped and the build
run rather than taken from the docs. Nothing below changes the ordering above; it records what has
and has not moved since 2026-08-13.

### Build and test state on the Windows dev box

| Check | Result |
|---|---|
| `mvn -o compile`, all five modules | passes |
| `no-sneak-net` tests (`-DskipTests=false`) | **260 run, 0 failures** on 2026-09-09. On 2026-09-11 Maven could no longer run them either (`surefire-junit-platform:3.5.6` is not cached); the suite — now 38 classes / ~359 tests after §13.22–§13.23 — was run class-by-class through IntelliJ, all green. |
| `no-sneak-core` v2, `ai-model`, `ai-assistant`, `no-sneak-app` tests | **could not run** — surefire's `surefire-junit-platform:3.2.5` provider is not in the local repository and the local TLS-intercepting proxy blocks the download (`PKIX path building failed`). Environment, not code; `no-sneak-net` runs because its pom pins a surefire configuration that is already cached. |
| CI | **none.** `.github/workflows/no-sneak-net-gates.yml` was deleted in `b21d050` (2026-08-18) and no workflow replaced it. Tests are skipped by the parent pom, so a green build proves compilation only. |

### The ten code-review findings above — all still open at `c082f11`; **all ten fixed 2026-09-11 (wave 1 ζ)**, see the matrix below

Verified in the code, not the doc, at `c082f11`:

- **1, 2** — `ScanPanel.onAuthChange` (line 98) still only calls `reloadScanResults()` /
  `reloadProbes()`; no `resetPanel()`. `saveScanResult(r)` is still on the EDT at line 186.
- **3** — `ProbeDefinitionLoader.validate` (v2, lines 137–143) still rejects only null/empty
  names; whitespace and commas in a probe name still reach `NMap.parseCommand`.
- **4, 5, 6** — `tickedProbes` is still a bare `Set<String>` (line 77), `effectiveCommand` still
  splices names (line 221), and `TimeoutException` is still imported but never translated.
- **7** — `ProvidersPanel.reloadIssues.clear()` at line 282, still unguarded against an overlapping
  reload.
- **8, 10** — `MDFileViewer.onSave` still runs `commit()` (line 518) before the save target accepts.
- **9** — `ChatPanel` still saves the chat at both line 399 and line 504.

### What the five commits since 2026-08-13 did touch

`5203f0d`, `bfa9bd1` (UDP callback one-liners), `b21d050` (docs + CI deletion), `c082f11`:
empty `sslUpgraded(SSLConfigInt)` overrides added to **twelve** callbacks in v1 and v2 to compile
against an upstream `TCPSessionCallback` change, and `v2/service/Checker` rewritten to reuse the
incoming `ProtoSession` (a `SimpleProtoSession` for anonymous requests) instead of its own
`ScanSession` keep-alive class.

**New item from that commit worth a look:** the twelve `sslUpgraded` overrides are all empty. If
the house library now signals a TLS upgrade through that hook, the `starttls` / `tls-connect`
paths in `v2/runtime/ProbeTCPCallback` and `ProbeSecureCallback` may need to react rather than
ignore it. Unverified either way — check the upstream `TCPSessionCallback` contract before
assuming the no-op is correct.

### Size of the v1 → v2 cut-over

| Slice of `no-sneak-core` | Files | LOC |
|---|---|---|
| `v2` | 61 | 7.6k |
| v1 (`nmap`, `probe`, `scanners`, `services`, `tools`) | 95 | 16.0k |

~~Four of the fourteen core test files (`scanners/`, `probe/`) target v1 and go with it at merge.~~ Gone with the 2026-09-12 merge; the table above is the pre-merge size.

### Suggested order

1. Findings **1 and 2** (ScanPanel logout reset + save off the EDT) — the data-boundary defects.
2. Findings **3–6** together; all sit in ScanPanel's probe-selection path, and the fix at depth is
   to apply ticks to the parsed `NMapConfig` rather than splicing the command string.
3. Findings **7–10** in the assistant, starting with deleting the line-504 save.
4. ~~`no-sneak-net` §13.21 shared items **S1–S3** (runnable on this box)~~ — **done 2026-09-11**,
   along with every other code item in §13.21 (`no-sneak-net/CLAUDE.md` §13.22–§13.23). See the
   priority matrix below for what is next.
5. Restore a CI workflow that runs the suites somewhere without the proxy.

## Status check (2026-09-12, commits `d1be5f7` Phase 1 update + `20a54f2` Phase 2 update, pushed)

**Start here if you are picking the project up.** Everything from the 2026-09-11 review and the four
fix waves that followed is committed and pushed on top of `9fb8bde`; the tree is clean. Build:
whole project green through IntelliJ (`mcp__idea__build_project`; Maven still cannot fetch the
surefire JUnit provider on this box, so tests run class-by-class through the IDE). Test suite at
these commits: `no-sneak-net` 39 classes / ~372 tests, `no-sneak-core` 29 / ~309 (v2 alone 25 / ~272),
`no-sneak-app` 13 / ~92, `ai-assistant` 9 / ~61 — the 18 classes touched by the waves were re-run
after the merge, 213 tests, 0 failures. Live checks the same day: `xlogistx.io -p 22,443 -sV`
(SSH version, grade A with the CBC advisory), `hostscan sweep 10.0.0.0/24` (254 probed, 26 alive).

**Open, in full (7 rows; the matrix below has the detail):**
- Yours: a CI runner that can reach Maven Central (row 2 of the matrix page).
- Hardware: M1 and M9 need a Mac, L1 needs the Linux appliance on a v6 segment.
- On this box: N3 (IPv6 unicast re-solicit — small code, proof needs L1's wire) and C1 (`DMTool`
  Mongo URL default — one line, needs the right value).
- Pinned by the maintainer, not scheduled: P17, the SSL-Labs posture checklist.

**Conventions set during that work, binding for anything new** (also in the module docs):
no thread ever blocks a pool thread; executors are injected parameters obtained from `TaskUtil`
only at the composition root; `NIOSocket` for every Java socket; every rate cap is zoxweb
`RateController` TIME mode on the injected scheduler (`no-sneak-net` `SweepDriver`, `no-sneak-core`
`ScanGate` — formerly `RateLimiter`); JSON is `NVGenericMap` + `GSONUtil` with `printNull=true`,
never a hand-written writer; the BCJSSE `tls-connect` engine comes from SunJSSE because the
published `bctls` 1.86 jar is broken on JDK 9+ — `BcjsseEngineCreationTest`'s canary fails the day
a fixed jar is on the classpath, which is the signal to remove that workaround.

**Merge done (2026-09-12, later the same day):** the original packages, their five test files
and `src/main/resources/probes/` (old set) plus the orphan `services-categories-info.json` are
deleted; the rebuild's package collapsed to `io.xlogistx.nosneak`; bundled probes are at
`/probes/`; `PLAN.md`/`PROBE-CONFIG.md` moved to the module root (the old authoring tutorial is
`PROBE-DEFINITION.md`); the app, the server test config and the docs are retargeted. Whole repo
compiles; 365 tests green under the new package; CLIs verified live.

**Merge analysis and parity pass (2026-09-12):** `no-sneak-core/V1-V2-MERGE-ANALYSIS.md` is the
code-verified v1-vs-v2 comparison. Verdict: keep v2, delete v1. The 18 regressions its §4 listed
(stapled-OCSP fallthrough, the TLS-1.3-classical vs ≤1.2 PQC split, enumeration toggles, down
hosts in Normal/CSV, CLI aliases, per-octet ranges, XML metadata, reverse DNS, …) were **all
closed the same day** — see its "Status after the fix pass" section. v2 is now 365 pure tests in
31 classes, all green; the whole repo compiles. **What is left is the merge itself**: delete the
five v1 packages and their five test files, collapse `v2` → `io.xlogistx.nosneak`, move
`/probes/` → `/probes/`, and retarget the files in that document's §2.

The filterable matrix page (same rows, live-updated during the work):
https://claude.ai/code/artifact/ad7da1cc-7807-4109-ad77-cb166e70596e

## Priority matrix (2026-09-11) — discovery closed out; port detection and protocol identification next

*Supersedes the "Suggested order" above for everything that touches scanning.* Host discovery
(`no-sneak-net`) was reviewed on 2026-09-11, and every code item that review and the earlier
§13.21 list raised has been fixed, unit-tested and live-checked on the Windows box in three work
packages (`no-sneak-net/CLAUDE.md` §13.22 and §13.23-A/B/C). What remains there is hardware-gated
or by design (rows N1–N5). The rest of this matrix is the scan pipeline in `no-sneak-core` v2:
stage 1 (live ports, `NMapScanner.portScanStage` → `PortScanCallback` on `NIOSocket`) and stage 2
(protocol identification, `probeStage` → `ProbeChecker` → JSON probe FSMs). Rows come from a
read-only exploration of that code on the same date; none of the P-rows has been fixed.

**Rules every slice inherits** (set by the maintainer): no thread ever blocks a pool thread
(no semaphore / sleep / join / blocking `get()` on injected executors); `ScheduledExecutorService`
and `ExecutorService` are constructor or method parameters, obtained from `TaskUtil` only at the
composition root; `NIOSocket` is the transport for every Java socket and is passed in, never
looked up; assessment only — detection from advertised versions, extensions and ordinary
handshake behaviour, never exploitation (repo root `CLAUDE.md`, *Operating scope*).

Columns: **sev** C = correctness, W = wire discipline, D = diagnosability, H = hygiene/coverage,
P = parity (v1 had it, so it is a regression at merge). **effort** S < 1 day, M 1–3 days, L > 3.
**here** = unit-testable on the Windows dev box with no live target.

### `no-sneak-net` — what is still open after packages A–C

| id | defect | sev | effort | needs | here | files |
|---|---|---|---|---|---|---|
| ~~N1~~ | **FIXED 2026-09-11 (wave 1).** A probe registered but never sent (the sender threw before arming its deadline) left the call incomplete; `PendingCall.failRemaining` closes every open slot and each `ping()` calls it from its abort path. Pinned by `PendingCallTest.aCallWhoseProbeWasNeverSentStillCompletes`. §13.23-E. | — | — | — | — | `util/PendingCall`, three `ping()` methods |
| ~~N2~~ | **FIXED 2026-09-11 (wave 1).** `hostscan observe [seconds] [--cache]` reports events and cached neighbours separately and prints `cache().snapshot()` per interface. First wire evidence of the IPv6 learner: a neighbour's `fe80::` learned from frame headers alone. §13.23-E. | — | — | — | — | `tools/HostScan`, `tools/HostScanFormat` |
| N3 | IPv6 unicast-NS re-solicit (the v6 twin of §13.13's unicast ARP) deliberately not built; a passive v6 sighting while a v6 resolve is pending gets no re-solicit. Needs a `dst16` overload of `Icmp6.neighborSolicitation` and a wire (L1). | P | M | L1 owner | codec test only | `codecs/Icmp6`, three backends' `learnSender` |
| N4 | Hardware-gated measurements: M1 (Mac `observe 60` before/after `ip6` in the filter), M9 (v6 neighbour + arena-shutdown race on a Mac), L1 (Linux NDP never on a wire). | D | S each | a Mac / the appliance / a v6 segment | N | — |
| ~~N5~~ | **FIXED 2026-09-11 (§13.23-D).** S6: futures completed inline on reader threads, so a blocking user continuation could stall that NIC's capture (or ICMP JVM-wide). Completions now hop to the injected dispatcher; the reader never runs a continuation; RTTs are unchanged because they are computed before the hop. Pinned by `CompletionThreadTest`. | — | — | — | — | `util/PendingResolve`, `util/PendingCall` |

### `no-sneak-core` stage 1 — live ports

| id | defect | sev | effort | depends on | here | files |
|---|---|---|---|---|---|---|
| ~~P1~~ | **FIXED 2026-09-11 (wave 1).** `PortScanCallback.exception` uses the v1 table: refused → CLOSED `conn-refused`, reset → CLOSED `reset`, unreachable/no-route → FILTERED `no-route`, deadline → FILTERED `timeout`, **anything else → FILTERED `error:<Class>`**. The callback reports `Result(state, reason, rttMs, banner)`; the scanner no longer guesses. `PortScanCallbackTest` (17). | — | — | — | — | `v2/nmap/PortScanCallback.java` |
| ~~P2~~ | **FIXED 2026-09-11 (wave 1).** RTT measured to `connectedFinished`; the socket stays open for min(1 s, timeout) on the injected scheduler and the first volunteered bytes (≤ 1024, ISO-8859-1) become `PortReport.banner`. TTL stays −1: a connect scan cannot see it. Live: xlogistx.io:443 rtt 1 ms, google.com:443 rtt 25 ms, no banner on TLS ports as expected. **Not yet rendered**: see P20. | — | — | — | — | `PortScanCallback.java`, `NMapScanner.scanHostPorts` |
| ~~P3~~ | **FIXED 2026-09-11 (wave 1).** `NMapConfig` defaults are 256 in flight / 2000 per second (matching `SweepOptions.defaults()`); explicit 0 still means unlimited. `NMapParseCommandTest.defaultsAreBoundedNotUnlimited`. | — | — | — | — | `v2/nmap/NMapConfig.java` |
| ~~P5~~ | **FIXED 2026-09-11 (wave 1).** `PortScanCallbackTest` (17 cases) and `UnitTest` (exactly-once, limiter released once). | — | — | — | — | tests |
| ~~P6~~ | **FIXED 2026-09-11 (wave 4).** `NMapScanner.scan(...)` returns a `ScanHandle` with `cancel()`/`isCancelled()`/`completion()`. Cancel flips a flag checked at every stage boundary and before every launch, aborts each in-flight `PortScanCallback`/`UdpScanCallback` (`abort()` -> `FILTERED/cancelled`), tears down each `ProbeChecker` sweep (delivers a `cancelled` result so barriers drain), and closes the `HostScanner` session; the report is delivered once with `ScanReport.cancelled` and a progress warning. `NMap.main` cancels on Ctrl-C (shutdown hook) and on the wait-budget timeout; `ScanPanel` has a Stop button (`IconUtil.StopIcon`) and its timeout path now cancels. Idempotent, nothing blocks. `ScanCancelTest` (8). Live: cancel 500 ms into a `-Pn` scan -> 7 ports completed, 1 `filtered/cancelled`, exit 0.55 s; full run unaffected. | -- | -- | -- | -- | `NMapScanner`, `NMap`, `PortScanCallback`, `UdpScanCallback`, `ProbeChecker`, `ScanPanel` |
| ~~P7~~ | **FIXED 2026-09-11 (wave 3 δ).** `-sU` UDP scan (`nmap/UdpScanCallback`, `UdpProbePayloads`): connected ephemeral datagram socket per host:port, one datagram + one retransmit at half budget; reply → `open/udp-response` (+RTT); ICMP port-unreachable → `closed/port-unreach`; other unreachable → `filtered/no-route`; silence → `open|filtered/no-response`. DNS and NTP payloads, empty datagram elsewhere, **no SNMP** (a community string is a credential guess). Probe stage runs `dns.json` on UDP ports that answered. Paced by the same limiter. Live: `xlogistx.io -sU -p U:53 -sV` → `53/udp open udp-response 6 ms dns`. `UdpScanCallbackTest` (10), `UdpProbePayloadsTest` (3). | — | — | — | — | `v2/nmap/UdpScanCallback`, `UdpProbePayloads`, `NMapScanner`, `NMap`, `NMapConfig` |
| ~~P9~~ | **FIXED 2026-09-11 (wave 1).** `--top-ports N`, `T:`/`U:` prefixes, `--open` (config flag, see P21), `-T0..-T5` mapped onto in-flight/rate/timeout; `-sS -sF -sX -sN -sA -sW -sM -O --stealth` rejected with a message naming the flag and the assessment-only rule. Live: `xlogistx.io --top-ports 10` (5 open), `google.com -p T:80,443 -T3`, `xlogistx.io -sS` → exit 2 with the message. `-O` is rejected rather than mapped to a heuristic. | — | — | — | — | `NMap.java`, `NMapConfig.java` |
| ~~P19~~ | **FIXED 2026-09-11 (wave 1).** OPEN reason is `connected` (was the false `syn-ack`); `PROBE-CONFIG.md` test count corrected (145 in 11 classes); `PLAN.md` no longer names `PortScanner`. | — | — | — | — | docs, `NMapScanner.scanHostPorts` |

### `no-sneak-core` stage 2 — protocol identification

| id | defect | sev | effort | depends on | here | files |
|---|---|---|---|---|---|---|
| ~~P4~~ | **FIXED 2026-09-11 (wave 3 δ).** The probe stage is paced by the scan's `ScanGate` (formerly `RateLimiter`; same class, renamed when its token-bucket pacer was replaced by zoxweb `RateController` so both modules pace with one leaky-bucket rule) through `ProbeChecker(nio, probes, ConnectionGate)` + `GatedProbeTransport.Registry`: a candidate holds one slot from admitted `start()` to delivery/cancel (unadmitted candidates are not started, so no timer runs while they wait); a deep probe's enumeration children are counted but never blocked, so a probe never waits on itself; cancelled losers hand slots back. `ProbePacingTest`, `GatedProbeTransportTest`. Live: `google.com -p 80,443 -sV --max-inflight 2` completes with full detail in 19 s vs ~6 s uncapped. | — | — | — | — | `v2/runtime/GatedProbeTransport`, `ProbeChecker`, `RateLimiter`, `NMapScanner.probeStage` |
| ~~P8~~ | **FIXED 2026-09-11 (wave 3 δ).** The probe stage runs UDP probes (`dns.json`) on UDP ports that answered the UDP scan, via `ProbeChecker.check(host, port, "udp", cb)`. Live: `xlogistx.io -sU -p U:53 -sV` → `53/udp open dns`. | — | — | — | — | `NMapScanner.probeStage` |
| ~~P10~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeContext` runs the user callback after releasing its monitor (`guarded` depth counter; `deliver` parks the result), so `FirstSweep.onResolve` and the losers' `cancel()` never run under a context monitor. `ProbeContextTest.theUserCallbackRunsOutsideTheContextMonitor` and two siblings. | — | — | — | — | `v2/runtime/ProbeContext.java` |
| ~~P11~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeTransport` seam (`NioProbeTransport` in production) + injected scheduler/executor; `ScriptedTransport` and `ManualScheduler` drive the FSM with no socket or timer. `ProbeContextTest` (18): banner match/capture, split reads, nomatch, error, both wait timeouts, watchdog, unmapped outcome, failed write, reconnect, STARTTLS → handshake start, cancel, exactly-once, stale `armGen` timer. Still live-only: the BC handshake, enumeration children, JSSE `tls-connect`. | — | — | — | — | `v2/runtime/*` |
| ~~P12~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeCheckerTest` (14): two-tier ordering, portScoped exclusion, election waits for higher priority, immediate win + cancel, none-identified fallback, `checkAll` order. `SendBytesTest` (7) pins the codecs and text-only templating; `MongoPayloadTest` (3) verifies both hex payloads against OP_QUERY/OP_MSG. Live: xlogistx.io 22 (OpenSSH 8.2p1), 25 (JAMES, STARTTLS → PQC X25519MLKEM768), 443 (PQC, TRUSTED, TLS 1.3 only, grade A); google.com 443 (PQC, TLS 1.0–1.3, grade C). | — | — | — | — | tests |
| ~~P13~~ | **FIXED 2026-09-11 (wave 3 ε).** `enumerate-groups` action: one single-group TLS 1.3 handshake per candidate (3 ML-KEM hybrids, 5 curves, 2 FFDHE) → `supported-groups` + `server-group-preference`; in `https-scan`/`tls-scan`; report-only advisory when no hybrid is accepted. Live: xlogistx.io accepts 8 groups, google.com 3, both prefer X25519MLKEM768. `GroupProbeCallbackTest`, `GradeTest`. | — | — | — | — | `analysis/GroupProbeCallback`, `ProbeContext.enumerateGroups` |
| ~~P14~~ | **FIXED 2026-09-11 (wave 3 ε).** `NetworkRevocationChecker`: OCSP POST to the AIA responder, then CRL from the CDP, non-blocking on the injected `HTTPNIOSocket`, bounded by `revocationTimeoutMs` (default 5 s), exactly-once, soft-fail `UNKNOWN/<method>-unreachable`; `revocation-date`/`-reason` kept; CRL signature and freshness verified. Live: both hosts GOOD via crl (neither CA publishes an OCSP responder any more; the OCSP branch is covered by the BC fixture). `RevocationCheckerTest` (9). | — | — | — | — | `analysis/*RevocationChecker`, `ProbeContext.checkRevocation` |
| ~~P15~~ | **FIXED 2026-09-11 (wave 3 ε).** `enumerate-ciphers` offers opsec's strong + weak + insecure TLS 1.2 sets (39) and all 5 TLS 1.3 suites; each accepted suite recorded with version/strength/key-exchange/forward-secrecy; `server-cipher-preference` from two ordered offers; RC4/NULL/EXPORT/DES/anon cap the letter at C. Enumeration budget: at most 64 child connections per deep probe. Live: google.com shows TLS_RSA_* and 3DES. See P24 for the grading side effect. | — | — | — | — | `ProbeContext.enumerateCiphers`, `Grade`, `ProbeResult` |
| ~~P16~~ | **FIXED 2026-09-11 (wave 1).** `Checker.TargetGuard`: resolves once on the pool, rejects loopback, link-local, site-local/ULA, unspecified, multicast and anything resolving to them; REST path answers 401/400 via `Responder`. `CheckerPrivateIpTest` (6). | — | — | — | — | `v2/service/Checker.java` |
| P17 📌 | **PINNED 2026-09-11 by the maintainer — recorded, deliberately not scheduled.** ACTION-PLAN item 1, the SSL-Labs-parity posture checklist (padding-oracle family, named-CVE evidence from version/extension presence only, renegotiation, downgrade/SCSV, compression, ALPN, resumption, 0-RTT, DH hygiene, intolerance, HSTS/pinning). Detection-only by design; anything not decidable without an exploit attempt stays unimplemented. | P | L (many S/M) | P11, P13 | mostly live | new actions + probe JSON |
| ~~P18~~ | **FIXED 2026-09-11 (wave 1).** Ticks are applied to the parsed `NMapConfig` (`ScanPanel.ProbeSelection`), keyed by stored-record GUID, never spliced into the command; re-save updates the existing row. **Remaining, nmap side (P22):** a stored probe named exactly like a bundled one still runs both. | — | — | — | — | `ScanPanel.java` |
| ~~P23~~ | **FIXED 2026-09-11 (wave 4 λ).** Not a classpath mismatch — every BC artifact is 1.86 — but a defect inside `bctls-jdk18on` 1.86 as published: its multi-release `versions/9/SSLEngineUtil` returns `ProvSSLEngine` while the un-versioned `ProvSSLContextSpi` calls the `SSLEngine` descriptor, so `createSSLEngine` throws on JDK ≥ 9 whenever BCJSSE (registered at position 2 by `SecUtil`) resolves `"TLS"`. `ProbeSecureCallback` now mints the `tls-connect` engine from `SunJSSE` explicitly; PQC stays on the BC TLS-API path. Also fixed: `sslUpgraded` was empty while zoxweb 2.4.0 signals handshake completion only there, so `https-version` could never complete. Live: `Server: gws` on google.com, `NOYFB` on xlogistx.io. `BcjsseEngineCreationTest` (3) includes a canary that fails once a consistent bctls is on the classpath — then remove the explicit provider. | — | — | — | — | `v2/runtime/ProbeSecureCallback.java` |
| ~~P24~~ | **FIXED 2026-09-11 (wave 4 μ).** `Grade.CipherPosture` applies SSL Labs' tiers: insecure (RC4/NULL/EXPORT/DES/anon) → C; no forward secrecy (static RSA/ECDH) or 3DES → B; forward-secret CBC → advisory "CBC suites accepted: …; prefer AEAD", letter unchanged. Forward secrecy from `supported-cipher-suite-details`, name-inferred otherwise. `Grade.toString()` prints advisories. Live: xlogistx.io back to A with the CBC advisory; google.com stays C. `GradeTest` (37). | — | — | — | — | `grade/Grade.java` |
| ~~P20~~ | **FIXED 2026-09-11 (wave 2 ο).** Every formatter renders per-port `reason` and, when measured, the RTT (Normal columns, JSON `reason`/`rttMs`, XML `rttms` on `<port>` + `<extraports>`, CSV trailing `reason,rttms`, gnmap owner/rpc slots). Live on xlogistx.io in all five formats. `FormattersTest` (11). | — | — | — | — | `v2/nmap/output/*` |
| ~~P21~~ | **FIXED 2026-09-11 (wave 2 ο).** One shared rule, `HostReport.portsToRender(cfg)`: `--open` lists only potentially-open ports and keeps the hidden counts; without it a non-open state is listed up to 10 entries and collapsed beyond, as nmap does. | — | — | — | — | `ScanReport.RenderSelection`, all formatters |
| ~~P22~~ | **FIXED 2026-09-11 (waves 2 ο + 3 δ).** `U:` ports are scanned by the UDP stage with or without `-sU`; `buildChecker` keeps one definition per name (stored shadows bundled with a warning). | — | — | — | — | `NMap`, `NMapScanner` |

### Divide-and-conquer slices — no two slices edit the same file

| slice | rows | files owned | order note |
|---|---|---|---|
| α port callback | P1, P2, P5 | `PortScanCallback.java`, `PortScanCallbackTest`, `UnitTest` | first; α's `scanHostPorts` edit is the one touch on `NMapScanner` — δ waits for it |
| β config / CLI | P3, P9, P19 | `NMapConfig.java`, `NMap.java`, `WellKnownPorts.java`, docs | parallel with α |
| γ probe orchestration | P10, P11, P12, P4 | `ProbeContext.java`, `ProbeChecker.java`, their tests | P11's seam first, then P10, P12, then P4 (also touches `NMapScanner.probeStage` — after α) |
| δ UDP | P7, P8 | new `UdpScanCallback`, `NMapScanner` stage insertion, `NMap` flag | after α and β land |
| ε posture | P13, P14, P15, P17 | `ProbeContext` TLS methods, `analysis/`, probe JSON | after γ's P11 seam; each item is its own PR |
| ζ app + REST | P16, P18 | `Checker.java`, `ScanPanel.java` | parallel with everything |
| η discovery leftovers | N1, N2, N3 | `util/PendingCall`, `tools/HostScan`, `codecs/Icmp6` | parallel with everything; N4 waits for hardware |
| — cancel | P6 | `NMapScanner`, `NMap`, `ScanPanel` | last: cuts across α, δ and ζ |

Recommended first wave: **α + β + ζ + η in parallel** (all small, all unit-testable here), then
γ, then δ and ε, then P6.
