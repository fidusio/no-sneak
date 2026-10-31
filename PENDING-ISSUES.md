# Pending issues

*The open-work index for the repo. The first section is the whole open list as of 2026-10-27;
everything under* History *is the dated record of how it got here and is not an open list. Per-area
detail lives in the module `CLAUDE.md` files, named below.*

> **Operating scope first:** the repo root `CLAUDE.md` → *Operating scope* states what this tooling
> does and does not do (assessment and detection only — no exploitation, credential attacks, DoS,
> or evasion). Nothing on this list may cross that line.

## Open now (2026-10-27)

**Maintainer's own items**
1. **Live checks owed**, in the order the features landed:
   - first sign-in downloads the Wireshark vendor list and a LAN scan names vendors; the next
     sign-in does not download; *Account → Settings → Sync MAC vendors* replaces the list;
   - a scan with no probe chips sends no probe traffic; ticking *Service detection* fills the strip;
   - Probe library: *Write with the assistant* on an open chat, then *Save as probe* on the reply;
     *Copy to my probes* of `ssh`, Save, and a scan reports the shadow warning;
   - `postgres-tls` against a real PostgreSQL with `ssl = on` (the version needs `trust` auth for
     the probe's user; otherwise `postgresql-tls-auth-required`, still a completed identification);
   - (2026-10-27, hardening) *Copy* of an API-key secret: the clipboard is blank a minute later
     unless something else was copied since; a deleted chat leaves no message rows behind on the
     installation (`StoreHardeningTest` proves it on a fresh store);
   - (2026-10-27, provider switch) a chat with two linked providers: pick the other one in the
     conversation's *Provider* combo, Send, and the reply's line reads that provider · model
     while the earlier replies keep theirs; with *Send history* ticked the new provider answers
     in context, unticked it sees the new message only;
   - (2026-10-27, send again) the copy icon at the bottom-right of a past prompt puts its text
     in the composer (appended after what is already typed) and Send sends it as a new turn;
     the X at the right end of the input box empties the typed text, leaves the chips, and
     disappears when the prompt is empty;
   - (2026-10-28, model combo) type in the Model box: `mini` narrows the drop-down as you type,
     `gpt*` and `!mini` follow the grammar, `*` shows the embedding and audio models too;
     arrows + Enter and a mouse click pick, Escape puts the chosen model's name back, and
     switching provider with text typed shows the other provider's full list;
   - (2026-10-30, probe actions) select one of your probes in the Probe library: *Edit* and
     *Delete* sit right of the name at the top of the detail pane; a bundled probe shows *Copy
     to my probes* in the same place;
   - (2026-10-29, hide window) on the Capture page untick *Hide window* and press Capture (N):
     the application stays on screen and an area drawn over it shoots the application; ticked
     again, the window disappears for the sweep as before; the chat's send-time sweep follows
     the same box; with it unticked *Define area* draws over the application too (the overlay
     sits on top of it).
2. **Run-through on a display** of the pages not yet tried since the redesign: a stored report
   opened from history, API keys, Providers, a chat with chips, a capture, Profile, Settings
   (Backup and Restore), Access control. Since 2026-10-27 that includes what was re-laid out or
   added that day and only checked by headless renders: the merged Chat page, the Profile and
   API Keys forms, the Settings blocks, the About card and Help text, the status bar's vendor
   line after a real *Sync*, and the **tooltips** (sidebar items, View menu, T0 to T5, the
   All / Bundled / Mine and result tabs, Access Control tabs), which a static render cannot show.
3. **Decisions parked with the maintainer:** run tier 2 only after tier 1 fails (the match-first
   sweep's ~18 simultaneous connections lose the `ssh` verdict on hosts with OpenSSH
   `MaxStartups 10:30:100`; measured 2 of 13 SSH hosts on the `/24`); the sibling TCP-ping aborts
   in `NMapScanner.discoverHost` that print a harmless `ClosedChannelException`; P17, the SSL Labs
   vulnerability checklist (pinned, not scheduled); a CI runner that can reach Maven Central.
4. **Needs a Mac:** `no-sneak-net` M1 (the `observe 60` measurement after the BPF filter fix) and
   M9 (an IPv6 neighbour answering multicast; the arena-shutdown race under sustained capture).

**no-sneak-app**
- Access control page: every table is an empty stub and search is not wired; the
  `DomainSecurityManager` catalog is there to bind to (`SubjectSecManagerPanel`).
- The assistant's job-queue page is a stub and is not offered in the sidebar.
- Register needs a confirmation dialog; the Technical / Simple tier toggle is not wired; an
  identifier has no status (primary / alias / verified; blocked on `PrincipalIdentifier` holding
  only the id string); the required marks (`FormPanel.requiredField`) are on the password and
  API-key forms only, the Profile name form marks nothing and the address form says in a note
  that a label or a street is enough.
- A scan report goes to the assistant as its full JSON (a `/24` is ~53 KB, ~15k tokens); the
  compact `NORMAL` render would need to be stored at scan time. Decide before stores fill up.
- `char[]` passwords are never zeroed after use (`UnlockPanel`, `SubjectPanel`); a partial fix
  only, since `Session` turns them into Strings for the manager.
- Installations written before 2026-10-21 (vault without super-admin, no `shiro.ini`, old table
  names) are refused by `open`: start fresh or write a migration.
- PostgreSQL is the next datastore target (Mongo deprecated 2026-10-25; the Mongo branch of
  `NoSneakUtil` is not to be extended).

**ai-assistant** — the full list is `ai-assistant/CLAUDE.md` → *Known rough edges*; the ones that
lose data or hang: no send timeout or cancel (a provider that never calls back leaves Send disabled
for the life of the app; the fix belongs in `ai-model`); a failed send loses the attached images;
`CapturePanel.full()` can write an image-less row over a stored capture when the store misses;
`maxTokens` never reaches the wire (commented out upstream in `xlog-api-ai`); auto-named capture
areas can collide; the compare (multi-model) path and chat-scoped skills are unbuilt.

**no-sneak-core**
- The vulnerability-scanning backlog (`no-sneak-core/CLAUDE.md` → *Vulnerability-scanning
  backlog*): nothing implemented; P17 above.
- HTTP security-header analysis and CNSA 2.0 compliance rules.
- `service/Checker`'s private-IP guard is a literal-prefix match that lets loopback, link-local
  and inward-resolving names through — fix before exposing the REST endpoint.
- An `-O`-style open-port heuristic would need its own flag (`-O` is rejected as nmap's
  fingerprint flag); a native raw-socket layer for accurate port state; end-to-end runtime
  testing of the DM tools.

**no-sneak-net**
- N3: IPv6 unicast-NS re-solicit (the v6 twin of the unicast ARP), small; needs a `dst16`
  overload of `Icmp6.neighborSolicitation`. The Linux v6 wire exists since 2026-09-13.
- M1 and M9 above (Mac).

**Declined, do not reopen:** an antivirus / interception-proxy detection heuristic (Avast's mail
shield fakes open mail ports on every host; scan with it off).

## Where per-area detail lives

| Area | Authoritative detail |
|---|---|
| Scanning engine, deferrals and the vulnerability backlog | `no-sneak-core/CLAUDE.md` → *Engine reference*, *Vulnerability-scanning backlog*, *Next up* |
| Probe format | `no-sneak-core/PROBE-DEFINITION.md` (the one probe-format document; the app shows it and hands it to the assistant) |
| Host discovery | `no-sneak-net/CLAUDE.md` §13.21 (open items per platform; every code item fixed, M1/M9 need a Mac, N3 open) |
| Desktop app | `no-sneak-app/CLAUDE.md` → *Needed fixes / updates*; `no-sneak-app/LOADING.md` for what loads when |
| Assistant | `ai-assistant/CLAUDE.md` → *Known rough edges*; `ai-model/CLAUDE.md` for the interface-shape gaps |

---

## History

*Dated status checks and the 2026-08-13 code review, kept because the Java sources and tests cite
their finding numbers (P6, P14, P23, findings 7 to 10). The checks are not in date order. Nothing
below is an open list; the open list is above.*

*The original handoff note (2026-08-13):* this file was the index of known open work at handoff
time; the "Code review findings" section records issues found in the uncommitted working tree on
that date (scan panel + AI assistant changes, post-`bf072b9`). All ten findings were fixed on
2026-09-11 (wave 1, group ζ). The store followed the datastore's deployment model on 2026-10-21
(`H2PSetup` on a first run, vault + `shiro.ini` + attached manager on every run, `app_user` granted
at sign-up); the 2026-10-05 and 2026-09-20 checks are the two sessions before it.

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

8. **Editor commits its baseline before the save target accepts** — `MDEditorPanel.java:518` (now `io.xlogistx.gui.MDEditorPanel` in io-xlogistx/gui-audio, 2026-10-22) *(confirmed)*
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
    `MDEditorPanel.onSave` runs `validateSkill` (line 517) before the save-target dispatch, and it
    rejects a blank Name with "Give the skill a name before saving." / title "Skill" regardless of
    the selected target. A valid probe JSON saved via "Save as: probe" with Name empty is refused
    with a skill-worded error — even though `fillProbe` passes the typed name to
    `ProbeDefinitionLoader.parse` only as an error-message label and always stores the name from
    the parsed JSON, so the forced input is used for nothing.

## Also known at handoff (pre-existing, tracked elsewhere)

- ~~v1 packages in `no-sneak-core` are frozen~~ **Merged 2026-09-12; the old packages are gone.** (was: never fix v1 bugs; anything v1 has that v2 lacks
  is a regression. See `no-sneak-core/CLAUDE.md` for the routing.
- **Vulnerability scanning (A11)** is still the largest v2 gap — checklist in
  `no-sneak-core/CLAUDE.md` → *Vulnerability-scanning backlog*.
- ~~Named-group enumeration (A12)~~ **Done** — `enumerate-groups` ships (`supported-groups`, `server-group-preference`).
- ~~Stale Mongo default (C1)~~ **FIXED 2026-09-12.** `DMTool` carries no datastore URL at all: it is
  resolved from `db-url=` → `NOSNEAK_DB_URL` → `-Dnosneak.db.url`, and with none set the tool prints
  usage and exits without touching a database (`tools/DMToolTest` pins the order and greps the source
  for any `mongodb://localhost` or `replicaSet=` creeping back).
- ~~**Linux IPv6/NDP** in `no-sneak-net` compiles and has tests but has never been verified on real
  hardware~~ **Verified 2026-09-13** on a segment with 18 v6 neighbours (`no-sneak-net/CLAUDE.md` §13.24).
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
- **8, 10** — `MDEditorPanel.onSave` still runs `commit()` (line 518) before the save target accepts.
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
- Hardware: M1 and M9 need a Mac. ~~L1 needs the Linux appliance on a v6 segment~~ closed 2026-09-13 (§13.24).
- N3 (IPv6 unicast re-solicit — small code; the Linux dev box now has the v6 wire to prove it on). ~~C1~~ closed
  2026-09-12 by removing the default rather than choosing a value.
- Pinned by the maintainer, not scheduled: P17, the SSL-Labs posture checklist.

**Conventions set during that work, binding for anything new** (also in the module docs):
no thread ever blocks a pool thread; executors are injected parameters obtained from `TaskUtil`
only at the composition root; `NIOSocket` for every Java socket; every rate cap is zoxweb
`RateController` TIME mode on the injected scheduler (`no-sneak-net` `SweepDriver`, `no-sneak-core`
`ScanGate` — formerly `RateLimiter`); JSON is `NVGenericMap` + `GSONUtil` with `printNull=true`,
never a hand-written writer. ~~The BCJSSE `tls-connect` engine comes from SunJSSE because the
published `bctls` 1.86 jar is broken on JDK 9+ — `BcjsseEngineCreationTest`'s canary fails the day
a fixed jar is on the classpath, which is the signal to remove that workaround.~~ **Removed
2026-09-20:** the canary fired on the local repository's `bctls` 1.85; the pin and the canary are
gone, `tls-connect` uses the JCA default (BCJSSE), `TlsConnectContextTest` pins engine creation.

**Merge done (2026-09-12, later the same day):** the original packages, their five test files
and `src/main/resources/probes/` (old set) plus the orphan `services-categories-info.json` are
deleted; the rebuild's package collapsed to `io.xlogistx.nosneak`; bundled probes are at
`/probes/`; `PLAN.md`/`PROBE-CONFIG.md` (both deleted 2026-10-26) moved to the module root (the old authoring tutorial is
`PROBE-DEFINITION.md`); the app, the server test config and the docs are retargeted. Whole repo
compiles; 365 tests green under the new package; CLIs verified live.

**Merge analysis and parity pass (2026-09-12):** `no-sneak-core/V1-V2-MERGE-ANALYSIS.md` (deleted
2026-10-26 as history) was the code-verified v1-vs-v2 comparison. Verdict: keep v2, delete v1. The 18 regressions its §4 listed
(stapled-OCSP fallthrough, the TLS-1.3-classical vs ≤1.2 PQC split, enumeration toggles, down
hosts in Normal/CSV, CLI aliases, per-octet ranges, XML metadata, reverse DNS, …) were **all
closed the same day** — see its "Status after the fix pass" section. v2 is now 365 pure tests in
31 classes, all green; the whole repo compiles. **What is left is the merge itself**: delete the
five v1 packages and their five test files, collapse `v2` → `io.xlogistx.nosneak`, move
`/probes/` → `/probes/`, and retarget the files in that document's §2.

The filterable matrix page (same rows, live-updated during the work):
https://claude.ai/code/artifact/ad7da1cc-7807-4109-ad77-cb166e70596e

## Status check (2026-09-13, Linux dev box) — the September rewrite re-verified on Linux, L1 closed

The §13.22–§13.23 rewrite of the Linux backend had been done entirely from the Windows box. Run on
Linux hardware as root on 2026-09-13 (`no-sneak-net/CLAUDE.md` §13.24): every 2026-07-28 baseline
number reproduces (ARP resolve, local-interface short-circuit, loopback RTT, off-link ping, a /24
sweep now at 254 probed), the unprivileged failure is still the honest `EPERM` pair, and Maven
runs the module suite on this box — **39 classes / 401 tests, 0 failures**. This segment has 18
IPv6 neighbours, so **L1 is closed**: `ACTIVE_NDP` in 1–8 ms, ICMPv6 echo 4/4, segment discovery
18 of 18 by ICMP after fixing a first-reply snapshot defect the wire exposed (Linux only; the
Darwin twin is M9's). One shared-code change: the `HostScan` host row says `ndp` rather than `arp`
for an IPv6 neighbour not proved by ICMP. A root-gated live class, `platform/linux/LinuxLiveTest`
(8), now exercises the real Linux sockets and is skipped without root — as root the module is
40 classes / 409 tests. Uncommitted at the time of writing.

## Status check (2026-09-20, Windows dev box) — scan pipeline speed, `-sV` correctness, handoff

**Start here if you are picking the project up.** One long session on the Windows box (the same
machine that is 10.0.0.61 on the maintainer's `/24`; Avast installed, Npcap installed). The
design is `no-sneak-core/CLAUDE.md` → *The scan pipeline* (the dated log that held the measured
record was deleted 2026-10-26). At the time of writing **43 files were modified
and uncommitted** (35 M, 4 A, 1 D, 1 R) — the maintainer commits; nothing here was.

**What changed (all in `no-sneak-core` unless noted):**
- `--up-only` — every formatter lists only live hosts (`ScanReport.hostsToRender()`); counts still cover the range.
- Adaptive connect deadline — 10 × the host's discovery RTT, clamped to [`--min-rtt-timeout` (500 ms), `-t`]; unmeasured on-link hosts inherit the segment's median RTT; `PortScanCallback` has a millisecond constructor.
- Probes streamed from the connect callback (`CountdownMonitor.addChild`), admitted on the gate's **priority lane** (`ConnectionGate.submitFirst`); `probeStage` is UDP-only now.
- `ScanGate` honours caps ≥ 1000/s (per-slot quantum over zoxweb `RateController`; was capped at ~990/s whatever `-T` said). `ScanGateThroughputTest` measures it.
- NIOSocket's `NIOChannelMonitor` appointment released when the callback's deadline wins (`PortScanCallback.releaseWith` → `abortClientSocket`); "Connection timed out" classifies as `timeout`.
- Per-host discovery decides at the **first positive** unit instead of the slowest.
- `ParallelJoin` → **`CountdownMonitor`** (rename, maintainer's request).
- BCJSSE/SunJSSE pin (P23) and its canary **removed**; `tls-connect` uses the JCA default provider; `TlsConnectContextTest` replaces the canary.
- **Gated probes never ran OCSP/CRL** (`UNKNOWN`/`none` since P14) — registry built contexts without the socket; fixed (`ProbeContext(ProbeTransport, NIOSocket, …)`, `GatedContextRevocationTest`).
- `postgres-db.json`: `^S$`/`^N$` (an SSH banner matched `^S`), failed TLS handshake → `fail`, not an identification.
- `https-scan.json` now ends with `tls-connect` + `GET /` to capture `Server:` as `service-version`; every failure of that tail records `no-server-header` and still delivers the posture.
- `NMap` usage text regrouped (Discovery / Timing / Output) and documents the above.
- App (`no-sneak-app`): copy icon beside *Send to chat* on the scanner card and a *Copy* row action in the result list.

**Measured on the maintainer's `/24`, 25 hosts up, ~24,500 filtered ports:** 136 s → 39.8 → 13.9
→ 8.25 → **6.17 s** (`-T5 --min-rtt-timeout 200 --max-inflight 4096 --up-only --open`). First
`-sV` run 68.9 s at `-T3`, before the priority lane. Single host `10.0.0.1 -p T:53,U:53 -sV`: 7.9 s
→ 6.1 s (the remaining 5 s is the 53/tcp fallback sweep waiting one `-t`; `-t 2` halves it).
`xlogistx.io -p 443 -sV --probes https-scan`: 5.0 s, grade A, `GOOD`/`crl`, `Server: NOYFB`.

**Test state:** core **399 tests in 36 classes, all green** through the hand-rolled launcher
(`.claude/tools/`, whole suite ≈ 16 s; its `cp.txt` drifts — a wave of `NoClassDefFoundError`
means the snapshot, not the code) and per class through IntelliJ. `no-sneak-app` builds; its Swing
changes have no tests.

**Open, in full:**
1. **Parked by the maintainer:** aborting the sibling TCP-pings at the first discovery positive
   races zoxweb's connect completion on the executor and prints a `ClosedChannelException` stack
   trace (`TCPSessionCallback.connected` → `getRemoteAddress` on a closed channel; harmless to the
   result, noisy). Fix when picked up: stop aborting them in `NMapScanner.discoverHost` (they finish
   on their own in ms, or hold one slot for ≤ `-t`); keep the first-positive verdict.
2. **Design question for the maintainer:** the match-first sweep launches every candidate at once —
   ~18 connections to one sshd plus the port scan's banner grab — and OpenSSH `MaxStartups 10:30:100`
   drops past ten, so the tier-1 `ssh` probe can lose to a fallback (seen on 10.0.0.8/.12 before the
   postgres fix). Proposal: run tier 2 only if tier 1 yields nothing. Not started.
3. ~~`https-scan`'s header tail hit its timeout on a TLS-1.2-only host (10.0.0.8: `no-server-header`
   in 9.5 s vs 5.0 s elsewhere). Posture delivered, header missing; cause not investigated.~~
   **Closed 2026-09-22** — a reverse DNS lookup inside the tail's deadline, not TLS 1.2; see the
   *Status check (2026-09-22)* below.
4. **Declined, do not reopen:** an antivirus/interception-proxy detection warning (Avast Mail Shield
   made 25/110/119/143/465/563/587/993/995 read `open` on every host). Scan with the shield off.
5. Unchanged from the matrix below: CI runner (maintainer's), M1/M9 (need a Mac), N3 (IPv6 unicast
   re-solicit), P17 pinned. App backlog in `no-sneak-app/CLAUDE.md` → *Needed fixes*.

**Environment facts that will mislead you on this box:** Avast's mail shield fakes open ports and
its TLS proxy fakes `UNTRUSTED_ROOT`; with Avast off, Windows Firewall stealth mode turns the
scanning host's own closed ports into `filtered`. Every host on the segment drops rather than
resets, so nearly every port pays the full adaptive deadline.

## Status check (2026-09-22, Windows dev box) — item 3 closed, one upstream note for zoxweb

Short session on the same box; everything from 2026-09-20 was committed as `b327232` before it
started. One code change, three new tests, uncommitted at the time of writing (maintainer commits).

**Item 3 was never about TLS 1.2.** The `tls-connect` tail builds the framework's connect address
from the target string, and zoxweb's `SSLContextInfo.newInstance()` mints the engine with
`clientAddress.getHostName()` — a **reverse DNS lookup** when the address came from an IP literal.
On this segment an address without a PTR record costs 4.6 s, paid between the TCP connect and
the ClientHello, inside the probe's one 5 s `arm()` window; the handshake then ran out of time
one step from finishing. Name targets never paid it (the resolver stores the name), which is why
xlogistx.io was fine. Fix: `ProbeSecureCallback.namedAddress` pins the host string on the resolved
address (`InetAddress.getByAddress`), pinned by `TlsConnectContextTest` (+3). Measured:
`https-scan` on 10.0.0.8 9.4–10.1 s → **4.8–5.3 s**, tail alone 2.3–3.0 s, all complete; the host
sends no `Server:` header at all, so `no-server-header` is the *right* answer there. Suite
**402 / 402**. A first reading of the log as a two-worker race in `NIOSocket` was wrong and was
withdrawn after the maintainer pushed back — the key's interest is zeroed before every dispatch
and only the finishing worker restores it; the "second thread" was the probe's own timeout.

**Later the same day:** the header `GET` moved to HTTP/1.1 (maintainer's request); a `/24 -sV`
run (20 up, 23.5 s at `-T5`) surfaced one banner defect, fixed — dropbear's binary KEXINIT arrives
in the same read as its greeting and its printable fragments were glued onto the row; the greeting
now ends at the first binary byte (`PortScanCallback.cleanBanner`, `PortScanCallbackTest` +1).
Suite **403 / 403**. The Web Shield was on for that
run and its proxy caps this process at **100 concurrent connections** (it says so in the mail-port
banners: `421 concurrent connection limit in Avast exceeded`), which is a second reason, besides
the fake open ports, to scan with it off.

**ai-assistant, same day:** the maintainer found the model-selection defect ("the first selection
is correct, any other selection is null"): Gemini's OpenAI-compatible model listing returns
`models/<name>` ids, its chat calls take `<name>`, and the prefixed id went to the wire as picked.
`AIAPIProvider.MODEL_NAME` (zoxweb `ReplacementFilter("models/", "")`) now strips it where the
catalog is stored and on all three send paths, so chats saved with the prefix still work.
`ModelNameTest` (+4); module suite **65 / 65**. Note zoxweb's `FilterType` has no such constant
and `TokenFilter` keeps the part *before* a separator, so neither fitted; `ReplacementFilter`
already existed and needed no zoxweb change.

**Open, in full:**
1. Unchanged — parked: the sibling TCP-ping aborts in `discoverHost` (harmless
   `ClosedChannelException` noise; five traces on the `/24 -sV` run).
2. Design question, now measured: tier 2 only after tier 1 fails. On the shields-off `/24 -sV`
   (19 up, 20.3 s) the sweep lost the `ssh` verdict on 2 of 13 SSH hosts (10.0.0.9 fell back to
   its banner, 10.0.0.12 got nothing); both identify on every standalone run, sweep or `ssh`
   alone (`OpenSSH_7.9p1`, `dropbear_2016.74`). Load-only, every time. Still the maintainer's call.
3. Closed (above).
4. Unchanged — declined, do not reopen: AV interception heuristic.
5. Unchanged: CI runner, M1/M9, N3, P17. App backlog in `no-sneak-app/CLAUDE.md`.
6. **Upstream fix applied by the maintainer, same day, verified here:** zoxweb-core 2.4.0
   `SSLContextInfo.newInstance()` line 436 now calls `clientAddress.getHostString()` (JDK 7+,
   never a lookup). The rebuilt jar (installed 08:06) measured on *unpinned* bare-IP addresses:
   `newInstance()` 10.0.0.8 4604 ms → **23 ms**, 10.0.0.1 → 0 ms; no-sneak suite 402 / 402 against
   it; live `https-scan` on 10.0.0.8 4.4–4.7 s, xlogistx.io 4.1 s. The zoxweb change was
   uncommitted in that repo when this was written. no-sneak's own `namedAddress` pin stays as
   belt and braces. `NIOSocket` line 272 still calls `getHostName()` on a resolver path; not on
   this probe's route, not measured.
7. **Observations, not chased:** 10.0.0.8 sits on the *first* connection after a quiet spell
   (seen from `curl` 8 s, and twice from the CLI as the first run of a series, before and after
   the fix; back-to-back runs never stall). After a forced 120 s idle, a plain `openssl s_client`
   handshake — no Java, no client-side lookup — took 2.4 s where a warm one is well under a
   second, and the CLI right after it was clean. That points at the server doing its own
   per-connection work (a reverse lookup of the client is the usual suspect); server-side, not
   ours. And BCJSSE 1.0.24 on a plain blocking
   `SSLSocket` times out against xlogistx.io's TLS 1.3 while SunJSSE completes it — the probe
   path succeeds there under both providers, so nothing in the product is affected today.

## Status check (2026-10-24, Windows dev box) — UI redesign Phase 1: setup and login

The maintainer found the UI unintuitive and asked for a redesign to review visually first. The
design is a nine-board canvas (https://claude.ai/artifact/Ln8xCjHgxDrnRo1joeurpE: unlock, new scan
with tabular results, history, assistant chat with PDF buttons and the attach popup, API keys,
capture, skills with the Save-as combo, providers, the PDF dialog); the execution plan is
**`no-sneak-app/UI-REDESIGN-PLAN.md`**. Two rules were set on the way: the implementation stays
Java Swing (FlatLaf + MigLayout), and **any reusable widget that does not reference a no-sneak type
goes into io-xlogistx/gui-audio (`io.xlogistx.gui`, Java 8)**.

**Phase 1 is implemented** (uncommitted at the time of writing):

- gui-audio: `UITokens`, `BadgeLabel`, `InlineMessage`, `DirectoryField`, `FormPanel`,
  `StepperPanel`, `SplashSidePanel`, icons `KeyIcon` / `LockIcon` / `LogoutIcon` / `ShieldIcon`;
  `FormPanelTest` (6 headless tests, green through the `.claude/tools/RunTests` launcher — the
  launcher's `cp.txt` lacks MigLayout, add the two `com.miglayout` jars from the local repository),
  `StepperPanelDemo`. Installed to the local repository; reload the Maven projects in IntelliJ.
- no-sneak-app: `ui/UnlockPanel` replaces `LoginPanel` + `DataStoreSetupPanel` (both deleted);
  `NoSneakMain` is one `AppFrame` whose content pane swaps between the unlock panel and the
  `AppShell` on the session's `authenticated` event; `NoSneakStore.openOrCreate`; `Navigator.Screen`
  lost `LOGIN` / `REGISTER`; the footer's "mock-build" text is gone. Tests: `UnlockFormTest`,
  `NoSneakStoreOpenOrCreateTest`; `DataStoreSetupFlowTest` unchanged.
- Decisions taken (listed in the plan): the DomainAppID combo and the passkey stub left the login
  screen; the store is fixed once step 1 completes (restart to switch); the `AppShell` is built when
  the store opens; the landing page after sign-in stays the profile until Phase 2.

**Phase 2 (the shell) is implemented the same day**, after the maintainer ran Phase 1 ("it looks
fine now"): gui-audio `SideNavPanel` + `HeaderBar` + navigation SVGs; `AppShell` = header,
sidebar (Scan / Assistant / Account / Admin, the last only for the super-admin), card host,
footer; `Navigator` routes `Screen` → card + section and `sync`s moves the assistant makes by
itself; every panel lost its toggle column (`show(SECTION_*)` instead, `SubjectSecManagerPanel`
is tabs, `PQCRegistryPanel` unregistered); `MenuBarFactory` is File / View / Help; the assistant's
`AssistantPanel` is wiring only with `Page` / `showPage` / `setOnPageShown`. Screens were
rendered headless on a throw-away store and checked before hand-over (lesson from Phase 1's
first cut, whose stepper did not wrap rows).

**Phase 3 (the scanner page) is implemented the same day**: core `NMap.formatCommand` (inverse of
`parseCommand`, `NMapFormatCommandTest`), gui-audio `ChipPanel` / `SegmentedControl` /
`KeyValuePanel` / `Tables`, app `ui.scan.ReportView` (reads the engine's per-port grade / PQC /
trust; no new grader), `ScanFormPanel` (form ⇄ command) and `ScanResultView` (Hosts / Services /
Raw JSON with a detail pane), wired into `ScanPanel` as targeted edits after a full-file rewrite was
stopped by the safety classifier mid-write (the truncated file was restored by writing HEAD's
content back; `git checkout` is off limits — the maintainer's rule: *I modify, they approve and
commit*). Rendered with a sample report and checked.

**Phase 4 (lists and the assistant pages) is implemented the same day**: scan history as a table
with search and a selection toolbar; API keys, Providers and Skills as list-left / editor-right
(each `CardStack` keeps its card names with `"list"` as the placeholder, so no call site moved);
Capture areas and captures side by side; composer chips for skills, images and areas-on-send.
Rendered and checked.

**Phase 5 (remaining pages) is implemented the same day**: gui-audio `PagePanel` (the shared page
frame) wraps Profile, Backup and Access control. JetBrains Mono is **optional, not open work**
(maintainer's call, 2026-10-25): the app ships with the logical monospaced font; `UITokens.mono`
honours `UIManager "xlogistx.monoFamily"`, so if the fallback looks dated the FlatLaf font
artifact plus two lines in `NoSneakMain` switch it over. The unreferenced `icons/*.svg` were
already gone.

**Run-through findings (2026-10-25).** First report from the maintainer: a scan with `80,443` in
Ports and "Host discovery only" ticked ran `-sn` and showed 0 open ports, the form giving no sign
that the ports were dropped. Fixed in `ScanFormPanel`: the box and the Ports field are exclusive,
last action wins. Typing ports unticks the box; ticking the box keeps the typed list and an
inline note says those ports are not scanned (`ScanFormPanelTest.discoveryOnlyAndPortsAreExclusiveLastActionWins`;
a first cut greyed the field, which the maintainer read as the port range being disabled). The
engine and the result parser were verified on the same segment with the CLI: 22 hosts up, 12
with port 80 open, counted as 12 by `ReportView`. Second request the same day: **Scan again** on a
stored report (history toolbar and the stored view's header) loads its command, probes and name
back into the New scan form (`ScanPanel.rerunScan`, `ProbeSelection.keysForNames`). Third:
**`subject=` + `password=` launch parameters** sign in directly when `ds.location=` +
`ds.store-password=` opened the store (`NoSneakMain` → `UnlockPanel.signIn`; a refusal stays on
the sign-in step with the reason inline; `UnlockPanelSignInTest`).

**Decisions (2026-10-25, maintainer):** JetBrains Mono is dropped for good (the
`xlogistx.monoFamily` hook stays, nothing more). **The Mongo datastore path is deprecated**: the
app's store is the encrypted H2 file today and **PostgreSQL is the next datastore target**;
`no-sneak-core` `NoSneakUtil`'s Mongo branch (D9) is legacy, not to be extended. The redesign
is closed; new work starts after this session.

**MAC vendors (2026-10-25, built to the maintainer's spec, uncommitted):** the maintainer added
`NSNetUtil.MAC_VENDORS` (a zoxweb `OUIDB`) and a `macVendor` field in `ScanReport`'s host JSON
(now the manuf *description*: the short name is an 8-char abbreviation). The table is filled
**after a login**, before the shell shows (`AppFrame.loadMacVendorsThenShow` →
`Session.loadMacVendors`): the store's `DataContent` named `Mac-Vendor-Content` holds the Wireshark
manuf file (`source_id` = `OUIDB.XLOG_MANUF_URL`, `data` = the bytes); missing → downloaded once
with `OUIDB.getRawContent`, parsed in a throw-away table to make sure it is a manuf file, stored,
loaded; present → loaded, no network. The row is app-wide (system context, no owner) so every
subject shares it. A failed download warns once and the app still starts. The result view shows a
**Vendor** column and `mac (vendor)` in the host detail. Tests: `ScanReportMacVendorTest`,
`SessionMacVendorsTest` (real store, download behind a seam), `ReportViewTest`. **Still to do by the
maintainer:** one live run (first login downloads, a LAN scan names vendors, the next login does
not download, and **Account → Settings → Sync MAC vendors** replaces the stored list). The Settings
page (new `SETTINGS` screen, `SubjectPanel.SECTION_SETTINGS`, gear icon added to gui-audio) holds
the **Sync** section: `Session.syncMacVendors()` downloads, replaces the row (`last_update_ts`
stamped) and re-loads the live table in place — `OUIDB.load` only adds or replaces entries, so a
scan in flight keeps resolving; `macVendorStatus()` feeds the page's status line. Same day, on
request: **Delete all** on the scan history toolbar (`Session.deleteAllScanResults`, confirmed,
subject-scoped; `SessionScanHistoryTest`), and the history table is **multi-select**: Delete
removes every selected row after one confirm (`Session.deleteScanResults`), the single-row
actions grey out while several rows are selected.

**2026-10-26, maintainer's spec, uncommitted:** (1) **no probe ticked, no probing** —
`ProbeSelection.applyTo` turns `-sV` off and drops any `--probes` when the chip set is empty; the
*Service detection* box mirrors the chips and, clicked by the user, means all (every bundled and
stored probe ticked) or none; the chip strip's empty text says nothing is probed. Engine side:
`NMapScanner.buildChecker` with a requested set that matches nothing returns a null checker
(nothing probed, warning) instead of the whole catalog. (2) The host detail pane shows a
**Network adapter** block (MAC, Vendor) when a MAC was learnt; the MAC left the subtitle. Tests:
`ScanPanelTest` (two new), `ExtraProbeCatalogTest.onlyUnknownNamesProbeNothing`. Live run owed:
no chips → a scan with no probe traffic; tick Service detection → all chips appear. (3) **Backup
moved under Settings** — the Backup and Restore blocks follow Sync on the Settings page;
`Screen.BACKUP`, `SECTION_BACKUP`, the sidebar item and the View-menu entry are removed. Rendered
and checked; no test touched the screen. (4) **The Probe library** ("very plain; the bundled
probes can't be read; it doesn't explain how to create a probe; I can use the AI assistant"):
core gained `ProbeDefinition.description` (optional; the 18 bundled files carry one),
`ProbeDefinitionLoader.bundledSource(name)` / `probeDefinition()` and a pom resource that serves
`PROBE-DEFINITION.md` from the classpath; the assistant gained the three-argument
`sendToChat(text, name, composerText)` and a *Save as <target>* button on every reply
(`ChatPanel.addSaveTarget`); the app's Probe library is a table (bundled + stored, filter and
search) with a read-only detail pane, a how-to block, an editor with inline Check, the definition
card and *Write with the assistant*. Tests: `ProbeDefinitionLoaderTest` (three new),
`ChatBubbleSaveAsSkillTest` (two new), `ProbeLibraryModelTest` (new, 5). Rendered in five states
and checked. Live checks owed: *Write with the assistant* on an open chat, then *Save as probe* on
the reply; *Copy to my probes* of `ssh`, Save, and a scan reports the shadow warning. (5) **Probe
set audit** ("are any of the default probe definitions redundant?"): the two unbundled files
(`https-classical`, `smtp-starttls`) are deleted; `postgres-tls` never sent the SSLRequest and so
only worked against PostgreSQL 17 direct-SSL servers — it now does SSLRequest → `S` →
**`tls-upgrade`** (new action: JSSE handshake in place on a `connect` with `upgradable: true`)
→ StartupMessage → version over TLS; `TlsUpgradeEndToEndTest` (loopback PostgreSQL-style TLS
negotiation) pins it. Live check owed: `postgres-tls` against a real PostgreSQL with `ssl = on`
(the version arrives only when `trust` auth applies to the probe's user; otherwise the note is
`postgresql-tls-auth-required`, which is still a completed identification).

**2026-10-27, maintainer's requests, uncommitted:** (1) **Chat and Chat History merged** into
one Chat page (the list is the page, a row opens the conversation as a page with *All chats*,
*Edit*, *Chat as PDF* and *New chat* in its head; `Page.HISTORY` and `Screen.CHAT_HISTORY` are
gone; the duplicated *Save as probe* on every reply fixed on the way); `NEW_SCAN` renamed `SCAN`
by the maintainer. (2) The Hosts tab shows a **MAC** column beside Vendor. (3) **Help** rewritten
to the sidebar's pages; **About** rebuilt as a card (tagline, the summary of what it will and
won't do, Version / Java / Platform / Vault / Store, a line about the tooltips, a Help link);
the sidebar footer's version line opens About; the header chip's tooltip and the About Store row
share `MenuBarFactory.STORE_NOTE`; the **status bar** shows *Signed in as …* and the MAC vendor
list's state (the new `Session.onMacVendorsChange` event after the login-time load and every
sync; the Settings Sync line follows the same event); the Settings **Backup / Restore** notes
list what the store holds and the archive name carries the day; the **Profile** page is three
blocks (Name form with a status line, Identifiers and Addresses with descriptions) and **API
Keys** is a page frame with *Add API key* in the head and stacked forms for change-password,
edit-key and the add dialog; the sign-in splash's tagline comes from `MenuBarFactory.TAGLINE`.
(4) gui-audio: `ListSection`'s description became a `WrapLabel` (it was a JTextArea one line
high on first show); `HeaderBar.setStatus` takes a tooltip. (5) **`ComponentRef`** (the
maintainer's class, reshaped: a source accessor, live read-through of `GetName` /
`GetDescription` / `GetDisplayName` with fallbacks, display-name and description overrides) is
now what every enum-driven control is built on: `SegmentedControl` (text = display name, tooltip
= description, `selectedSource()`), `SideNavPanel.item(option, icon)`, the View menu, the
assistant's page cards, the navigator's routes (the shell registers panels, the navigator adds
the cards), the scan result tabs (`ScanResultView.Tab`) and the Access Control tabs
(`SubjectSecManagerPanel.View`), `ListSection.rowRefs()` and `ChipPanel.chipRefs()`. The four
UI enums (`Navigator.Screen`, `AssistantPanel.Page`, `ProbeLibraryModel.Filter`,
`NMapConfig.Timing`) implement `GetDescription`, so the sidebar, the View menu and the T0 to T5
segments carry tooltips. Tests: gui-audio `ComponentRefTest`, `SegmentedControlTest`,
`SideNavPanelTest`, `RowRefsTest` (14); app `ScreenLabelsTest` pins every description;
`SessionMacVendorsTest` pins the event. Every page rendered headless and read. **Live checks
owed:** the tooltips appear on hover; the status bar after a real *Sync*; *Save changes* on
Profile shows *Saved.*; a backup lands as `<db>-backup-<date>.zip`.

**2026-10-27 (later), hardening, uncommitted:** the five items the open list carried under
*Hardening* are closed. `Session` has one signed-in guard (`requireSignedIn`, checks both
`subjectIdentifier` and `principalID`, one wording *Not signed in*; the tests that pinned *Not
Logged in* follow); `addIdentifier` runs it and leaves validation to the manager, which already
refuses a blank (*Invalid principal ID*) and a duplicate (*Principal ID already exists*, the
store's unique index) — the commented-out guards are gone; `removeIdentifier` answers *Cannot
remove the only identifier* ahead of the manager's own row-locked refusal; `changeAPIDetails`
removes a metadata entry handed a blank instead of writing `""` (`putOrRemove`), so a cleared
provider reads as absent; `AssistantStorage.deleteChat` (and `deleteSkill`) pass
`withReference=true` — the H2P cascade is DB-driven and keeps a child another row still
references, so a deleted chat takes its `ai_message` / `ai_request` / `ai_response` rows with
it; a copied API-key secret is wiped from the clipboard after 60 s if it is still there (gui-audio
`GUIUtil.copyToClipboard(text, millis)` on a one-shot Swing `Timer`, `clearClipboardIfHolding`
guards it; jar reinstalled, reload Maven in IntelliJ). Tests: `StoreHardeningTest` (a real
`H2PSetup` installation under `target/`: the cascade and the duplicate identifier, two rules the
mock store cannot exercise), `IdentifierRoundTripTest.addAndRemoveRejectedWhenSignedOut`,
`APIKeyRoundTripTest.changeApiDetailsRemovesBlankAssistantMetadata`, gui-audio
`GUIUtilClipboardTest` (3); the seven app classes 58 / 58 through the CLI launcher. Left under
*Hardening* in the app `CLAUDE.md`: the `char[]` secrets are never zeroed.

**2026-10-27 (evening), switching assistants inside a chat, uncommitted:** the maintainer asked
"if I have 2 ai assistant can I switch between them" and chose, when asked, a **Provider combo
in the conversation's options row**, *Send history* keeping its meaning unchanged, and replies
labelled by provider and model. Built: `ChatPanel` has a Provider combo beside Model
(`onProviderPicked`: rebind the chat, refill the models, land on the provider's default model,
save, re-frame the facts line; `syncProviderSelector` fills and selects it from the chat on every
`refreshPrompt` / `refreshProviderCombos` / `clearModels` under a guard; a provider no longer
linked shows no selection); `AIResponse.provider` (new param, the config id) is stamped by
`AssistantCallback`, which now takes the provider id the request goes to; the bubble's detail
line and the PDF's `### Assistant` heading read `provider · model` (`ChatHistoryModel.replyMeta`:
name when known, raw reference otherwise, model alone on older rows; `AssistantUtil.detailLine`
has a leading *who*); invariant 4 of the assistant's *Hard rules* (key + model immutable) is
dropped. Tests: `ChatHistoryModelTest.replyMeta`, `DetailLineTest.whoAnsweredLeads`; the
assistant's unit classes 33 / 33. Rendered headless with two linked providers and a chat answered
by both, then the combo driven: the chat rebinds and lands on the other provider's default
model. Live check owed above.

**2026-10-27 (evening, later), sending a past prompt again, uncommitted:** the maintainer asked
for "a copy icon for every past prompt" that, clicked, "insert[s] in the main prompt so I could
send it again". Built: every user bubble carries one white copy icon at its bottom-right
(`AssistantUtil.chatBubble` nine-argument form with an `onReuse` runnable, button named
`AssistantUtil.REUSE_PROMPT`); `ChatPanel.addMessage` wires it to `insertIntoComposer`, the path
a skill insert and `setComposerText` already use (blank composer replaced, otherwise appended at
the caret, focus to the composer), so nothing goes out until Send. Reply bubbles are unchanged;
the Copy / PDF buttons stay on replies only (the user row never built them before and now says
so in code). Test `ChatBubbleReuseTest` (3); the four bubble classes 17 / 17 through the CLI
launcher. Rendered headless in both themes: white glyph on the accent bubble, right-aligned
under the text. Live check owed above.

**2026-10-27 (evening, last), Clear on the composer, uncommitted:** the maintainer asked for a
"clear button to the main prompt area", then "an icon instead of a text button". Built: an
**X icon** (`IconUtil.CancelIcon`, toolbar style, 28 px, the + button's twin) at the right end
of the input box (`ChatPanel.clearButton`, named `CLEAR_PROMPT`); it empties the typed text only
(chips and attachments stay), returns focus to the composer, and is shown only while the
composer holds text (the svg glyph has no dimmed look, so it hides rather than greys) — the
document listener that already resized the bar now also syncs it (`composerChanged`). A text *Clear* button beside Send came first and was replaced the same
evening. Test `ChatPanelClearTest` over a real `ChatPanel` on the context
test's in-memory repository (made package-private); rendered headless empty (no X) and
filled (X at the right end of the box). Live check owed above.

**2026-10-28, provider switch kept the model filter (bug, fixed, uncommitted):** the maintainer:
"when I [switch] providers ie claude to chatgpt the model filter should be updated properly, now it
hangs on the old one". Cause: the *Filter models* text is a session filter (`ctx.getModelFilter`),
and `onProviderPicked` refilled the model combo through it, so "sonnet" typed for Claude hid every
ChatGPT model. Fix: `onProviderPicked` blanks the filter field before refilling (the field's
document listener runs `applyModelFilter` against the new binding; an already blank field falls
through to the explicit `fillModels`). Opening another chat bound to a different provider still
keeps the filter — that is the session-filter design and was not changed. Test
`ChatPanelProviderSwitchTest` (2) over a real `ChatPanel` with two fake providers; the assistant
suite 85 / 85. Live check: type a Claude-only filter, switch to ChatGPT, the filter is blank and
the list is ChatGPT's.

**2026-10-28, one filterable model combo (uncommitted, both repos):** the maintainer: "the
model widget and filter widget [could be] one widget like a combo and put it in the xlogistx-io
gui package". Built in gui-audio: `io.xlogistx.gui.FilterComboBox<T>` — an editable `JComboBox`
whose own model keeps the full list and a visible, filtered view; typing in the editor narrows
the drop-down through a pluggable `Matcher` (default `CONTAINS`; the matcher also sees blank
text), the popup reopens sized to the matches, Enter takes the highlighted item or resolves the
typed text (exact name ignoring case, else free text when `setFreeText(true)`, else no change),
Escape restores the selected item's text, and the filter is dropped when the popup closes, on a
pick with the list closed and on `removeAllItems`. Hooks survive a look-and-feel change
(`setEditor` / `updateUI` re-install them once per editor). `FilterComboBoxTest` (6, headless);
jar installed 10:16, reload Maven in IntelliJ. In the assistant: `ChatPanel.modelSelector` is one
of these with the `ModelFilter` grammar as matcher and free text on; the `Filter models` field,
`applyModelFilter`, and the session filter on `AssistantContext` (`getModelFilter` /
`setModelFilter`, the `"modelFilter"` event, the reset line) are gone; `PanelSupport.fillModels`
takes a `Predicate<String>` (the conversation's combo takes everything, the three-arg form is
chat models only for the History and Providers forms). The morning's "filter hangs on the old
provider" fix is subsumed: the refill clears the combo's own filter. Tests: the assistant suite
85 / 85 (`ChatPanelProviderSwitchTest` now types into the combo); rendered headless with two
fake providers — the options row is Provider · Model · the two boxes, the model editor shows the
bound model, typed text narrows the visible count. Live check owed: type in the Model box
(`mini`, `gpt*`, `!mini`, `*`), pick with the mouse and with arrows + Enter, Escape, and switch
provider with text typed.

**2026-10-29, vault password warning and step-1 tooltips (uncommitted):** the maintainer: "in the
vault setup panel add tooltip for the input field and put emphasis on the vault password it is
crucial for the user to keep it safe because IT IS NOT RECOVERABLE". In `UnlockPanel` step 1 every
input carries a tooltip (location and its path field and Choose button, vault password, operator
username / password / confirm, database username / password / encryption password), and a
warning row sits under the vault password field in both modes: alert glyph, bold text in the
warning colour on the `warnSoft` tint — `Form.VAULT_PASSWORD_WARNING` ("Keep the vault password
safe. IT IS NOT RECOVERABLE: there is no reset, no recovery and nobody who can retrieve it. Lose
it and the vault, the database and everything they hold are gone for good."). The first-run note
under the card and the warning share one `callout(icon, text, background)` helper. Rendered
headless in create and open mode; `UnlockFormTest` + `UnlockPanelSignInTest` 6 / 6. Live check
owed: hover each step-1 field for its tooltip.

**2026-10-29, Hide window box on the Capture page (uncommitted):** the maintainer: "when I click
on capture to an area in the current design by default the app window is hidden add a check to
enable it is set you hide the application if not it stays". `CapturePanel` carries a **Hide
window** check box beside Capture (N) (component name `CapturePanel.HIDE_WINDOW`, tooltip *Hide
this window while the areas are shot; untick to capture the application itself*), ticked by
default. It drives `AssistantContext.hideWindowOnCapture` (a session preference, kept across
sign-out, not persisted), which `CaptureSupport.shootAndSave` reads: set, the owner window is
hidden and restored around the sweep as before; clear, it is left where it is and the areas are
shot with the application on screen. The chat's send-time sweep goes through the same method, so
the box governs it too. The maintainer's first try ("if I uncheck the hide window it is not
working"): the sweep honoured the box but *Define area*, *Redraw* and the chat's *Capture
area...* still hid the window for the drag, so no area could be drawn over the application in
the first place; `CaptureSupport.select(ctx, owner)` now reads the same flag (the overlay is
always on top, so the drag works over the application).
`CapturePanelHideWindowTest` (2) drives the box on a real `CapturePanel`; rendered headless in
both states (the box sits right of Capture (1), ticked and clear). Live check owed: item 1.

**2026-10-29, Help made richer (uncommitted):** the maintainer: "update the help content make
richer to reflect the recent update". `app-description.md` (Help in the sidebar footer and the
Help menu) gained an *Opening the store and signing in* section (step 1 / step 2, the vault
password NOT RECOVERABLE, the header and status bar), the pages grouped under Scan / Assistant /
Account, and the work since 2026-10-25 in the user's words: the command-is-the-truth rule, `-sn`
versus ports, no chip = no probing, MAC and vendor, Scan again, Stop, multi-select Delete and
Delete all, the Probe library's three routes, the Provider box and the provider · model line,
the Model box grammar (`mini`, `gpt*`, `!mini`, `*`), Send history, Auto-copy code, the chips,
the copy icon and the ×, Chat as PDF, Hide window on Capture, several providers on one key, the
clipboard wipe, Backup / Restore. About's `SUMMARY` still says the same thing in one paragraph
and was left alone; the note in the app module's `CLAUDE.md` follows. Rendered through
`MDViewerPanel` at the dialog's width (2175 px tall, two pages): table, headings and nested
lists come out right. Live check owed: open Help from the sidebar footer and scroll it.

**2026-10-30, Probe library actions moved to the top (uncommitted):** the maintainer: "move the
edit and delete to the top it is confusing on the bottom for a human user". The detail pane's
action row (*Copy to my probes* for a bundled probe, *Edit* and the confirmed *Delete* for a
stored one) left its place under the read-only JSON and now sits on the title row, right of the
probe's name (`ScanPanel.buildLibraryProbeCard`, a header `MigLayout` with the title growing and
the three buttons under `hidemode 3`). Nothing else changed: the same buttons, the same
visibility rule, the same confirm dialog, the same store call. Rendered headless through a real
`ScanPanel` on a fresh store with one stored probe: the stored state shows *Edit · Delete* beside
"my-redis", the bundled state shows *Copy to my probes* beside "https-scan". Live check owed:
select a probe of yours in the library, Delete is now at the top right of the pane.

**Open after Phase 5 (updated 2026-10-27):** the rest of the maintainer's run-through on a
display (unlock, the scan form and history are done; still to try: a stored report from history,
API keys, Providers, a chat with chips, a capture, Profile, Settings with Backup and Restore,
Access control, and the 2026-10-27 re-layouts and tooltips above); the **live
checks owed** for the 2026-10-25/26 additions — first login downloads the vendor list and a LAN
scan names vendors, the next login does not download, *Settings → Sync* replaces the list, a scan
with no chips sends no probe traffic and ticking Service detection fills the strip, the Probe
library's assistant round trip (ask, send, Save as probe) and a copied bundled probe; and, from
before the redesign, the ACL tables are still empty stubs and the job-queue page is not offered.

## Status check (2026-10-21, Windows dev box) — the store follows the datastore's deployment model

The maintainer's instruction: *"the model how to setup the local h2 database changed, read it from
the datastore project"*. What changed upstream between 2026-10-09 and 2026-10-21 (zoxweb-datastore
`e46b7b8`, io-xlogistx `1147986`, jars installed 00:34–00:35 on 2026-10-21; record:
`zoxweb-datastore/h2p-datastore/CLAUDE.md` → the `H2PSetup` row and the `ShiroIniRealmMain`
paragraph, `SHIRO-DS.md` → the 2026-10-20 entries):
- A **deployment** is a `SecretStore` vault whose **mandatory** entries are `master-key`,
  `super-admin-id`, `super-admin-password` and `db.url` (plus `db.user`, `db.password`,
  `db.enc-password`, `app-id`), set up once by **`H2PSetup command=create`** (vault, H2 file,
  `SecurityAdminTool bootstrap-super-admin` = catalog + super-admin + common app with its
  registrar, `create-app` for the deployment's default app, `shiro.ini` written and loaded once).
- At **run time** an application sets nothing up (`ShiroIniRealmMain.build`): vault → master key
  into `KeyMakerProvider`, `H2PDSCreator.toAPIConfigInfo` + controller + key maker, the store
  registered under `ResourceManager.Resource.DATA_STORE`, `ShiroUtil.loadSecurityManager(shiro.ini)`
  installed as the global security manager, `ShiroDSDomainSecurityManager.fromGlobal(store)`
  (attached, not self-managed), `setSuperAdminPrincipalID` from the vault.
- The **app login gate** (user rule 2026-10-20): a login carrying a domain and app succeeds only
  when the subject's grants in that app imply `app:login` — the `app_user` starter role carries
  it, the super-admin's wildcard applies in every login. no-sneak's login is scoped to
  `xlogistx.com-nosneak`, so a subject created by a bare `createSubjectID` can no longer log in.
- Dual ownership (`app_guid` on every entity, app-owned registered classes) is in the store but
  touches no-sneak only through the schema: no no-sneak class is registered on the app.

**Done in `no-sneak-app`** (record: `no-sneak-app/CLAUDE.md` → the 2026-10-21 block); all
uncommitted, the maintainer commits:
- `NoSneakStore` rewritten. An installation directory holds `no-sneak.store`, `no-sneak.mv.db`
  and **`shiro.ini`**. `create(location, vaultPassword, FirstRun)` runs `H2PSetup command=create`
  in-process with every answer given (`db.path` = the directory, `db.name=no-sneak`, encrypted,
  `app.id=xlogistx.com-nosneak`, INI beside the vault) — the **operator is the super-admin**
  (`FirstRun.adminID/adminPassword` → `super-admin-id/password`, password rules enforced before
  the run); empty DB passwords are generated by the set-up and live only in the vault. The
  app's registrar `registrar.xlogistx.com-nosneak` (the app's owner and `app_admin`; user,
  2026-10-21: *"this is the app super-admin and he should have a password too"*) gets the
  **operator's password** as a second login beside its JWT one (`setRegistrarPassword` =
  `createCredential(registrar, CIPassword)`, kept when one exists); its signing key, printed
  once by the set-up, is discarded (no-sneak never signs up through a registrar JWT).
  `open(location, vaultPassword)` is the `ShiroIniRealmMain` model above, refuses a vault lacking a
  mandatory entry ("predates the current set-up model") or a missing INI, and verifies the no-sneak
  app exists; it no longer seeds or creates anything. `bootstrap` stays for stores not set up by
  `H2PSetup` (the mock-store tests, `NoSneakMain.createDomainSecManager`). New
  `grantAppUser(dsm, subject)` = the no-sneak app's `app_user` role, idempotent.
- `Session.registerUsernamePassword` grants `app_user` after `createSubjectID` (else the realm
  refuses the login); `loginUsernamePassword` uses the `char[]` token constructor (the `String`
  one is deprecated upstream).
- `DataStoreSetupPanel`: on a directory without a vault it asks for the **operator username,
  password and confirmation** and the DB user (default `sa`) / password / encryption password
  (empty = generated); the factory takes a `NoSneakStore.FirstRun`. `NoSneakMain` wiring updated;
  `ds.location=` + `ds.store-password=` unchanged.
- Tests: `TestSecurity.createUser` (create + grant) replaces the bare `createSubjectID` in the
  eight mock-store suites; `DataStoreSetupFlowTest` rewritten on the new path (vault entries,
  INI, attached manager, operator login through the wildcard, the registrar's password login
  into the app, an ungranted subject refused, sign-up login through `app_user`, pool-thread
  isolation, wrong password, reopen) plus a
  refusal case; it uses `target/no-sneak-setup-test/<id>` rather than `@TempDir` because the
  set-up's URL carries `DB_CLOSE_DELAY=-1`. **79 / 79** through IntelliJ (10 classes).

**Decisions taken here, the maintainer may overrule:** the operator typed on the setup screen is
the store's super-admin (the model makes the entry mandatory; a desktop store has one operator)
and the registrar's password is that same password (one operator, one secret to remember; it can
be changed later through `updateCredential` or the admin tool);
further accounts still sign up from the login screen through the direct `createSubjectID` +
`app_user` grant, not the registrar path; no DB password is asked for by default (generated).

**Not done / to know:**
- Installations written before this session (vault without super-admin, no `shiro.ini`, tables of
  the pre-2026-10-19 class names) are refused by `open` with the reason — the one at `/data/ds` in
  the IntelliJ run configuration `NoSneakMain` is one of them: delete it and run without arguments
  for the setup screen, then put its vault password back in the run configuration.
- The app was not launched with a window this session (tests only).
- `no-sneak-core` `NoSneakUtil` (Mongo path, D9) and D5/D6 of the 2026-10-05 check unchanged
  (Mongo deprecated 2026-10-25: H2 now, PostgreSQL next).

## Status check (2026-10-05, Windows dev box) — the app absorbed the upstream security update

The maintainer's "major code update" of 2026-10-05 across zoxweb-core, zoxweb-datastore and
io-xlogistx (all three committed 18:18–18:20, jars installed 18:13–18:14): `DomainSecurityManagerDefault`
deleted from core; the Shiro manager, realm and `SecuritySetup` moved from
`zoxweb-datastore/xlogistx-shiro-ds` (module removed) into io-xlogistx `shiro`, the admin CLI into
`opsec`; the h2p store refuses every connection without a `SecurityController` **and** a `KeyMaker`
with the master key loaded, and checks every row against the thread-bound Shiro subject. Before
this session the repo compiled against the new jars but the app could not open its store at
runtime. Everything below is uncommitted (the maintainer commits).

**Done in `no-sneak-app`** (record: `no-sneak-app/CLAUDE.md` → the 2026-10-05 block):
- `NoSneakStore` (new): an installation = a directory with the vault `no-sneak.store` (opsec
  `SecretStore`: master key + `db.*` entries) and the encrypted H2 file. `create` (first run) /
  `open` (every run, vault password is the one secret) → master key into `KeyMakerProvider`,
  `ShiroSecurityController` + key maker on the config, connect, `bootstrap` (catalog seeded, app
  `xlogistx.com-nosneak` ensured, Shiro sessions never time out). `NoSneakMain` takes `ds.location=` +
  `ds.store-password=`; `DataStoreSetupPanel` asks for the vault password and shows the DB
  fields only on a directory without a vault.
- `Session`: unbound Shiro subject login scoped to the no-sneak app; `getDataStore()` is a
  `Proxy` wrapping each store call in `SubjectSwap` (the panels and the assistant run on pool
  threads); `asSubject` / `runAsSystem`; `logout` ends the subject; `loginAPIKey` removed with the
  login screen's API-key card; a vendor's domain/app on an external key is metadata
  (`vendor-domain` / `vendor-app`), not the key's `app_id` — the 3 pending `APIKeyRoundTripTest`
  cases are closed by that decision; `registerUsernamePassword` reports the real reason.
- `AssistantStorage` reads the subject view; `SubjectPanel` runs backup/restore in the system
  context and shows the vendor fields.
- Tests: `TestSecurity` + 7 round-trip suites on the mock store, `DataStoreSetupFlowTest` on a
  real vault + encrypted H2 with the access check on (two users, pool threads, isolation, logout,
  wrong vault password, reopen). **78 / 78** through the `.claude/tools` launcher; `cp.txt` moved
  to JUnit 6.1.3 (6.1.2 is gone from the local repository). Whole reactor `test-compile` green.

**Decisions taken here, the maintainer may overrule** (the plan's D1/D3/D4/D5/D7 in
`zoxweb-datastore/h2p-datastore/no-sneak-plan.md`): vault next to the database, its own password;
sign-up stays the direct `createSubjectID` with BCrypt, no registrar, no `app_user` grant (a scoped
password login needs none); no super-admin and no `super-admin-id` entry in a desktop vault
(enforcement off); the keys no-sneak generates itself stay as they are (D5 open). The manager
has no `loginUnboundSubject(principal, password, domain, app)`; the four lines live in
`Session.loginUsernamePassword` — upstream's call whether to add it.

**Not done / to know:**
- The app was not launched with a window this session (tests only). The IntelliJ run
  configuration `NoSneakMain` still carries the old `ds.user=… ds.enc-password=…` arguments; change it
  to `ds.location=<dir> ds.store-password=<pw>`, or run without arguments for the setup screen.
- Existing no-sneak databases (pre-vault, subjects without subject keys, keys in clear) do not
  open through the new path — D6, start fresh or write a migration.
- `no-sneak-core` `NoSneakUtil` (Mongo path) builds the Shiro manager but opens its store without
  a controller/key maker; Mongo is on standby (D9). **Deprecated 2026-10-25** — the store is H2,
  PostgreSQL is next; the Mongo branch is not to be extended.

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
| N3 | IPv6 unicast-NS re-solicit (the v6 twin of §13.13's unicast ARP) deliberately not built; a passive v6 sighting while a v6 resolve is pending gets no re-solicit. Needs a `dst16` overload of `Icmp6.neighborSolicitation`; the wire exists since 2026-09-13 (Linux dev box, §13.24). | P | M | — | codec test + live on the Linux box | `codecs/Icmp6`, three backends' `learnSender` |
| N4 | Hardware-gated measurements: M1 (Mac `observe 60` before/after `ip6` in the filter), M9 (v6 neighbour + arena-shutdown race on a Mac). ~~L1 (Linux NDP never on a wire)~~ **closed 2026-09-13 (§13.24)**, which also found and fixed a first-reply snapshot defect in Linux `discoverIpv6Segment`; Darwin has the same shape and is M9's to fix. | D | S each | a Mac | N | — |
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
| ~~P19~~ | **FIXED 2026-09-11 (wave 1).** OPEN reason is `connected` (was the false `syn-ack`); the engine reference's test count corrected (145 in 11 classes; that file was deleted 2026-10-26); the plan log (also deleted 2026-10-26) no longer named `PortScanner`. | — | — | — | — | docs, `NMapScanner.scanHostPorts` |

### `no-sneak-core` stage 2 — protocol identification

| id | defect | sev | effort | depends on | here | files |
|---|---|---|---|---|---|---|
| ~~P4~~ | **FIXED 2026-09-11 (wave 3 δ).** The probe stage is paced by the scan's `ScanGate` (formerly `RateLimiter`; same class, renamed when its token-bucket pacer was replaced by zoxweb `RateController` so both modules pace with one leaky-bucket rule) through `ProbeChecker(nio, probes, ConnectionGate)` + `GatedProbeTransport.Registry`: a candidate holds one slot from admitted `start()` to delivery/cancel (unadmitted candidates are not started, so no timer runs while they wait); a deep probe's enumeration children are counted but never blocked, so a probe never waits on itself; cancelled losers hand slots back. `ProbePacingTest`, `GatedProbeTransportTest`. Live: `google.com -p 80,443 -sV --max-inflight 2` completes with full detail in 19 s vs ~6 s uncapped. | — | — | — | — | `v2/runtime/GatedProbeTransport`, `ProbeChecker`, `RateLimiter`, `NMapScanner.probeStage` |
| ~~P8~~ | **FIXED 2026-09-11 (wave 3 δ).** The probe stage runs UDP probes (`dns.json`) on UDP ports that answered the UDP scan, via `ProbeChecker.check(host, port, "udp", cb)`. Live: `xlogistx.io -sU -p U:53 -sV` → `53/udp open dns`. | — | — | — | — | `NMapScanner.probeStage` |
| ~~P10~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeContext` runs the user callback after releasing its monitor (`guarded` depth counter; `deliver` parks the result), so `FirstSweep.onResolve` and the losers' `cancel()` never run under a context monitor. `ProbeContextTest.theUserCallbackRunsOutsideTheContextMonitor` and two siblings. | — | — | — | — | `v2/runtime/ProbeContext.java` |
| ~~P11~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeTransport` seam (`NioProbeTransport` in production) + injected scheduler/executor; `ScriptedTransport` and `ManualScheduler` drive the FSM with no socket or timer. `ProbeContextTest` (18): banner match/capture, split reads, nomatch, error, both wait timeouts, watchdog, unmapped outcome, failed write, reconnect, STARTTLS → handshake start, cancel, exactly-once, stale `armGen` timer. Still live-only: the BC handshake, enumeration children, JSSE `tls-connect`. | — | — | — | — | `v2/runtime/*` |
| ~~P12~~ | **FIXED 2026-09-11 (wave 2 γ).** `ProbeCheckerTest` (14): two-tier ordering, portScoped exclusion, election waits for higher priority, immediate win + cancel, none-identified fallback, `checkAll` order. `SendBytesTest` (7) pins the codecs and text-only templating; `MongoPayloadTest` (3) verifies both hex payloads against OP_QUERY/OP_MSG. Live: xlogistx.io 22 (OpenSSH 8.2p1), 25 (JAMES, STARTTLS → PQC X25519MLKEM768), 443 (PQC, TRUSTED, TLS 1.3 only, grade A); google.com 443 (PQC, TLS 1.0–1.3, grade C). | — | — | — | — | tests |
| ~~P13~~ | **FIXED 2026-09-11 (wave 3 ε).** `enumerate-groups` action: one single-group TLS 1.3 handshake per candidate (3 ML-KEM hybrids, 5 curves, 2 FFDHE) → `supported-groups` + `server-group-preference`; in `https-scan`/`tls-scan`; report-only advisory when no hybrid is accepted. Live: xlogistx.io accepts 8 groups, google.com 3, both prefer X25519MLKEM768. `GroupProbeCallbackTest`, `GradeTest`. | — | — | — | — | `analysis/GroupProbeCallback`, `ProbeContext.enumerateGroups` |
| ~~P14~~ | **FIXED 2026-09-11 (wave 3 ε).** `NetworkRevocationChecker`: OCSP POST to the AIA responder, then CRL from the CDP, non-blocking on the injected `HTTPNIOSocket`, bounded by `revocationTimeoutMs` (default 5 s), exactly-once, soft-fail `UNKNOWN/<method>-unreachable`; `revocation-date`/`-reason` kept; CRL signature and freshness verified. Live: both hosts GOOD via crl (neither CA publishes an OCSP responder any more; the OCSP branch is covered by the BC fixture). `RevocationCheckerTest` (9). **Addendum 2026-09-20:** the live verification was on the ungated `ProbeChecker` CLI; the gated path (`NMapScanner`, the app) built its contexts without a socket and reported `UNKNOWN`/`none` on every scan until `GatedProbeTransport.Registry.create` was fixed to keep it (`GatedContextRevocationTest`). | — | — | — | — | `analysis/*RevocationChecker`, `ProbeContext.checkRevocation`, `GatedProbeTransport.Registry` |
| ~~P15~~ | **FIXED 2026-09-11 (wave 3 ε).** `enumerate-ciphers` offers opsec's strong + weak + insecure TLS 1.2 sets (39) and all 5 TLS 1.3 suites; each accepted suite recorded with version/strength/key-exchange/forward-secrecy; `server-cipher-preference` from two ordered offers; RC4/NULL/EXPORT/DES/anon cap the letter at C. Enumeration budget: at most 64 child connections per deep probe. Live: google.com shows TLS_RSA_* and 3DES. See P24 for the grading side effect. | — | — | — | — | `ProbeContext.enumerateCiphers`, `Grade`, `ProbeResult` |
| ~~P16~~ | **FIXED 2026-09-11 (wave 1).** `Checker.TargetGuard`: resolves once on the pool, rejects loopback, link-local, site-local/ULA, unspecified, multicast and anything resolving to them; REST path answers 401/400 via `Responder`. `CheckerPrivateIpTest` (6). | — | — | — | — | `v2/service/Checker.java` |
| P17 📌 | **PINNED 2026-09-11 by the maintainer — recorded, deliberately not scheduled.** the SSL-Labs-parity posture checklist (`no-sneak-core/CLAUDE.md` → *Vulnerability-scanning backlog* since 2026-10-26; ACTION-PLAN item 1 before) (padding-oracle family, named-CVE evidence from version/extension presence only, renegotiation, downgrade/SCSV, compression, ALPN, resumption, 0-RTT, DH hygiene, intolerance, HSTS/pinning). Detection-only by design; anything not decidable without an exploit attempt stays unimplemented. | P | L (many S/M) | P11, P13 | mostly live | new actions + probe JSON |
| ~~P18~~ | **FIXED 2026-09-11 (wave 1).** Ticks are applied to the parsed `NMapConfig` (`ScanPanel.ProbeSelection`), keyed by stored-record GUID, never spliced into the command; re-save updates the existing row. **Remaining, nmap side (P22):** a stored probe named exactly like a bundled one still runs both. | — | — | — | — | `ScanPanel.java` |
| ~~P23~~ | **FIXED 2026-09-11 (wave 4 λ).** Not a classpath mismatch — every BC artifact is 1.86 — but a defect inside `bctls-jdk18on` 1.86 as published: its multi-release `versions/9/SSLEngineUtil` returns `ProvSSLEngine` while the un-versioned `ProvSSLContextSpi` calls the `SSLEngine` descriptor, so `createSSLEngine` throws on JDK ≥ 9 whenever BCJSSE (registered at position 2 by `SecUtil`) resolves `"TLS"`. `ProbeSecureCallback` now mints the `tls-connect` engine from `SunJSSE` explicitly; PQC stays on the BC TLS-API path. Also fixed: `sslUpgraded` was empty while zoxweb 2.4.0 signals handshake completion only there, so `https-version` could never complete. Live: `Server: gws` on google.com, `NOYFB` on xlogistx.io. `BcjsseEngineCreationTest` (3) includes a canary that fails once a consistent bctls is on the classpath — then remove the explicit provider. **Canary fired and workaround removed 2026-09-20** (`bctls` 1.85 on the classpath); `TlsConnectContextTest` (2) replaces it. | — | — | — | — | `runtime/ProbeSecureCallback.java` |
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
