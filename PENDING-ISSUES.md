# Pending issues — handoff

*Written 2026-08-13. This is the index of known open work at handoff time. The per-module lists
below stay authoritative for their areas; the "Code review findings" section records issues found
in the uncommitted working tree on this date (scan panel + AI assistant changes, post-`bf072b9`)
that are not written down anywhere else.*

> **Before picking anything up:** the repo root `CLAUDE.md` → *Operating scope* states what this
> tooling does and does not do (assessment and detection only — no exploitation, credential
> attacks, DoS, or evasion). Finding 1 below is a data-boundary defect, which is the other half of
> the same rule set.

## Where the existing open-work lists live

| Area | Authoritative list |
|---|---|
| Scanning engine (v2 rebuild) | `no-sneak-core/ACTION-PLAN.md` → *Pending Issues / Next Steps* (item 1, vulnerability-check checklist, is the largest remaining gap) |
| v1→v2 parity / probe engine | `no-sneak-core/PROBE-CONFIG.md` (remaining parity items) |
| Host discovery | `no-sneak-net/CLAUDE.md` §13.21 — open items split per platform. The one untested claim: **Linux IPv6/NDP is written but has never touched a wire.** |
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
   unreferenced in the background (no cancel path exists).

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

- **v1 packages in `no-sneak-core` are frozen** — never fix v1 bugs; anything v1 has that v2 lacks
  is a regression. See `no-sneak-core/CLAUDE.md` for the routing.
- **Vulnerability scanning (A11)** is still the largest v2 gap — checklist in
  `ACTION-PLAN.md` → *Pending Issues / Next Steps* item 1.
- **Named-group enumeration (A12)** is partly open — v2 enumerates versions and cipher suites only.
- **Stale Mongo default (C1)** — `v2/tools/DMTool:38` keeps `mongodb://localhost:27017/…` as
  `DB_URL`; overridable, stale default rather than a bug.
- **Linux IPv6/NDP** in `no-sneak-net` compiles and has tests but has never been verified on real
  hardware — distrust it until it moves packets (§13.21).