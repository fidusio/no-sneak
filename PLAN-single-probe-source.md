# Coding plan — One probe source (the bundled probes become the subject's own, once)

**Date:** 2026-11-02 · **Owner:** Marwan · **Status:** implemented 2026-11-02 (uncommitted) —
see `no-sneak-app/CLAUDE.md` → *ScanPanel* → *One probe source*. As written, with two details
settled while coding: a *new* draft whose name an existing row holds still updates that row (the
assistant's *Save as probe* relies on it), only a *stored* row renamed to a taken name is refused;
and the Origin column keeps the `SOURCE` constant name in `NSAppUtil.ProbeLibraryColumn`.
**Entity rename, later that day:** the maintainer renamed `ProbeContent` → `ProbeType` (param
`content` → `definition`, table `probe_type`, `setName` lower-cases and trims); the app mirrors
the name rule (`ProbeSelection.nameForm`) and refuses a draft whose name is not already in that form.
**Rule:** never commit. Edit, build, test, leave staging and commits to the maintainer.
**Review rule:** this plan creates **no new entity** and changes **no entity param**. The two
pieces of state it adds go into existing property bags (`ProbeType.getProperties()` for the
origin, the subject identifier's bag for the seed marker, where the profile fields already live).
Say so if you would rather have either as a real param — that is an entity change and needs your
review first.

## Goal
Today a probe has two sources: the 18 bundled JSON files on `no-sneak-core`'s classpath (keyed
`b:<name>`, read-only) and the subject's `ProbeType` rows (keyed `s:<guid>`). After this plan a
subject has **one** set of probes, all `ProbeType` rows: at their **first login** the 18
bundled definitions are copied into their account, once, and from then on every probe is theirs
to tick, edit, delete and group. The copy is a one-time setup, **not** a start-up sync.

## Invariants (do not break)
- `tickedProbes` stays the only source of probing. No chip = no probing.
- The report keeps recording probe **names**; `ProbeGroup` keeps its set of names.
- Probes stay subject-scoped: each subject gets their own copies, nothing is shared.
- The CLI (`NMap.main`, `ProbeChecker.main`) keeps the bundled catalog exactly as it is; only
  the app stops using it.
- Pure rules stay in `ui.scan` and headless-testable; Swing only in `ScanPanel`.

## Decisions taken (defaults — override if wanted)
1. **Per subject, at first login.** The seed runs inside `Session.loginUsernamePassword`, after
   the subject is resolved and **before** the `authenticated` event fires, so every listener
   (`ScanPanel.reloadProbes`) already sees the copies. 18 inserts, once per subject.
2. **The marker** is the property `probes-seeded` on the subject identifier's bag (value: the
   day, `2026-11-02`). Present → never seed again, even for a subject who deleted every probe.
   Written **last**, so a seed interrupted half-way is completed at the next login (a name that
   already exists is skipped, never overwritten).
3. **No upgrade path**, by your instruction: a bundled probe fixed or added in a later version
   does not reach a seeded subject. The one escape hatch is **Restore bundled probes** on the
   library bar: the same routine with the marker ignored — adds every bundled name the subject
   no longer has, overwrites nothing, says how many came back.
4. **Origin is remembered**, not enforced: a copied row carries the property `origin=bundled`;
   the library shows it in the Source column (*bundled copy* / *mine*) and the detail facts.
   Nothing reads it for behaviour.
5. **Names become unique per subject.** A save that would give a probe the name of another of
   the subject's probes is refused inline. A **rename cascades to the groups** that name the
   probe. Together these close the rename / duplicate-name holes found on 2026-11-01.
6. **The engine gets one flag**, `NMapConfig.bundledCatalog` (default `true`): `false` makes
   `selectedCatalog` skip `ProbeDefinitionLoader.loadBundled()` so the catalog is exactly
   `extraProbes`. Set by `ProbeSelection.applyTo` like `extraProbes` is — never printed into or
   parsed from the command line, so `formatCommand` / `parseCommand` are untouched and the CLI
   never sees it.

---

## Step 1 — Engine flag (no-sneak-core)
`nmap/NMapConfig.java`: `public boolean bundledCatalog = true;` + builder
`bundledCatalog(boolean)`.
`nmap/NMapScanner.selectedCatalog`: wrap the `loadBundled()` loop in `if (cfg.bundledCatalog)`.
With it off there is no bundled probe to shadow, so the *shadows the bundled probe* warning
cannot fire; the *duplicate stored probe* warning stays.
`ExtraProbeCatalogTest`: with `bundledCatalog(false)` and two extras the catalog is exactly those
two, no warning; with it off and nothing named, `probeNames` empty → the two extras in priority
order; the default still merges the bundle.

## Step 2 — Session (no-sneak-app `ui/utility/Session.java`)
- `int seedBundledProbes(boolean force)` — `requireSignedIn`; unless `force`, return 0 when the
  marker is present; load `getAllProbes()` names; for each `ProbeDefinitionLoader.BUNDLED`
  definition whose name is not stored: `ProbeType` with the name, the definition's
  `description`, `content = bundledSource(name)`, `origin=bundled` on the bag, `saveProbe`; then
  write the marker (`updateSubjectID`) when it was absent; return the count inserted.
- `loginUsernamePassword`: after `subjectIdentifier` is set and before the event, call
  `seedBundledProbes(false)` in a try: a failure is logged with its reason and the login goes
  on (the marker is not written, the next login tries again). `ProbeDefinitionLoader` is already
  on the app's classpath through core.
- `boolean probesSeeded()` — the marker, for the test and the status line.
- `String originOf(ProbeType)` — the bag's `origin`, `""` when absent.

## Step 3 — Pure rules (`ui/scan`)
- `ProbeSelection`: delete `bundledKey`; `storedKey` stays (`s:<guid>`, `s:name:` for an unsaved
  row); `select(stored, ticks)` drops the bundled list and sets `cfg.bundledCatalog(false)` in
  `applyTo`; `keysForNames(csv | Collection, stored)` resolves by name among the stored rows
  only; `portsPlaceholder` takes the ticked stored definitions; `existingByName` unchanged.
- New `ProbeSelection.nameTaken(stored, name, exceptGuid)` → the rule behind decision 5.
- `ProbeGroupModel`: `rows(mine, presets, stored)`, `memberKeys(g, stored)`, `missing(g, stored)`,
  `namesFromTicks(ticks, stored)` (mine by name — the catalog order is the stored rows sorted
  by priority then name, as the library sorts them); new
  `List<ProbeGroup> renamed(groups, oldName, newName)` → the groups whose set held `oldName`,
  each with the name replaced in place, for the caller to save.
- `ProbeLibraryModel`: `rows(stored)` only; `Row` loses the bundled branch (`stored()` is
  always true → remove it); the Source column reads `origin`; `matches(row, query)` loses the
  filter argument.

## Step 4 — `ScanPanel`
- Fields `bundledProbes`, `bundledSources` and `libraryFilter` go; `reloadProbes` loads the
  stored rows only; `probeRows()` is one list; the Add probe popup keeps **GROUPS** over one
  **PROBES** section (one *All*); `tickAllProbes`, `tickedDefinitions`, the chips, the Ports
  placeholder and *Scan again* (`keysForNames(saved, probes)`) all follow Step 3.
- Library: bar = search, count, **Restore bundled probes** (`seedBundledProbes(true)` off the
  EDT, then `reloadProbes`, note *N probes restored* / *Nothing to restore*), *Probe definition*;
  the All / Bundled / Mine segment goes (`NSAppUtil.ProbeLibraryFilter` deleted; its
  `ScreenLabelsTest` line too). Every row has **Edit** and a confirmed **Delete**; *Copy to my
  probes* goes; the how-to's three ways become: edit any probe, write with the assistant, new
  probe. The detail facts gain **Origin**.
- Editor: the shadow note goes (`NSAppUtil.ProbeEditor.SHADOW` deleted). `probeToSave`: a name
  held by another stored probe → the `InlineMessage` *A probe named "x" already exists* and no
  save; a rename of an existing row → after the save, `ProbeGroupModel.renamed` and one
  `saveProbeGroup` per changed group, then `reloadProbeGroups`. `saveProbeFromEditor` (the
  assistant's route in) keeps update-by-name.
- Groups page member lines: *missing* badge only (`BADGE_BUNDLED` deleted, `BADGE_MINE` kept
  for nothing → delete both, the badge says only what is wrong).
- `NSAppUtil`: `ProbeLibraryPage.RESTORE` (+ tooltip), `ProbeLibraryPage.FACT_ORIGIN`,
  `ProbeEditor.NAME_TAKEN` prefix, `ProbeMenu.SECTION_PROBES`; the constants above deleted.
  `NSAppUtilTest` needs nothing (reflection).

## Step 5 — Tests (headless)
- `SessionProbeSeedTest` (real store, the `SessionProbeGroupTest` pattern): first login inserts
  18 rows with `origin=bundled` and the marker; a second login inserts 0; a subject who already
  had a probe named `ssh` keeps theirs (17 inserted); after deleting `ssh`, a third login still
  inserts 0 and `seedBundledProbes(true)` brings exactly `ssh` back; the other subject is seeded
  on their own first login and sees none of the first subject's rows.
- Core `ExtraProbeCatalogTest` additions (Step 1).
- `ScanPanelTest`: every key is `s:`, `select` over stored rows only, `applyTo` turns the bundle
  off, `keysForNames` by name, the Ports placeholder from stored definitions, `nameTaken`.
- `ProbeGroupModelTest` / `ProbeLibraryModelTest`: signatures of Step 3, `renamed`, the origin
  column.
- Render (`RenderLib` / `RenderGroups` in the scratchpad): library with the Restore button and
  Origin, the editor's refusal message, the popup's one section.

## Step 6 — Docs (same day)
- `no-sneak-app/CLAUDE.md`: *ScanPanel* → Probe library (one source, Restore, Origin, unique
  names, rename cascade), the Add probe popup, *Probe groups* (names resolve among the subject's
  rows), *Session* (the seed, the marker, when it runs), the layout tree.
- `no-sneak-core/CLAUDE.md`: `bundledCatalog` under *Engine reference* (catalog merge).
- Root `CLAUDE.md` banner; `app-description.md` (Help: the Probe library paragraph);
  `PENDING-ISSUES.md` (close the 2026-11-01 rename / duplicate-name notes; add the live checks).

## Order & checkpoints
1. Step 1 + core test → green (`mvn -o -q -pl no-sneak-core install -DskipTests`, then the
   launcher).
2. Step 2 + `SessionProbeSeedTest` → green on a real store.
3. Step 3 + the pure tests → green.
4. Step 4 → app suite green, renders read; manual run: first login shows 18 probes under *mine*,
   a scan with ssh ticked identifies as before with no shadow warning in the report, delete
   `ssh` → Restore brings it back, rename `http` → its group follows.
5. Step 6.

## Out of scope (this pass)
An automatic re-seed on upgrade (decision 3); sharing probes between subjects; a bundled preset
group; changing `ProbeType` or `ProbeGroup` params (review first if wanted).
