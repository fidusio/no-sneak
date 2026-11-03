# Coding plan — Probe groups (add / edit / remove, select a group when scanning)

**Date:** 2026-11-01 · **Owner:** Marwan · **Status:** implemented 2026-11-01 (uncommitted) —
see `no-sneak-app/CLAUDE.md` → *ScanPanel* → *Probe groups*. Deviations from the text below:
`ProbeSelection` was a nested class of `ScanPanel`, not a file in `ui/scan`, and was **moved**
there as a public class (the plan's "or move it" option); the real packages are
`io.xlogistx.nosneak.app.ui` / `.ui.scan` / `.ui.utility`, not `ui/…`; the inline note goes
through a new `ScanFormPanel.showNote` (info, not error); `resetPanel` clearing the groups is
exercised by the panel's reset path but not by a headless test (constructing a `ScanPanel`
needs a store). Everything else is as written.
**Rule:** never commit. Edit, build (`mvn -q -pl no-sneak-core,no-sneak-app -am test`), leave staging and commits to the maintainer.

## Goal
A subject can save named sets of probes ("groups"), manage them (create, edit, delete), and when
setting up a scan pick a whole group or individual probes. A group is a convenience over the
existing ticks — it never reaches the engine and never changes what a report stores.

## Invariants (do not break)
- `tickedProbes` (keys `b:<name>` / `s:<guid>`) remains the only source of probing.
  `ProbeSelection.applyTo` and the report's `probes` csv are untouched.
- No chip = no probing. Ticking a group ticks its probes; the chips stay individual probes.
- Groups store probe **names** (csv), resolved at use time by `ProbeSelection.keysForNames`
  (bundled first, then mine by name, unknown dropped) — identical to *Scan again*.
- Canonical identity entity is **subject**. Groups are subject-scoped like probes.
- All list/parse logic is pure and headless-testable; Swing only in `ScanPanel`.
- Icons: Feather/Lucide SVG, `stroke=currentColor`. Tokens from `UITokens`.

## Decisions taken (defaults — override if wanted)
- Groups are managed under the **Probe library** (a *Groups* button in its bar), not a new sidebar
  item. Navigator / MenuBarFactory untouched.
- No bundled (read-only) groups in this pass. Leave a seam: the group table model accepts a
  `bundled` list so presets can be added later from a core JSON resource.

---

## Step 1 — Data entity (no-sneak-core)
`xlogistx-scan`
- `extends PropertyImpl`, mirror `ProbeType` exactly.
- `Param.PROBES` → NVConfig `"probes"` (String, csv of probe names).
- `NVC_PROBE_GROUP_CONTENT = new NVConfigEntityPortable("probe_group", null, "ProbeGroupContent", …)`.
- Name and description come from the DAO base (`setName` / `setDescription`).
- `getProbes()` / `setProbes(String csv)`, plus `List<String> probeNames()` (trimmed, non-empty, order kept).
- Backup/Restore is whole-store → nothing to register.

## Step 2 — Session (no-sneak-app `ui/utility/Session.java`)
Next to the probe methods (~L1025):
- `ProbeGroupContent saveProbeGroup(ProbeGroupContent g)` — GUID present → `setLastTimeUpdated`, `ds.update`; else `setSubjectGUID`, `ds.insert`.
- `void deleteProbeGroup(ProbeGroupContent g)` — `ds.delete(g, true)`.
- `ProbeGroupContent getProbeGroup(String guid)` — `userSearchByID`.
- `List<ProbeGroupContent> getAllProbeGroups()` — `userSearch(subject, NVC, null)`; empty when signed out.

## Step 3 — Pure model (no-sneak-app `ui/scan/ProbeGroupModel.java`)
`AbstractTableModel`, Swing-free except the contract. Columns: **Name · Probes · Description**
(`Probes` = resolved count, e.g. `4` or `4 (1 missing)`).
Static helpers:
- `Set<String> memberKeys(ProbeGroupContent g, List<ProbeDefinition> bundled, List<ProbeType> stored)` → `ProbeSelection.keysForNames(g.getProbes(), bundled, stored)` (make `keysForNames` package-visible or move it; keep one implementation).
- `List<String> missing(g, bundled, stored)` → names that resolve to nothing.
- `String csvFromTicks(Set<String> ticks, bundled, stored)` → names of ticked probes in catalog order (bundled by priority/name, then mine) — inverse of `memberKeys`.
- `ProbeGroupContent existingByName(List<ProbeGroupContent>, String name)` (case-insensitive, GUID present).
- `String validate(String name, String csv)` → null when OK, else the reason (blank name, no probes).
- `boolean matches(ProbeGroupContent g, String query)` → name, description, any member name.

## Step 4 — Scan page: pick a group (`ScanPanel`)
In `showProbeMenu()` add a **GROUPS** section *above* Bundled probes (same `addProbeGroup`-style header):
- One `JCheckBoxMenuItem` per group; checked iff `memberKeys` non-empty and `tickedProbes.containsAll(memberKeys)`; tooltip = member names (missing ones suffixed ` (missing)`).
- Tick → `tickedProbes.addAll(memberKeys)`; untick → `removeAll(memberKeys)`; then `refreshProbeChips()`.
- Group with missing members: tick what exists, show inline note via the form's existing inline message: `Group "<name>": <n> probe(s) no longer exist`.
- Empty state item (disabled): `No groups yet — save ticked probes as a group`.
- Footer (after a separator): **Save ticked as group…** — enabled only with ≥1 tick; small dialog for name (+ optional description); existing name → update that row; then `reloadProbeGroups()`.
- `resetPanel()`: `probeGroups = List.of()`; `onAuthChange` login → `reloadProbeGroups()` alongside `reloadProbes()`.
- `reloadProbeGroups()` via `BackgroundTask.run` (off the EDT), like `reloadProbes()`.

## Step 5 — Probe library: manage groups (`ScanPanel`)
- Library bar: add **Groups** button (icon `layers` or `folder`) → `cardStack.show("Probe_groups")`.
- New card `Probe_groups` (`buildProbeGroupsPanel`), same shape as the library: head (title *Probe groups*, back link *Probe library*, primary **New group**), bar (search, count), split card — table on `ProbeGroupModel` left; right a `CardStack`: *howto* when nothing selected (what a group is, two ways to make one: here, or *Save ticked as group* on the Scan page) and *group* for a selected row: name + **Edit** / confirmed **Delete** on the header row, `KeyValuePanel` (Description, Probes count, Missing), then the member list (one line per name, `BadgeLabel` *mine* / *bundled* / *missing*). Double-click = Edit. Selection survives reload by name.
- New card `Edit_probe_group` (`buildEditProbeGroup`, `openGroupEditor(group|null)`): Name field, Description field, search box, checklist of every probe (two sections Bundled / Mine with an *All* each — reuse `probeRows()`), live count label, `InlineMessage` for validation, **Save** / **Cancel**. Save → `ProbeGroupModel.validate`, dedupe by name, `session.saveProbeGroup`, reload, back to `Probe_groups` with the row selected. Failure → modal, draft stays.
- Delete → `BackgroundTask.runCatching(… deleteProbeGroup …, reload)`.

## Step 6 — Tests (headless)
- `ui/scan/ProbeGroupModelTest`: rows & columns, `memberKeys` bundled-first/mine/unknown-dropped, `missing`, `csvFromTicks` ↔ `memberKeys` round trip and ordering, `existingByName` case-insensitivity, `validate`, `matches`.
- `ScanPanelTest` additions: ticking a group adds exactly its keys and nothing else; unticking removes only its keys (other ticks survive); a group whose members are all gone ticks nothing and notes it; *Save ticked as group* yields the expected csv; `resetPanel` clears groups.
- `SessionProbeGroupTest` (pattern of `SessionScanHistoryTest`): save/update/delete, list is subject-scoped, empty when signed out.

## Step 7 — Docs (keep in step, same day)
- `no-sneak-app/CLAUDE.md` → *ScanPanel* section: groups in the Add probe popup, *Save ticked as group*, the `Probe_groups` / `Edit_probe_group` cards, the names-not-keys rule, the tests that pin it.
- `app-description.md` (Help) → Probe library paragraph: groups, and the Scan paragraph: pick a group.
- `PENDING-ISSUES.md` → close/add as applicable.

## Order & checkpoints
1. Steps 1–3 + `ProbeGroupModelTest` → green.
2. Step 4 + `ScanPanelTest` → green; manual run: tick a group, chips appear, Ports placeholder updates, run scans, report `probes` lists the names.
3. Step 5 → manual run: create / edit / delete, missing badge after deleting a member probe.
4. Step 6 remaining tests, Step 7 docs.

## Out of scope (this pass)
Bundled preset groups; a group chip in the chip strip; exporting/importing groups; engine changes.
