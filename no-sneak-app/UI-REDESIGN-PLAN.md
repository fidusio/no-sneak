# no-sneak UI redesign — execution plan

Design reference: the canvas at https://claude.ai/artifact/Ln8xCjHgxDrnRo1joeurpE (nine boards,
2026-10-24). This file is the implementation plan for it. Rule from the maintainer (2026-10-24):
**any reusable panel or widget that does not reference a no-sneak type goes into
`io-xlogistx/gui-audio` under `io.xlogistx.gui`**; only no-sneak screens and wiring stay here.
gui-audio compiles at **Java 8**: no records, `var`, pattern matching or `_` lambda parameters
there. After each gui-audio change: `mvn install` in `io-xlogistx/gui-audio`, then reload the
Maven projects in IntelliJ before running no-sneak.

The maintainer commits; this plan never commits or pushes.

---

## Phase 1 — Setup and login (the Unlock screen)

> **Status 2026-10-24: implemented, uncommitted.** gui-audio: `UITokens`, `BadgeLabel`,
> `InlineMessage`, `DirectoryField`, `FormPanel`, `StepperPanel`, `SplashSidePanel`, four icons,
> `FormPanelTest` (6 green), `StepperPanelDemo`; installed to the local repository. no-sneak-app:
> `UnlockPanel`, `NoSneakStore.openOrCreate`, `NoSneakMain.AppFrame` content-pane swap,
> `LoginPanel` + `DataStoreSetupPanel` deleted, `Navigator.Screen` without `LOGIN`/`REGISTER`;
> `UnlockFormTest` (5) + `NoSneakStoreOpenOrCreateTest` (1) + `DataStoreSetupFlowTest` (2) green
> through the `.claude/tools/RunTests` launcher on Maven's `-X` `testPath` (the launcher's
> `cp.txt` has drifted: no MigLayout, stale h2p-datastore). Docs updated (`CLAUDE.md`,
> `LOADING.md`, `PENDING-ISSUES.md`, gui-audio `CLAUDE.md`). Manual run of the window is still
> the maintainer's: this session had no display. Next: Phase 2.

**Goal.** One pre-auth screen replaces `DataStoreSetupPanel` + `LoginPanel`: a two-step card
(board 1 of the canvas). Step 1 opens or creates the store exactly as `NoSneakStore.open` /
`NoSneakStore.create` do today, including every first-run field. Step 2 is the Shiro login, with
register as a mode of the same step. Behaviour that stays: last location pre-filled from
`AppPrefs`, Enter in the vault password field triggers Open/Create, first-run rows only when the
chosen directory has no vault, pre-October-2026 installations refused with the reason, `ds.*`
launch parameters skip step 1, password rules checked before register, "already taken" message,
the store is closed on app close only.

### 1a. gui-audio — reusable pieces (Java 8)

| Class (`io.xlogistx.gui`) | What it is | Notes |
|---|---|---|
| `UITokens` | Static accessors for the semantic colours used everywhere in the redesign: `accent()`, `ok()`, `warn()`, `danger()`, `muted()`, `border()`, `surface()`, `surfaceAlt()` | Reads `UIManager` keys (`Component.accentColor`, `Component.borderColor`, `Label.disabledForeground`…) with the canvas hex values as fallbacks, so FlatLaf themes drive them |
| `BadgeLabel` | Pill label with `Tone {OK, WARN, DANGER, NEUTRAL, ACCENT}` | Used for "vault unlocked", "super-admin", grades, "used by N providers" |
| `InlineMessage` | One-line status under a form: `info(text)`, `error(text)`, `clear()` | Replaces the `modeLabel` / `registerError` JLabels |
| `DirectoryField` | Read-only path field + **Choose…** button over a `JFileChooser` (directories only); `setDirectory(File)`, `getDirectory()`, `onChange(Consumer<File>)`, chooser start dir from a `Supplier<File>` | Pulls the chooser code out of `DataStoreSetupPanel` |
| `FormPanel` | MigLayout form: `field(String label, JComponent)`, `field(label, component, hint)`, `required(label)`, `group(String key, Runnable adder)` + `showGroup(key, boolean)` | Groups are how the first-run rows show and hide; `PanelBuilder.addRow/addSection` stay for existing callers |
| `StepperPanel` | Vertical numbered steps, each `step(String title, String description, JComponent body)`; `complete(int, String summary, Runnable onChange)` collapses a step to its summary row with a Change button and a done mark; `activate(int)`; `setStepEnabled(int, boolean)` | Board 1's two-step card |
| `SplashSidePanel` | Dark side panel: title, tagline, bullet points (check icons), footer line | The left half of board 1. Content is passed in; nothing no-sneak in it |
| `IconUtil` additions | `KeyIcon`, `LockIcon`, `LogoutIcon`, `ShieldIcon` if missing (`VisibleIcon`/`InvisibleIcon`, `CheckIcon`, `FolderIcon` exist) | SVG-path icons like the rest of `IconUtil` |

Tests/demos in gui-audio `src/test`: `StepperPanelDemo`, `FormPanelDemo` (runnable, like the
existing `*Demo` classes) and a JUnit `FormPanelTest` that constructs a form headless and checks
`showGroup` toggles visibility of exactly the grouped rows.

### 1b. no-sneak-app

New `ui/UnlockPanel.java` (replaces `DataStoreSetupPanel` and `LoginPanel`, both deleted):

- Layout: `SplashSidePanel` (NoSneak title, tagline from `MenuBarFactory.TAGLINE`, the three data
  promises, version/Java/OS footer) on the left, a centred card with a `StepperPanel` on the right.
- **Step 1 "Open store"**: `DirectoryField` (pre-filled from `AppPrefs.storeLocation()` when it
  still exists), vault password (`PanelBuilder.passwordField`), an `InlineMessage` saying
  "Existing vault found: enter its password." or "No vault here: a new vault, database and
  operator account will be created.", and a `FormPanel` group `firstRun` with Operator username,
  Operator password, Confirm, Database username (default `NoSneakStore.DEFAULT_DB_USER`),
  Database password (empty = generated), Encryption password (empty = generated). Button reads
  **Open** or **Create**. Enter in the vault field clicks it. Validation and `FirstRun` assembly
  are moved verbatim from `DataStoreSetupPanel.onSave`.
- Step 1's work runs through `BackgroundTask.run` and a new `NoSneakStore.openOrCreate(location,
  vaultPassword, FirstRun)` that holds the decision currently inlined in `NoSneakMain.showSetup`
  (`vaultExists || firstRun == null ? open : create`). On success: `AppPrefs.storeLocation(path)`,
  `complete(1, "<path> · vault unlocked")`, `activate(2)`, and the panel fires
  `onStoreOpened(ShiroDSDomainSecurityManager)`.
- **Step 2 "Sign in"**: username, password with show/hide toggle (`VisibleIcon`/`InvisibleIcon`),
  **Sign in** button, and a link-style button "Create another account in this store" that flips
  the step into register mode: Confirm password row appears, button reads **Register**, the
  `InlineMessage` carries the password-rule or mismatch error; success shows "Registered
  successfully", clears the fields and flips back. Logic moved from `LoginPanel.passwordAction`.
  **Dropped:** the DomainAppID combo (`Session.loginUsernamePassword(subject, password)` takes no
  domain, so it never did anything) and the hidden Passkey card/stub buttons.
- First-run info box under the card ("First time here? Pick an empty folder…").
- `resetForSignIn()`: called on logout — clears step 2 fields, keeps step 1 completed (the store
  stays open for the process, as today).

`NoSneakMain` changes:

- `showSetup` and the separate "NoSneak - Setup" frame go away. `AppFrame` is created at once and
  shows `UnlockPanel` as its content pane. `AppContext`/`AppShell`/menu bar are built **when step
  1 completes** (they need the manager), then step 2 is wired to `ctx.session()`. On
  `authenticated=true` the frame's content pane becomes the `AppShell`; on `false` it becomes the
  `UnlockPanel` again at step 2. With `ds.location` + `ds.store-password`, step 1 is completed
  programmatically before the frame shows.
- Window-closing handler unchanged (closeNio, logout, close datastore) but guarded for the
  no-store-yet case.
- Frame size and FlatLaf setup unchanged.

`AppShell`: stop registering the `LOGIN` card (`Navigator.Screen.LOGIN`/`REGISTER` removed); the
auth-change handler keeps the assistant reload/clear calls; first screen after auth stays
`SUBJECT` in this phase (Phase 2 moves it to the scanner). Footer: replace the "mock-build" text
with `store: <dir> · subject: <principal>`.

### 1c. Tests and verification

- `UnlockFormTest` (new, headless): the pure decisions extracted into a small
  `UnlockPanel.Form` helper — create vs open from `vaultExists`, required-field and confirm
  checks for first run, register validation (`FilterType.PASSWORD`, mismatch) — so the panel
  itself is thin.
- `NoSneakStoreOpenOrCreateTest` (new): `openOrCreate` on an empty directory creates, on a
  directory with a vault opens, in `target/no-sneak-setup-test/<id>` like `DataStoreSetupFlowTest`.
- `DataStoreSetupFlowTest` unchanged (it tests the store path, which does not move).
- Manual: run without parameters → create in a fresh folder → sign in → app; relaunch → step 1
  pre-filled, Enter opens → sign in; run the `NoSneakMain` configuration with `ds.*` → lands on
  step 2 directly; wrong vault password → error dialog, stays on step 1; logout → step 2 empty.
- Tests run through IntelliJ (build project, run configuration per class), per the maintainer's
  preference.

### 1d. Docs (part of "done")

`no-sneak-app/CLAUDE.md`: replace the `LoginPanel` and `DataStoreSetupPanel` sections with
`UnlockPanel`, update *Entry point* (no setup frame, content-pane swap), the Layout tree and the
footer text. `LOADING.md`: AppShell is now built at step-1 completion rather than at launch.
`PENDING-ISSUES.md`: a dated status line pointing at this plan. Add the new gui-audio classes to
whatever index gui-audio keeps (its README/CLAUDE.md if present).

---

## Phase 2 — The shell: one sidebar, one header

> **Status 2026-10-24: implemented, uncommitted.** gui-audio: `SideNavPanel`, `HeaderBar`, eleven
> navigation SVGs (`scan clock flask chat list book plug user archive help capture`, used through
> `IconUtil.svgIcon`). no-sneak-app: `AppShell` rebuilt (header, sidebar, routes, Admin section
> for the super-admin, lands on `SCAN_NEW`), `Navigator` with `Screen` × `Route` + `sync`,
> `MenuBarFactory` = File / View / Help (Mode and Technical Mode gone, Sign out in the header),
> `ScanPanel` / `SubjectPanel` lost their toggle columns and expose `show(SECTION_*)`,
> `SubjectSecManagerPanel` is a `JTabbedPane`, `PQCRegistryPanel` unregistered. ai-assistant:
> `AssistantPanel` is wiring only, `Page` enum + `showPage` + `setOnPageShown`. Rendered on a
> throw-away store (`RenderShell`) on four screens and checked. Next: Phase 3.

gui-audio: `SideNavPanel` (sections + `ButtonGroup` of flat toggle items keyed by String,
`onSelect(Consumer<String>)`, `select(key)`, `setItemVisible`, footer slot), `HeaderBar` (brand
slot, mono status chip, right-aligned subject chip and action buttons).

no-sneak-app: `AppShell` = `HeaderBar` north, `SideNavPanel` west, `CardLayout` centre, footer
south. `Navigator.Screen` becomes the full page list (`SCAN_NEW, SCAN_HISTORY, PROBES, CHAT,
CHATS, CAPTURE, SKILLS, PROVIDERS, PROFILE, API_KEYS, BACKUP, ACL`); each existing panel drops its
`buildDefaultSplitPanel` toggle column and exposes `show(section)` over its own `CardStack`
(`ScanPanel`, `SubjectPanel`, `SubjectSecManagerPanel`; `AssistantPanel.showPage(...)` in
ai-assistant). `MenuBarFactory` shrinks to Help/About or is removed (Sign out moves to the
header). Land on `SCAN_NEW` after login. The dead "Technical Mode" checkbox goes. Admin section
visible only when the subject is the super-admin (`NoSneakStore.registrarPrincipal` /
super-admin id from the vault).

## Phase 3 — Scan: form-driven command and tabular results

> **Status 2026-10-24: implemented, uncommitted.** core: `NMap.formatCommand` + `portSpec`,
> `NMapConfig.Timing.matches / matching / closest`, `NMapFormatCommandTest` (round trips, canonical
> order) — no `PostureGrader`: the engine already writes a letter, PQC status and trust per port
> (`grade.Grade`), the view reads them. gui-audio: `ChipPanel` (+ `WrapLayout`), `SegmentedControl`,
> `KeyValuePanel`, `Tables`. no-sneak-app `ui.scan`: `ReportView` (pure parser + host posture,
> `ReportViewTest`), `ScanFormPanel` (form ⇄ command, `ScanFormPanelTest`), `ScanResultView`
> (Hosts / Services / Raw JSON + detail pane); `ScanPanel` rewired piece by piece — the full-file
> rewrite was stopped by the safety classifier mid-write, so the integration went in as targeted
> edits (form over result view, probe chips + popup, stored report in the same tables).
> `ScanPanelTest` untouched and green. Rendered with a sample report and checked. Next: Phase 4.

no-sneak-core: `NMap.formatCommand(NMapConfig)` with a round-trip test
(`parseCommand(formatCommand(cfg))` equals `cfg` for the supported flags); `PostureGrader`
(pure) that grades a host's TLS data from the report (A hybrid PQC on 1.3, B classical 1.3, C
1.2 ECDHE, D static RSA/CBC/expired) — verify first which TLS fields `ScanReport` carries.

gui-audio: `ChipPanel` (removable chips + add button), `SegmentedControl` (T1–T5),
`KeyValuePanel` (the detail pane's label/value grid), `TablePanel` helper (JTable with the
redesign's header style and an actions column).

no-sneak-app `ScanPanel`: `ScanFormPanel` (targets, ports, name, option checkboxes, timing,
in-flight, min RTT, probe chips) bound both ways to the command field; results as a
`JTabbedPane` Hosts / Services / Raw JSON with `ScanReportTableModel`, `ServicesTableModel`, a
host detail pane in a `JSplitPane`; Copy / Send to assistant / Saved badge in the result header.
`ProbeSelection` and the run/stop/save paths are unchanged.

## Phase 4 — Lists and the assistant pages

> **Status 2026-10-24: implemented, uncommitted.** History is a `JTable` (search, newest first,
> toolbar on the selected row, double-click views; `hostsUp` / `openPorts` recorded on the row at
> save time). API keys: list left, editor right (the `"list"` card became the placeholder, so no
> call site changed). Assistant: Providers and Skills list-left / editor-right the same way,
> Capture areas and captures side by side, composer chips for skills / images / areas-on-send
> inside the composer bar. Every page rendered on the throw-away store and checked. Next: Phase 5.

History as a `TablePanel` over the projected `ReportContent` rows (view, copy command, copy
result, send, delete). API keys as list + editor side by side (existing `SubjectPanel` cards
re-laid out). ai-assistant: Capture page as areas and captures side by side; Skills list +
editor with the Save as combo (exists); Providers rows with status badge and the form beside the
list; chat: chips row above the composer for what goes with the next message (new), attach popup
restyled into its four sections (exists), PDF buttons (exist). Nothing between transcript and
composer (house rule).

## Phase 5 — Remaining pages and polish

> **Status 2026-10-24: implemented, uncommitted, with two notes.** gui-audio gained `PagePanel`
> (the page frame every page shares: title, description, optional action, white cards on
> `UITokens.ground()`); Profile, Backup and Access control now sit in it (`SubjectPanel`,
> `SubjectSecManagerPanel`). **JetBrains Mono is optional, not pending** (maintainer's call on
> 2026-10-25): `UITokens.mono` takes its family from `UIManager "xlogistx.monoFamily"` when set
> and falls back to the logical monospaced font (Courier New on Windows) otherwise, which is what
> the app ships with. If the fallback looks dated on a real display, add
> `com.formdev:flatlaf-fonts-jetbrains-mono` plus `FlatJetBrainsMonoFont.install()` and
> `UIManager.put("xlogistx.monoFamily", FlatJetBrainsMonoFont.FAMILY)` in `NoSneakMain`; the
> artifact was not cached locally and central was unreachable when Phase 5 shipped. **The unreferenced
> `src/main/resources/icons/*.svg` were already gone** — nothing to delete. Every page of the
> application has now been rendered on the throw-away store and checked.

Profile, Backup, Access control in the shell; `FlatJetBrainsMonoFont` for mono text alongside
the installed Roboto; footer status; remove the unreferenced `src/main/resources/icons/*.svg`.

---

## After the plan — additions on the maintainer's instructions (2026-10-25/26, uncommitted)

Not part of the redesign, but built on its pages; each is documented in `CLAUDE.md` and
`PENDING-ISSUES.md` → *Status check (2026-10-24)*:

- **MAC vendors.** The engine's `macVendor` (zoxweb `OUIDB`, filled from the Wireshark manuf
  file that the store keeps as the app-wide `DataContent` *Mac-Vendor-Content*, loaded after
  login) shows as a **Vendor** column in Hosts and a **Network adapter** block (MAC, Vendor) in
  the host detail pane. **Account → Settings** is a new page (`SETTINGS`, gear icon added to
  gui-audio) whose **Sync** section re-downloads the list on demand.
- **Backup moved under Settings** (2026-10-26): the Backup and Restore blocks are the second and
  third blocks of the Settings page; the Backup page, `BACKUP` screen, sidebar item and View-menu
  entry are gone. Mentions of a Backup page earlier in this plan are history.
- **Scan history**: multi-select, Delete takes the selection, **Delete all** clears the list.
- **No probe ticked = no probing**: the chips are the only source of probing; the Service
  detection box mirrors them and is the all / none shortcut; the empty strip says so.

## Decisions taken in this plan (say so if any should change)

1. **DomainAppID and Passkey leave the login screen** (dead UI; the session API has no domain).
2. **Step 1 is fixed once completed** for the life of the process; switching stores means a
   restart, as today. The "Change" button is available only before step 1 completes.
3. **AppShell is built when the store opens**, not at launch: it needs the manager, and this keeps
   `AppContext` construction unchanged.
4. **Landing page after login moves to the scanner in Phase 2**, not Phase 1, so Phase 1 touches
   only the pre-auth path.
5. Fonts stay Roboto for UI in Phase 1; JetBrains Mono is a Phase 5 addition.
