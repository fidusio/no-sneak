# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak assessment tooling. Contains the application entry point
and the **`ui`** package that wires together the screens, navigation, and the session/access
layer. It began as a UX prototype but now runs a **real** session/access layer and a **working
network scanner screen** over `no-sneak-core`; the PQC file-sharing screen is still a placeholder.

> **2026-10-25/26 — after the redesign (uncommitted).** Four additions on the maintainer's
> instructions, each documented in its section below and in `PENDING-ISSUES.md` → *Status check
> (2026-10-24)*: **MAC vendors** — after a login `Session.loadMacVendors()` finds or downloads the
> Wireshark manuf file as the store's app-wide `DataContent` *Mac-Vendor-Content* and loads it into
> `NSNetUtil.MAC_VENDORS`, so the engine's `mac` / `macVendor` show as MAC and Vendor columns (MAC since 2026-10-27) and a *Network
> adapter* block; *Account → Settings → Sync* (`SECTION_SETTINGS`, `syncMacVendors`) refreshes it on
> demand, and since 2026-10-26 **Backup and Restore are blocks of that Settings page** (the
> separate Backup page, `BACKUP` screen and sidebar item are gone). **Scan history** is
> multi-select, Delete takes the selection and *Delete all* the whole list. **No probe ticked = no probing**: the chips are the only source of probing, the Service
> detection box is their all / none shortcut, and the engine probes nothing for a tick set that
> matches nothing. **The Probe library** (2026-10-26, "the bundled probes can't be read, and it
> doesn't explain how to create one") is a table of every probe, bundled and stored, with a
> read-only detail pane, a how-to block, an editor with inline Check, the probe definition
> (`PROBE-DEFINITION.md`) shown in the app, and *Write with the assistant* (the definition
> attached, the request typed, *Save as probe* on the reply) — see *ScanPanel* below. Live
> checks still owed by the maintainer are listed in `PENDING-ISSUES.md`.
>
> **2026-10-24 — UI redesign, Phase 1 (setup and login).** The maintainer asked for a more
> intuitive UI, reviewed the nine-board design canvas, and approved the execution plan in
> **`UI-REDESIGN-PLAN.md`** (read it before continuing the redesign). Phase 1 is done: one window
> from the start, whose content pane is the new **`UnlockPanel`** — step 1 opens or creates the
> store (every `DataStoreSetupPanel` behaviour kept, through `NoSneakStore.openOrCreate`), step 2
> signs in or registers — until the session authenticates, when `NoSneakMain.AppFrame` swaps in
> the `AppShell`; `LoginPanel`, `DataStoreSetupPanel`, the setup frame, the DomainAppID combo,
> the passkey stub and the favicon fetch are gone. The reusable pieces (`StepperPanel`,
> `FormPanel`, `DirectoryField`, `InlineMessage`, `BadgeLabel`, `SplashSidePanel`, `UITokens`,
> four icons) went into **io-xlogistx/gui-audio** per the maintainer's rule: *generic panels go to
> xlogistx-gui-audio, only no-sneak screens and wiring stay here.* Phases 2–5 (sidebar shell,
> form-driven scan with tabular results, lists and assistant pages, polish) followed the same day
> and the next; the plan file carries a status block per phase, and the redesign was committed on
> 2026-10-25.
>
> **2026-10-21 — the store follows the datastore's deployment model.** User instruction: *the
> model how to set up the local H2 database changed, read it from the datastore project*. The
> model (zoxweb-datastore `h2p-datastore/CLAUDE.md` → `H2PSetup`, `ShiroIniRealmMain`; io-xlogistx
> `shiro`): a deployment is a vault with **mandatory** `master-key`, `super-admin-id`,
> `super-admin-password`, `db.url` (+ `db.*`, `app-id`), set up once by `H2PSetup command=create`
> (vault, H2 file, `bootstrap-super-admin`, `create-app`, `shiro.ini`); at run time the application
> sets nothing up — vault → key maker → store with controller, registered under
> `ResourceManager.Resource.DATA_STORE` → `ShiroUtil.loadSecurityManager(shiro.ini)` as the global
> security manager → `ShiroDSDomainSecurityManager.fromGlobal(store)` (attached) with the
> super-admin id from the vault; and a login scoped to an app passes only with `app:login` in that
> app (the **app login gate**, user rule 2026-10-20: `app_user` carries it, the super-admin's
> wildcard applies everywhere). Absorbed here, superseding the 2026-10-05 block below where they differ:
>
> - **`NoSneakStore`**: an installation directory holds `no-sneak.store`, `no-sneak.mv.db` and
>   **`shiro.ini`**. `create(location, vaultPassword, FirstRun)` = `H2PSetup command=create`
>   in-process (`db.path` = the directory, `db.name=no-sneak`, `CIPHER=AES`,
>   `app.id=xlogistx.com-nosneak`, INI beside the vault); the **operator typed on the setup screen
>   is the super-admin** (`FirstRun.adminID` / `adminPassword`, password rules enforced first);
>   an empty DB password / encryption password is generated and lives only in the vault; the
>   app's registrar `registrar.xlogistx.com-nosneak` (owner + `app_admin` of the app, "the app
>   super-admin", user 2026-10-21) gets the **operator's password** as a login beside its JWT
>   (`setRegistrarPassword`, kept when one exists; `registrarPrincipal(dsm)` names it); the
>   registrar's signing key the set-up prints once is discarded. `open(location, vaultPassword)` is the
>   run-time model above; it refuses a vault lacking a mandatory entry (an installation from before
>   this model) or a missing INI, verifies the no-sneak app exists, seeds nothing. `bootstrap` is
>   kept for stores not set up by `H2PSetup` (mock-store tests, `createDomainSecManager`).
>   `grantAppUser(dsm, subject)` gives the app's `app_user` role, idempotently.
> - **`Session.registerUsernamePassword`** grants `app_user` after `createSubjectID` — without it
>   the realm refuses the scoped login. `loginUsernamePassword` passes the password as `char[]`
>   (the `String` token constructor is deprecated upstream).
> - **`DataStoreSetupPanel`** on a directory without a vault asks for the operator username,
>   password + confirmation, DB user (default `sa`), DB password and encryption password (empty =
>   generated); its factory takes a `NoSneakStore.FirstRun` (null = open).
> - Tests: `TestSecurity.createUser` (create + grant) in the eight mock-store suites;
>   `DataStoreSetupFlowTest` rewritten on the new path (vault entries, INI, attached manager,
>   operator login, registrar password login, ungranted subject refused, sign-up login,
>   isolation, wrong password, reopen,
>   a refusal case), in `target/no-sneak-setup-test/<id>` because the set-up's URL carries
>   `DB_CLOSE_DELAY=-1` (a `@TempDir` cleanup would hit the locked file). **79 / 79** through
>   IntelliJ, 10 classes. Installations written before this session are refused by `open` with
>   the reason: the `/data/ds` one in the IntelliJ run configuration `NoSneakMain` is one of them.
>
> **2026-10-05 — the app runs on the Shiro manager, through a vault.** The upstream "major
> code update" of that day (zoxweb-core deleted `DomainSecurityManagerDefault`; the Shiro manager,
> realm and `SecuritySetup` moved from `zoxweb-datastore/xlogistx-shiro-ds` into io-xlogistx's
> `shiro` module; the h2p store refuses every connection without a `SecurityController` **and** a
> `KeyMaker` holding the master key) is absorbed here. What changed, in one place each:
>
> - **`NoSneakStore`** (new, beside `NoSneakMain`) is how the store opens. An installation is a directory
> with `no-sneak.store` (an opsec `SecretStore` vault: AES master key `master-key` + `db.url` /
> `db.user` / `db.password` / `db.enc-password`) and the encrypted H2 file `no-sneak.mv.db`.
> `create(location, vaultPassword, dbUser, dbPassword, dbEncPassword)` is the first run (writes
> the vault, then opens); `open(location, vaultPassword)` is every later run — the vault password
> is the one secret the subject types. Both load the master key into `KeyMakerProvider.SINGLETON`,
> put the `ShiroSecurityController` + that key maker on the `APIConfigInfo` (`secure`), connect,
> and `bootstrap` the manager: catalog seeded, the app **`xlogistx.com-nosneak`** created when
> missing (its registrar + sealed key are left unused), Shiro session timeout set to never. No
> super-admin, no `super-admin-id` in the vault: a desktop store has one operator and permission
> enforcement stays off. `NoSneakMain` takes `ds.location=` + `ds.store-password=`; the setup screen
> shows the three database fields only while the chosen directory has no vault.
> - **`Session` logs in a Shiro `Subject`, unbound** (`loginUsernamePassword` builds the subject on
>   the manager's security manager and logs it in with a `DomainUsernamePasswordToken` scoped to the
>   no-sneak app; the manager has no password variant of `loginUnboundSubjectJWT`, so the four
>   lines live here). The store checks every row against the *thread-bound* subject and the panels
>   work on `SwingWorker` threads, so `Session.getDataStore()` is a **`Proxy` over the store that
>   wraps each call in xlogistx-shiro's `SubjectSwap`** of the kept subject; `asSubject(...)` does
>   the same for arbitrary work and `runAsSystem(...)` lifts the check for the backup/restore
>   dump. `AssistantStorage` reads that view, never the manager's raw store. `logout` ends the
>   subject. Manager calls need no binding (system view inside, enforcement off).
> - **No API-key login anywhere.** `Session.loginAPIKey` and the login screen's API-key card are
>   gone; the manager refuses `loginApiKey`. A third-party key's vendor domain/app is **metadata**
>   (`APIKeyInfo.VENDOR_DOMAIN` / `VENDOR_APP`, read with `vendorDomainOf` / `vendorAppOf`): the
>   key's own `app_id` is an app-model scope the Shiro manager resolves to an app record of this
>   store, which a vendor's app never is — that closed the 3 failing `APIKeyRoundTripTest` cases. A
>   key no-sneak issues keeps the `xlogistx.com-nosneak` scope, not editable.
> - `registerUsernamePassword` says "already taken" only for a duplicate; any other failure
>   carries the store's own reason (the principal filter wants ≥ 8 characters — `alice` is refused).
> - Tests: `TestSecurity` (throw-away vault key, mock store configured like the real one,
>   `NoSneakStore.bootstrap`) under the 7 round-trip suites, and **`DataStoreSetupFlowTest`** —
>   the proof on a real vault + encrypted H2 file with the controller on: two users, rows and a
>   sealed key saved and read from pool threads, the second user sees nothing, logout leaves no
>   thread bound, wrong vault password = no store, reopen through the vault. **78 / 78** through
>   the `.claude/tools` launcher (its `cp.txt` moved to JUnit 6.1.3). Plan and upstream log:
>   `zoxweb-datastore/h2p-datastore/no-sneak-plan.md`.
>
> **Status.** The session layer (`ui.utility.Session`) is backed by io-xlogistx's
> **`ShiroDSDomainSecurityManager`** over an **encrypted H2** `H2PDataStore`
> (`jdbc:h2:file:<dir>/no-sneak;MODE=PostgreSQL;CIPHER=AES`, built by `H2PDSCreator`), opened
> through the installation's vault and `shiro.ini` (`NoSneakStore`, manager attached to the INI
> realm since 2026-10-21). `NoSneakMain` opens the store from either `ds.*` launch parameters or
> the first-run **Data Store Setup** screen. The store **persists across restarts**; the first run
> (`H2PSetup`) seeds the catalog, creates the no-sneak app and **one account, the operator's**
> (the super-admin) — further accounts register from the login screen.
>
> Working end-to-end: username/password **register + login**, **change password**,
> **add/remove identifiers**, **profile save/load** (name/DOB), a **multi-address book**, and the
> **third-party API-key lifecycle** (generate or import → edit → rotate → delete; never a login).
> API keys are **sealed at rest** by the store (an `ENCRYPT` field under the owner's key chain) and
> served in clear to their logged-in owner; imported keys also carry AI-assistant metadata
> (`provider`, `base-url`, `auth-type`, `header-name`, `vendor-domain`, `vendor-app`) on their
> property bag. All blocking `Session` calls run **off the EDT** via `BackgroundTask.runCatching`
> (failures surface as a dialog from the thrown `AccessSecurityException`).
>
> **The `SCAN` screen is real now.** `ScanPanel` fronts the `no-sneak-core` engine: the command
> box takes the full `NMap` CLI surface through `NMap.parseCommand`, a probe selector ticks
> bundled and subject-authored probes into the run, results persist as `ReportContent` rows, and
> probes persist as `ProbeContent` rows (both DAOs live in `no-sneak-core`'s
> `io.xlogistx.nosneak.data`). It is also wired to the assistant **both ways** — a scan result
> can be sent into a chat, and a chat response can be saved back as a probe. See `ScanPanel` below.
>
> **Still stubbed:** passkey (login/register are empty `void` no-ops), the ACL admin
> tables, the PQC file-sharing screen, and — in the AI assistant — the Job-queue page and
> the multi-model compare path. (The assistant's provider discovery,
> the user-picked provider flow — a provider is now its own persisted **`AIProviderConfig`**
> record borrowing a credential by GUID, so one key can back several providers and
> `assistant-enabled` is derived from whether any config still uses it — single-provider chat
> send **with message persistence** and rendered markdown replies, per-message skill attachment,
> the **screen-capture page** (multi-monitor drag-select, reusable areas, persisted `AICapture`
> rows) with **multi-image attachment** from the composer, and full
> **History + Skills + Provider CRUD** are wired now — see `ai-assistant/CLAUDE.md`.)

**`LOADING.md`** (this directory) maps *when* the running app does work — what is built or fetched
eagerly at startup and login, what is deferred, and what is re-queried on every call — across
`no-sneak-app` + `ai-assistant` + `ai-model`. Read it before diagnosing startup or login latency,
a stale list, or before adding another projected store read; its §5 is the set of rules those
decisions have to keep.

## Data boundary

Two properties this module owns, and every screen has to keep them: **the store is encrypted and
opened with the subject's own credentials**, and **everything in it is scoped to the subject who
created it** — scan reports, probes, chats, captures, keys. The one setting outside
the store is `ui.utility.AppPrefs` (`java.util.prefs` of the OS user, 2026-10-22): the directory
of the last successful open or create, and the last backup/restore directory. Directories only;
the vault password is never written there. Logout must leave nothing of the
previous subject on screen or in a panel field; `ScanPanel.resetPanel()` runs on *every* auth
change for exactly this reason (the gap `PENDING-ISSUES.md` finding 1 described, closed
2026-09-11), and a scan whose subject signed out before it finished is discarded, not shown to
whoever signed in next. Scan reports are network topology: they leave the machine only
when the subject attaches one to a chat themselves. Nothing here uploads, phones home, or syncs.

## Layout

```
io.xlogistx.nosneak.app
├── NoSneakMain.java               ← entry point; ds.location/ds.store-password (+ subject=/password=) or the unlock screen; AppFrame swaps unlock ↔ shell, loads the MAC vendors after login (2026-10-25)
├── NoSneakStore.java              ← vault + encrypted H2 + shiro.ini: create (H2PSetup) / open (attached manager) / secure / bootstrap / grantAppUser / setRegistrarPassword (2026-10-21)
└── ui/                            ← UI (screens, menu, session/access wiring)
    ├── AppShell.java              ← the signed-in window: HeaderBar + SideNavPanel + CardLayout host (2026-10-24), mounts ai-assistant's AssistantPanel
    ├── UnlockPanel.java           ← the pre-auth screen (2026-10-24): step 1 open/create the store, step 2 sign in / register; replaced LoginPanel + DataStoreSetupPanel. 2026-10-29: every step-1 input has a tooltip and a warning row under the vault password says it is NOT RECOVERABLE (`Form.VAULT_PASSWORD_WARNING`)
    ├── PQCRegistryPanel.java      ← PQC file-sharing registry view
    ├── SubjectPanel.java          ← Account pages in the PagePanel frame: Profile, Credentials (API keys), Settings (Sync of the MAC vendor list, Backup, Restore)
    ├── SubjectSecManagerPanel.java← Access control (admin) page; tabs are stubs
    ├── ScanPanel.java             ← scanner wiring: ScanFormPanel + ScanResultView, probe chips (the only source of probing, 2026-10-26), history JTable (multi-select, Delete / Delete all), probe editor
    ├── scan/
    │   ├── ScanFormPanel.java     ← the form that generates the command line (and follows an edited one); Service detection = all / none of the chips
    │   ├── ScanResultView.java    ← header counts + Hosts (MAC and Vendor columns, blank when the report has none) / Services / Raw JSON, host detail with the Network adapter block
    │   └── ReportView.java        ← the engine's JSON parsed into records (pure; ReportViewTest)
    ├── MenuBarFactory.java        ← builds the application menu bar
    ├── assistant/                 ← app-side bindings for the ai-assistant module
    │   ├── SessionAICredentialSource.java ← the subject's API keys + which are assistant-enabled (AICredentialSource)
    │   └── AssistantStorage.java  ← AIRepository impl (chats + skills + provider configs), GUID-keyed over the H2P APIDataStore
    └── utility/
        ├── AppContext.java        ← per-app service locator (Session + Navigator)
        ├── Session.java           ← auth (unbound Shiro subject) + identifiers + credentials + profile + addresses + the subject view of the store + the app-wide MAC vendor record (loadMacVendors / syncMacVendors, system context)
        ├── Navigator.java         ← top-level screen switching over a CardLayout
        └── AppPrefs.java          ← java.util.prefs of the OS user: last store location + last chooser directory (2026-10-22)

(The `CardStack` / `PanelBuilder` / `ListSection` / `BackgroundTask` helpers live in the shared
`io.xlogistx.gui` toolkit — `xlogistx-gui-audio` — not in this module.)
```

## Entry point

### `NoSneakMain`
Bootstraps the app. `main` first parses `ds.*` launch parameters (`ParamUtil.parse("=", args)`):
`ds.location` (the installation directory) and `ds.store-password` (its vault password). If
**both** are present it opens the installation directly — `NoSneakStore.open(location,
password)` reads the vault, loads the master key, opens the encrypted H2 store with the Shiro
controller + key maker, builds the realm from the directory's `shiro.ini` and returns the
`ShiroDSDomainSecurityManager` attached to it; a failure prints the reason and exits with status 2.
It then installs FlatLaf **FlatLightLaf** (Roboto as the default font) and calls
`launchApp(dsm, location, subject, password)` on the EDT — with a null manager when there were no
parameters. **`subject=<username>` + `password=<password>`** (2026-10-25, asked for during the
run-through; `username=` is an alias for `subject=`) sign that subject in once the window is up,
through `UnlockPanel.signIn`, the same path as typing on the sign-in step: success lands in the
shell, a refusal stays on the sign-in step with the reason inline and the username kept. They need
the `ds.*` pair (the store must be open) and are ignored with a message on stderr otherwise.
`UnlockPanelSignInTest` pins both outcomes on a real store.
(`createDomainSecManager(store)` is still there for a store opened elsewhere and not set up by
`H2PSetup`: it builds a self-managed manager and bootstraps it, `OPSecUtil.singleton()` first.)

**One window from the start (2026-10-24, Phase 1 of the UI redesign — plan in
`UI-REDESIGN-PLAN.md`).** `launchApp` creates `AppFrame` — a `JFrame` titled "NoSneak", sized
**relative to the primary display** (60 % × 70 % of `Toolkit.getScreenSize()`, then centred; on a
multi-monitor setup the frame is sized off the primary regardless of where it opens), with the
shield badge as its window icon — whose content pane is the **`UnlockPanel`**. The application is
built lazily around the store:

- **`AppFrame.storeOpened(dsm)`** — called on the EDT by the unlock panel after a successful
  Open / Create, or by `launchApp` when the manager came from the parameters — creates the single
  `AppContext`, builds the menu bar via `MenuBarFactory`, constructs `AppShell` (every signed-in
  screen), hands the panel its `Session` (`unlock.bindSession`) and subscribes to
  `session().onAuthChange(...)`: **authenticated** → `loadMacVendorsThenShow()` (2026-10-25: a
  `BackgroundTask` runs `Session.loadMacVendors()` with *Loading MAC vendors…* under the sign-in
  fields, then) menu bar installed, content pane = the `AppShell` — a failed download is shown
  once as a warning and the app still starts; **signed out** → menu bar removed, `unlock.resetForSignIn()`, content pane = the
  unlock panel again, at its sign-in step. A second `storeOpened` is ignored: **the store is fixed
  for the life of the process**; switching installations means a restart, as before.
- With parameters, `launchApp` also calls `unlock.markStoreOpened(location)`, so the window opens
  on the sign-in step with step 1 already collapsed to `<location> · vault unlocked`.
- `AppFrame` is `EXIT_ON_CLOSE`; its `windowClosing` handler calls `ctx.session().closeNio()` and
  `ctx.session().logout()` when a context exists, then `domainSecurityManager.getDataStore().close()`
  when a store was opened, so the encrypted H2 store is flushed/closed on exit rather than left to
  the JVM teardown. (The datastore is closed on **app close only**, not on logout — logout keeps
  it open for the next sign-in.)

There is no separate "NoSneak - Setup" frame and no `showSetup` any more; `DataStoreSetupPanel`
and `LoginPanel` were deleted with it. The IntelliJ run configuration `NoSneakMain` points
`ds.location=/data/ds` at an installation written before the 2026-10-21 model (no super-admin in
its vault, no INI): `open` refuses it with the reason — delete it, run without arguments for the
unlock screen, then put the new vault password back in the configuration.

> Passing the vault password via `ds.store-password`, or a subject's password via `password=`, on
> the command line exposes it (process list, shell history, run-config files), so treat that path
> as a dev convenience and prefer the unlock screen. A **wrong vault password** fails the keystore's integrity check (`IOException` from
> `SecretStore.open`, shown inline under the location on step 1); the database passwords never
> leave the vault.

## `ui` — UI screens & wiring

### `AppShell`
The signed-in application (rebuilt 2026-10-24, Phase 2 of the redesign): a `BorderLayout` of
gui-audio's **`HeaderBar`** (north: shield + "NoSneak", a mono chip with the open store's
directory from `AppPrefs.storeLocation()` and "vault open" — its tooltip is
`MenuBarFactory.STORE_NOTE`, the About card's Store row, plus a pointer to *Settings > Backup*
(2026-10-27) —, then the subject — initial avatar,
principal, a *super-admin* badge when `ShiroDSDomainSecurityManager.isSuperAdminSubject` says so —
and a **Sign out** button that confirms and calls `session().logout()`), one **`SideNavPanel`**
(west), the `CardLayout` content host (centre) and the status bar (south — 2026-10-27: *Signed
in as …* / *Signed out* on the left; on the right the MAC vendor list's state in the Settings
page's words, `MAC vendors: 52,000 vendors loaded · stored 2026-10-21 …`, *loading…* until
`Session.onMacVendorsChange` fires, blank when signed out; the old static *Ready* is gone).

**One navigation layer now.** The sidebar's sections and items are the whole page list; since
2026-10-26 the item labels come from the enum itself (`Screen implements GetDisplayName` — and
`GetDescription` since 2026-10-27: one line per page, the tooltip of its sidebar item
(`AppShell.item(screen, icon)` → `SideNavPanel.item(screen, icon)`, a `ComponentRef` over the
constant: its name is the key, so `navigator.onShow(nav::select)` syncs by the `Screen` itself)
and of its View-menu entry; `ScreenLabelsTest` pins that every
screen has one and that the assistant's `Page` says the same —, the
maintainer's cleanup: `NEW_SCAN` — `SCAN` since 2026-10-27 — and `CHAT_HISTORY` replaced `SCAN_NEW` and `CHATS`; later that
day `CHAT_HISTORY` went altogether when Chat History merged into the Chat page), and so do
**the page titles and the View-menu items** (one exception: the View menu calls `CHAT`
*Assistant chat*, 2026-10-27): `ScanPanel`'s three headers, the Profile and
Settings `PagePanel`s, the API Keys header and the Access Control page all read
`Screen.<X>.getDisplayName()`, so one string names a page in the sidebar, at the top of the page
and in the menu. The assistant's own pages (`ai-assistant`, which cannot see `Navigator`) take
their titles from `AssistantPanel.Page.getDisplayName()`, and `ScreenLabelsTest` pins that each
assistant page and its `Screen` (`AppShell.screenFor`, package-private for the test) carry the same
words, that every screen label is distinct, and that the two segment enums (`ProbeLibraryModel.Filter`,
`NMapConfig.Timing`) label themselves. The remaining GUI enums are not label sources:
`ReportView.Tone` is a colour, `Session.APIKeyInfo` is a property key.

| Section | Items (`Screen.getDisplayName()`) → `Navigator.Screen` → card · section |
|---|---|
| Scan | Scan → `SCAN` → `ScanPanel.show(SECTION_SCAN)`; Scan History → `SCAN_HISTORY` → `SECTION_HISTORY`; Probe Library → `PROBES` → `SECTION_PROBES` |
| Assistant | Chat / Capture / Skills / Providers → `CHAT` / `CAPTURE` / `SKILLS` / `PROVIDERS` → `AssistantPanel.showPage(Page.CHAT …)`; Chat is the list of chats and the open conversation in one page (merged 2026-10-26) |
| Account | Profile / API Keys / Settings → `PROFILE` / `API_KEYS` / `SETTINGS` → `SubjectPanel.show(SECTION_PROFILE / SECTION_CREDENTIALS / SECTION_SETTINGS)` |
| Admin | Access Control → `ACL` → `SubjectSecManagerPanel` (visible only for the super-admin: `nav.setSectionVisible("admin", …)` on every login) |

Footer of the sidebar: **Help** (`MenuBarFactory.showDescription`) and the version line, a muted
link that opens About (`showAbout`; since 2026-10-27 the line is name + version only, the Java /
platform / store facts are in the About card).
`navigator.onShow` keeps the sidebar highlight in step; a click on an item is
`navigator.show(Screen.valueOf(key))`. When the assistant moves itself (a chat opened from
history, a capture sent to the chat, `sendToChat` from the scanner) `AssistantPanel.setOnPageShown`
→ `navigator.sync(screen)` updates the highlight without re-running the route. The per-screen
toggle columns (`PanelBuilder.buildDefaultSplitPanel`) are gone from every panel; each keeps its
`CardStack` and exposes `show(section)` with `SECTION_*` constants. The `PQCRegistryPanel`
placeholder is **no longer registered** as a card (the class remains, unreferenced).

Every panel is constructed here, when the store opens and before anyone signs in — the navigator
controls visibility only, never construction. On **login** the shell sets the header subject,
shows or hides the Admin section, calls `assistantPanel.reloadProviders()` + `refreshHistory()` +
`refreshSkills()` and lands on **`SCAN`**; on **logout** it clears the subject,
`refreshHistory()` + `refreshSkills()` (empty-owner → cleared) + `clearProviders()` +
`resetPanel()` and returns the cards to `SCAN`, so nothing of the previous subject is on
screen when `NoSneakMain.AppFrame` swaps the shell back in. `menuBar()` hands the frame the
`MenuBarFactory` menu that goes with the shell.

**`AppShell` is also where the scanner and the assistant are joined**, and the order matters:
`assistantPanel` is built first, then `ScanPanel` takes `assistantPanel::sendToChat`, then
`assistantPanel.addSaveTarget("probe", scanPanel::saveProbeFromEditor)` registers the reverse
direction. Both are plain callbacks, so the dependency stays one-way (`no-sneak-app →
ai-assistant`) in both directions of the data flow. The `ASSISTANT` card is the `ai-assistant`
module's `AssistantPanel`, constructed with an `AssistantContext`:
`new AssistantPanel(new AssistantContext(new SessionAICredentialSource(ctx.session()), new
AssistantStorage(ctx.session())))` — the **only** coupling point.

### `PQCRegistryPanel`
A placeholder with no settled specification (two "PLACEHOLDER" toggles over an empty card). Since
2026-10-24 it is **not registered** as a card and has no sidebar item; the class stays in the tree
until a product decision exists for it.

### `SubjectPanel`
The `SUBJECT` screen — the signed-in subject's own account view, a **master–detail**
(`JToggleButton` selectors + `CardStack`, assembled by `buildDefaultSplitPanel`). Both sections
are wired to `Session` for real. Because the panel is built once (before login), it subscribes to
`onAuthChange` and, on **both** login and logout, calls `identifiers.refresh()` /
`credentials.refresh()` / `populateProfile()` — repopulating on login, clearing on logout (the
`Session` getters return empty when signed out).

Since 2026-10-24 (Phase 5 of the redesign) the Profile and Settings sections sit in gui-audio's
`PagePanel` — page title and description over the ground, the existing content in one white card
that scrolls — and the old in-form "Profile" title and description line are gone; Credentials
has its own two-card layout (Phase 4).

**Settings** (`SECTION_SETTINGS`, sidebar *Account → Settings*, 2026-10-25, asked for by the
maintainer) is a `PagePanel` with three blocks separated by rules: **Sync**, **Backup** and
**Restore** — the last two moved here from their own Backup page on 2026-10-26 on the
maintainer's instruction (the `BACKUP` screen, its sidebar item and its View-menu entry are
gone). On 2026-10-27 `buildDBBackup` / `buildDBRestore` took the Sync block's shape (`blockNote`, a
`WrapLabel` at 480 px, and `blockStatus`, muted), their notes list what the store holds (accounts
and API keys, scan reports, chats, captures, skills, probes, the MAC vendor list), Backup warns
that reports carry the network's layout, and the default archive name carries the day
(`<db>-backup-<yyyy-MM-dd>.zip`). Each block is a note, one button and a
muted status line. Sync's button runs `Session.syncMacVendors()` on a `BackgroundTask` (download the current Wireshark list, replace the
stored row, load it into the live table); a failure is the usual error dialog with the reason and
the stored copy is kept. The status line (`syncStatusText`: *58,575 vendors loaded · stored
2026-10-25 · last sync …*, or *No stored list yet*; the status bar at the bottom of the window
shows the same text) is re-read off the EDT each time the page is shown (`show(SECTION_SETTINGS)`
→ `refreshSyncStatus`, a projected read that skips the 3 MB body) and, since 2026-10-27, on every
`Session.onMacVendorsChange` event (the post-login load, a sync), with *Loading the vendor list…*
while the table is not filled yet. The note names where the vendor shows up (Hosts tab columns,
Network adapter block) and points at the status bar.
Other reference data this installation keeps belongs in further blocks on this page.

The **Profile** screen is itself a nested `CardStack` (`profileCards`, built by
`buildProfileArea`, a 480 px column like the Settings blocks) with a **profile** card and an
**editAddress** detail card. Re-laid out on 2026-10-27 in the Settings page's shape. The same day
gui-audio's `ListSection` description became a `WrapLabel` wrapped at the section's width (it was
a wrapping `JTextArea`: one line high until laid out once, and stretched by BoxLayout after).

- **Profile** (card key `profile`) — three blocks separated by rules, in the Settings page's
  shape (`blockNote` / `blockStatus`):
  - **Name** — a `FormPanel` (First name, Last name, Date of birth with the *yyyy-mm-dd* hint),
    the page's one primary button **Save changes** (`Session.saveProfile(...)`, name/DOB only;
    `populateProfile()` reads them back via `Session.loadProfile`) and a muted status line
    (*Saving…* / *Saved.*) in place of the old dialog.
  - **Identifiers** — a `ListSection` bound to `Session.getAllPrincipalIDForLoggedInUser()`, with
    a description (the names you sign in with; deleting the current one moves the account to
    another). **+ Add identifier** prompts for a value → `Session.addIdentifier`; per-row
    **Remove** (trash icon) → `Session.removeIdentifier`. Both surface the thrown
    `SecurityException`'s message on failure.
  - **Addresses** — a `ListSection` bound to `Session.getAllAddresses()`, with a description
    (for your own records; nothing reads them). **+ Add address** opens the **editAddress** card
    blank; each row's **Edit** (pencil) opens it pre-filled; **Remove** (trash) confirms then
    `Session.deleteAddress`. The editAddress card (`buildEditAddress`, via `PanelBuilder.detail`
    for a back arrow) is a `FormPanel` — Label (hint *Home, Work…*) / Street / City /
    State-region / Postal code / a **Country** combo (from `DataConst.COUNTRIES`) — with a note
    that a label or a street is enough and the primary **Save address**: Add stores a fresh
    `NVGenericMap` via `Session.addAddress`, Edit mutates the selected map in place and persists
    via `Session.changeAddressDetails`. Save requires at least a **Label or Street** (blocks
    with a "Missing information" dialog otherwise).
- **Credentials** (card key `Credentials`; the sidebar's **API Keys** page). Since 2026-10-27 it
  is a `PagePanel` like every other page: title, description ("Your password, and the third-party
  API keys the assistant borrows; it holds none of its own.") and the page's one primary action
  **Add API key** in the head (it was a button inside the list), over the two cards of board 5 of
  the redesign: the list card on the left, the editor on the right. The right-hand
  `credentialCards` stack keeps its card names — `"list"` is the placeholder shown while nothing
  is being edited — so every `credentialCards.show("list")` after a save, a delete or a logout
  still lands on the right thing. Three views: a **list**, a **change-password** form, and an
  **edit-API-key** form (`editAPI`). The list card stacks **two** `ListSection`s, each with a
  description (the password you sign in with, the vault password being a different one; keys of
  third-party AI providers kept sealed under your account, picked by the assistant's Providers
  page, sent only to their own provider) and an empty-state row ("No API keys yet"):
  - **Password section** (no add button) — the Password row's **Edit** (pencil) flips to the
    change-password form: a `FormPanel` (current / new / confirm, all required, with a note that
    the vault password is changed outside the app) and the primary **Change password** →
    `Session.changePassword` via `BackgroundTask`.
  - **API keys section** — one row per key (`"API key — " + SubjectAPIKey.getName()`); the row's
    **Edit** opens the `editAPI` card. **Add API key** (page head) opens the add dialog. The
    **Generate local** path is hidden, so the dialog opens on the **Add a third-party API key**
    form — `SubjectPanel.AddKeyForm`, a `FormPanel` 480 px wide with section headers `Key` /
    `Scope` / `Provider endpoint` (the render harness paints it through `newAddKeyForm()`):
    **Label** (required), **Description**, the **API key** (required) in a masked
    `JPasswordField` (reveal button), App ID / Domain ID (hint: both, or neither), a
    **Provider** editable combo (Claude / OpenAI / Gemini / Grok, or type your own), and a
    **Base URL**. On **Create key** it stores via `Session.storeAPIKey(label, description,
    domainID, appID, rawKey, provider, baseURI, authScheme, headerName, external)` with
    `external = true`; the AppID filters validate the optional domain/app-id pair (invalid →
    `SecurityException`), provider/baseURI go to the property bag, and the list refreshes.
    `storeAPIKey` enforces a non-blank key.
    > Known rework: broader mandatory-field validation (label/description) on this dialog is still
    > to come, and the dialog currently closes on click even on error.
  - The `editAPI` card (the same `FormPanel` sections as the add form since 2026-10-27, the secret with its Copy — wiped from the clipboard after 60 s, see *Hardening* — and Show buttons on one line, the primary **Save** beside **Delete**) is fully wired
    **Show/Hide** toggle (`VisibleIcon`/`InvisibleIcon`, re-masked on every open) and a **Copy**
    button; editable **Label** / **Description**, **App ID** / **Domain ID**, and **Provider**
    (its own editable `keyProvider` combo — **not** the add dialog's `inProvider`; see the
    review note below) / **Base URI** — all populated from the key on open. **Label and
    Description are required**. Saved via `Session.changeAPIDetails(key, label, description,
    domainID, appID, provider, baseURI, authScheme, headerName)` — App ID / Domain ID persist
    when both non-blank (re-validated through the AppID filters); `authScheme`/`headerName` are
    not on the form but round-trip unchanged from the stored key. **Delete** sits beside Save in
    the card's action row (and on every list row) and runs the same `onDeleteAPIKey`:
    `Session.deleteAPIKey` after a confirm, off the EDT, then refresh — and when the deleted key
    is the one the card is editing it clears `selectedKey`, blanks the revealed secret, and flips
    back to the list, so the card can't be left showing a row that no longer exists. **Rotate**
    (`Session.rotateAPIKey`, disabled for external keys) is wired but **commented out of the
    card** (`keyView.add(rotateKey)`) — read the `external`-flag hazard under
    *Hardening* before putting it back.

> **Icon buttons.** Actions render as `io.xlogistx.gui.IconUtil` SVG icons with tooltips, and the
> vocabulary is deliberately one-meaning-per-icon: **EditIcon** (pencil), **DeleteIcon** (trash),
> **RefreshIcon** (rotate/regenerate **only** — restore-from-backup uses **RollbackIcon**),
> **CopyIcon** → **CheckIcon** on success, **TextBoxIcon** (copy the command a scan ran with,
> beside the result's CopyIcon), **VisibleIcon/InvisibleIcon** (reveal, and as a pair
> they are the mask toggle), **VisibleIcon** alone = view/open a row, **NextIcon** = advance with
> this row (open chat, send to chat), **SearchIcon**, **BackIcon** (`PanelBuilder.detail`),
> **InfoIcon** (usage), **RunIcon** (run a scan), **AreaIcon** (define/redraw a capture area),
> **CancelIcon** (discards edits — distinct from BackIcon, which promises not to).
> Icon-only buttons come from **`GUIUtil.iconButton(Icon)`**, which sizes tight to the icon; the
> back arrow is **32×32**, action icons **16×16**. Primary/confirming buttons keep their text; the
> save-style ones (Save Changes, Change password, Save address) also carry a **SaveIcon**.
> `SVGIconButtonTest` (test sources) is a runnable visual check. The app-bundled
> `src/main/resources/icons/*.svg` files are no longer referenced and can be removed.

### `SubjectSecManagerPanel`
The `ACL` page (sidebar: Admin → Access control, super-admin only) — an admin view over the
access-control model (the UI front for zoxweb's `DomainSecurityManager`). Since 2026-10-24 its
five views are **tabs** of one `JTabbedPane` in a `PagePanel` card instead of a toggle column (since
2026-10-27 an enum `View implements GetDisplayName, GetDescription` names and explains them: title and
tooltip through a `ComponentRef` per tab, `view(View)`), each a header +
description + search bar + `JTable` (wrapped in a `JScrollPane`, with a trailing unlabeled
actions column reserved for per-row controls):

- **Subjects** — subjects and their principals, credentials, grants (Name, Primary principal, Owns).
- **Permissions** — permission definitions, scoped by AppID (Permission, Description).
- **Roles** — named bundles of permissions (Role, Description).
- **Role groups** — bundles of roles granted together (Role Group, Roles).
- **Grants** — permission/role/role-group grants bound to subjects (Subject, Grant Type, Granted).

All tables are empty `DefaultTableModel` stubs; search and the actions column are not wired.

> Scope: `SubjectPanel` manages **your own** account; `SubjectSecManagerPanel` is the **admin**
> view over all subjects/permissions/roles/grants.

### `ScanPanel`
The scanner pages — the front end for the `no-sneak-core` scanning engine. Six cards: the three the
sidebar routes to (`SECTION_SCAN` = New scan, `SECTION_HISTORY` = History, `SECTION_PROBES` = Probe
library, through `show(section)`) and three reached from within (a stored report, the probe editor,
the probe definition). **Rebuilt on 2026-10-24 (Phase 3 of the redesign; board 2 of the canvas).**
Constructed as `new ScanPanel(ctx, assistantPanel::sendToChat)`; the second argument is a
`ScanPanel.ChatHandoff` — `(text, name, composerText)`, the assistant's three-argument
`sendToChat` since 2026-10-26 (a `BiConsumer` of content and name before) — so the panel can hand
a report, or a request, to the assistant without `no-sneak-app` reaching into it for anything else.

**New scan card.** A page header, then **`ui.scan.ScanFormPanel`** over a **`ui.scan.ScanResultView`**.

- **The form generates the command, and the command refills the form.** Targets (whitespace
  separated), Ports (a `-p` spec; empty = the engine's default list), Name, the option boxes
  (Service detection `-sV`, Host discovery only `-sn`, Skip ping `-Pn`, Live hosts only
  `--up-only`, Open ports only `--open`), a `SegmentedControl` built from `NMapConfig.Timing.values()`
  for the `-T` template (the enum's display name is its `-T` token; `timing.selected(values())` gives
  the template back, 2026-10-26), Max in flight,
  Min RTT timeout, the probe chips, and the **Command** field. The command is the truth and the form
  a view over it: `toConfig()` parses the field (`NMap.parseCommand`) so flags the form has no
  control for — `-PR`, `--dns-servers`, `-sU` — survive, then lays the fields over it; every field
  change re-prints the command with **`NMap.formatCommand`** (core, same day; the inverse of
  `parseCommand`, pinned by `NMapFormatCommandTest`); every command edit re-parses into the fields,
  a guard stopping the echo. A command that does not parse shows the engine's reason inline under
  the field and leaves the fields alone; `--help` text is behind the ⓘ button. Picking a `-T`
  template resets Max in flight to the template's value; a template with one knob overridden prints
  as `-T5 --max-inflight 4096` (`Timing.closest`). `ScanFormPanelTest` (headless) pins the round
  trips. Enter in the command or the targets runs the scan. **Host discovery only and Ports are
  exclusive, last action wins** (2026-10-25, the maintainer's first run: `80,443` typed with the
  box ticked ran `-sn` and said 0 open ports with nothing explaining why): typing ports unticks the
  box; ticking the box with ports typed keeps the text and an inline note under the command says
  those ports are not scanned. Nothing is ever greyed: a first fix disabled the field under `-sn`
  and the maintainer read it as "I can no longer specify the port range". A parsed command is not
  typing: `-sn` in the command ticks the box and empties the field without unticking anything.
- **Probes are chips, not checkboxes.** *Add probe* opens a popup with a check item per bundled and
  stored probe (grouped, an *All* per group, the bundled tooltip of service · ports); ticked probes
  show as chips (`ChipPanel`; a stored one carries a *mine* badge) and a chip's × unticks it. The
  ticks are still `tickedProbes`, keyed as before (`b:<name>` / `s:<guid>`), still applied to the
  parsed config by `ProbeSelection.applyTo` — never spliced into the command. **The ticks are the
  only source of probing (maintainer, 2026-10-26): no chip, no probing.** `applyTo` with an empty
  selection sets `probeScan` false and clears any `--probes` the command carried (a bare `-sV`
  would otherwise run the engine's whole catalog); a non-empty one implies `-sV` and names the
  set. The *Service detection* box mirrors the chips both ways (`refreshProbeChips`) and is the
  all / none shortcut when the user clicks it: a tick with no chips ticks every bundled and stored
  probe (`tickAllProbes`, through `ScanFormPanel.onServiceDetectionToggled`, which programmatic
  `setServiceDetection` does not fire), an untick clears them. The empty chip strip says so. The
  engine side of the rule is in `NMapScanner.buildChecker`: a requested set that matches nothing
  now probes nothing (null checker, warning *nothing probed*) instead of falling back to all.
  `ScanPanelTest.noTicksMeanNoProbingWhateverTheCommandSays` / `allTickedNamesEveryProbe` and
  core `ExtraProbeCatalogTest.onlyUnknownNamesProbeNothing` pin it.
- **Run.** `onRun` builds `form.toConfig()`, applies the ticks, and records as the report's `command`
  the field's text (or the config's print when the field was empty). Invalid input is an inline
  message, not a dialog. The worker is `runScan` as before (wait budget, Stop through the handle, a
  partial report on cancel). The outcome goes to `resultView.setReport(name, json, stopped, saved)`:
  a stopped scan shows its partial report with a *stopped · not saved* badge and the reason inline;
  a completed one shows *not saved* until the store insert lands (`BackgroundTask.runCatching`,
  off the EDT), then `markSaved(true)` and the history list reloads. The departed-subject rule is
  unchanged: a scan whose subject signed out is not saved.
- **The result as tables.** `ScanResultView` parses the JSON with **`ui.scan.ReportView`** (pure;
  `ReportViewTest` reads a hand-written sample and a report the engine itself rendered): header with
  name, command, time, duration, the state badge, the four counts (hosts up, open ports, TLS
  endpoints, PQC ready), Copy (the raw JSON) and Send to assistant; then **Hosts** (address and
  hostname, the MAC's **vendor** when the engine named it — the report's `macVendor`, 2026-10-25,
  blank otherwise; the detail pane has a **Network adapter** block (2026-10-26) with MAC and
  Vendor rows when a MAC was learnt —, status, open count,
  services, the worst TLS endpoint's version · key exchange, and the
  **posture** — the engine's own letter from the port's `grade` field, with *Hybrid PQC* /
  *Classical* / *Not ready* from `pqc`, coloured by tone; selecting a row fills the detail pane:
  ports with version · probe, the worst TLS port's protocol / key exchange / cipher / certificate /
  chain / groups offered, and the verdict in words from the PQC status, the trust verdict and the
  engine's advisories), **Services** (every open port flat) and **Raw JSON** — the three are the
  enum `ScanResultView.Tab` (2026-10-27): title and tooltip through a `ComponentRef` per tab,
  `tab(Tab)` hands the content back. Nothing here grades:
  `grade.Grade` in the core wrote the letter per port; the view only picks the worst per host.

**History / stored report (Phase 4, same day; board 3).** A `JTable` over
`Session.getAllScanResults()` — Scan (name), Command (mono, muted), When, Hosts up, Open ports —
sorted newest first, a search box that filters every column (`RowFilter`), a count label, and a
toolbar acting on the selected row: View, Scan again, Copy command, Copy result, Send to
assistant, Delete (confirmed). **The table is multi-select** (2026-10-25): with several rows
selected the single-row actions grey out and Delete reads *Delete N*, confirms once and removes
them all (`Session.deleteScanResults`); `selectedHistoryRow()` is null unless exactly one row is
selected. And **Delete all** (2026-10-25), enabled whenever the list has
rows rather than by the selection: after a confirm naming the count, `Session.deleteAllScanResults()`
deletes every projected row through the subject view (so only this subject's scans go) and the
list reloads empty (`SessionScanHistoryTest`). Double-click views. **Scan again** (2026-10-25, asked for during
the run-through; also a header button on the stored report's view, `ScanResultView.onRerun`)
puts the report's saved `command`, `probes` (names mapped back to ticks by
`ProbeSelection.keysForNames`: bundled by name, stored by name, deleted ones dropped) and name
into the New scan form and navigates there; nothing runs until Run is pressed, so the command can
be adjusted first. A report without a `command` property falls back to its description cut before
the `· probes:` suffix. Rows are still projections re-fetched by GUID before their
content is read; the two counts come from the `hostsUp` / `openPorts` properties a run now records
on the `ReportContent` (parsed from the report at save time), so older rows show a dash. *View*
opens the stored report in a second `ScanResultView` with a *Back to history* link — the same
tables as a fresh run. `showResult(name, json)` feeds the scanner page a report from outside
(renders, tests).

**Probe library (2026-10-26, on the maintainer's instruction).** `buildProbePanel` is the same
shape as the history page: a head (title, *Write with the assistant*, the primary *New probe*), a
bar (search, an All / Bundled / Mine `SegmentedControl` built from `ProbeLibraryModel.Filter.values()`
— the enum carries its labels, 2026-10-26 —, the count, *Probe definition*), and a split
card — left a table on `ui/scan/ProbeLibraryModel` (rows = `bundledProbes` + the stored probes,
columns Name · Service · Ports · Transport · Priority · Source, Source a `BadgeLabel`, sorted by
priority then name as the engine orders its catalog; `ProbeLibraryModel.matches` is the row filter:
segment, then a query against name, service, description and exact port), right a detail
`CardStack`: **howto** with nothing selected (what a probe is, and the three ways to add one as
link buttons: copy a bundled probe, write with the assistant, new probe) and **probe** for a
selected row (a `KeyValuePanel` of its facts — Description, service, transport, ports, priority,
port-scoped, watchdog, states and start, source — the JSON read-only in the mono font, and the
actions: *Copy to my probes* for a bundled row, *Edit* and a confirmed *Delete* for a stored one;
double-click does the same). The bundled JSON comes from core's `ProbeDefinitionLoader.bundledSource(name)`,
read once into `bundledSources` by `reloadProbes()` (public now, for the render harness). A stored
probe whose JSON no longer parses keeps its row with the loader's reason in the detail pane. The
selection survives a reload by name and source.

**The probe editor** (`buildEditProbe`, card `Edit_probe`, opened by `openProbeEditor(row, title)`:
*New probe* / *Edit probe* / *Copy of <name>*) is a mono, non-wrapping text area under a help
line (*See the Probe definition, or let the assistant write it*, two link buttons) and the shadow
note (a stored probe with a bundled name replaces that probe in scans). *Check* runs
`ProbeLibraryModel.checkMessage` — the loader's verdict, *Valid: ssh · tcp 22, 2222 · 5 states from
connect* or its reason — into an `InlineMessage`; the name is a label read from the JSON
(`refreshEditName`), no field to disagree with it; Save goes through `probeToSave` as before
(name from the JSON, update-by-name, a modal only on failure). `saveProbeFromEditor` is still
the assistant's route in.

**Probe definition** (`showProbeDefinition`, card `Probe_definition`): `PROBE-DEFINITION.md`
in gui-audio's `MDViewerPanel`, loaded from the classpath on first use
(`ProbeDefinitionLoader.probeDefinition()`; core's pom serves the module-root file at
`/probes/PROBE-DEFINITION.md`), reached from the bar and the editor, back link to the library.

**Write with the assistant** (`onWriteProbeWithAssistant`): a small dialog asks for the service
and the port, then `sendToChat.send(probeDefinition, "Probe definition",
ProbeLibraryModel.assistantPrompt(service, port))` attaches the definition and types the request
(one JSON object in a fence, section 13 of the definition, a one-line description) into the
composer, and the app goes to Chat. With no chat open the assistant's "Open a chat first" shows and
the app goes to Chat all the same, which then lands on the list of chats (New chat is there, since
the merge of 2026-10-26). The reply carries a **Save as probe** button (the assistant's bubble
save targets, registered by `AppShell.addSaveTarget("probe", scanPanel::saveProbeFromEditor)`),
so the loop is: ask, send, click. Pinned by `ProbeLibraryModelTest` (rows, order, the broken
stored row, the filter, the check message, the prompt).

> **Two-way assistant wiring.** Out: the result views and the history rows call
> `setSendToChat(content, name)` → the injected `ChatHandoff` → `AssistantPanel.sendToChat`, then
> `ctx.nav().show(Screen.CHAT)`. A missing chat throws a `SecurityException` whose message the
> panel shows. In: `AppShell` registers `assistantPanel.addSaveTarget("probe",
> scanPanel::saveProbeFromEditor)`, which puts **probe** in the skill editor's "Save as" combo —
> choosing it routes the editor's content here instead of to the skill store; on success the
> navigator shows `PROBES`.

### `MenuBarFactory` & the navigation model
Builds the `JMenuBar` of the signed-in window: **File** (Sign out, with the same confirmation
as the header button), **View** (one item per `Navigator.Screen`, in sidebar order, for keyboard
discoverability — it mirrors the sidebar and adds nothing; since 2026-10-27 each item is a
`ComponentRef` over its `Screen` (`page(screen)` / `page(label, screen)` for the one reworded
item: the ref's display name is the text, its description the tooltip, its source the screen the
click shows; `viewItems()` lists them), **Help** (Help = the bundled
`app-description.md` in an `MDViewerPanel`, titled *NOSNEAK — Help* — rewritten 2026-10-27 to the
sidebar's pages: one paragraph per page, what the tool will not do, where the data stays; About =
a 460 px card in the house look (same day): name, `TAGLINE`, the `SUMMARY` paragraph that repeats
the Help's "what it will and won't do", a `KeyValuePanel` of Version / Java / Platform / Vault
(the directory) / Store (`STORE_NOTE`),
a muted line that every page, button, option and tab carries a tooltip (same day, when the
enums gained descriptions), and a `UITokens.link` button that opens Help. The Help text says the
same under *Where things live* and names the T0 to T5 and All / Bundled / Mine segments. Keep
both in step when a page is added or merged.)
Both dialogs are modeless and owned by the application window. `showDescription()` / `showAbout()`
are public so the sidebar's footer (*Help*, and the version line for About) can open them. The old *Tools* / *Mode* menus and
the never-wired *Technical Mode* checkbox were removed on 2026-10-24.

**There is one navigation layer** (2026-10-24). The sidebar in `AppShell` chooses the page; a
page is a `Navigator.Screen`, routed to a card on the content host plus a section inside that
card's panel. A panel's internal `CardStack` still exists (the scan panel's result and probe
detail cards, the subject panel's edit cards) but is driven by the panel's own buttons and by
`show(section)`, never by a second column of toggles.

### Access-control backend — `ShiroDSDomainSecurityManager` (io-xlogistx `shiro`)
`NoSneakStore.bootstrap(new ShiroDSDomainSecurityManager(store))` (also behind
`Main.createDomainSecManager`) builds io-xlogistx's Shiro-backed `DomainSecurityManager` over the
encrypted H2 `H2PDataStore` and passes it to `AppContext` → `Session`. It registers `CIPassword`
and `SubjectAPIKey` itself, creates every subject **with its subject key** (so the store's
configuration must carry the `KeyMaker` with the master key — `NoSneakStore.secure`), runs its own
store access in the system context, and implements the full model — subject/principal/credential
CRUD, the per-app permission/role/role-group catalog, grants, the app model. The keying the code
relies on: a password login resolves the principal to its subject and verifies the `PASSWORD`
`CIPassword`; identifiers are keyed by **subjectGUID**, credentials by **principalID** or
**subjectGUID**. Its catalog rows belong to the common app `xlogistx.com-common`, which is why the
bootstrap seeds the catalog before anything else; no-sneak's own app is `xlogistx.com-nosneak`.
Its notes and session log: `zoxweb-datastore/h2p-datastore/SHIRO-DS.md`.

- **Persistent, bootstrapped, no accounts** — data lives in the encrypted H2 file store and
  survives restarts; the catalog and the two apps exist from the first open, subjects do not.
- **`createSubjectID` throws on a duplicate** principal (`"Principal ID already exists"`);
  `registerUsernamePassword` maps that one to `"That username is already taken"` and lets any
  other reason through as `"Registration failed: <root cause>"`.
- **`loginApiKey` always refuses** (user rule 2026-10-03).

> Profile fields (name/DOB) and the address book are stored in the `SubjectIdentifier`'s inherited
> `PropertyImpl` property bag (`getProperties()` → `NVGenericMap`) — name/DOB as flat keys,
> addresses as a nested `NVGenericMapList` — persisted via `updateSubjectID`; the schema itself
> has no such fields.
>
> **Tests** (`src/test/...`, over an in-memory `MockAPIDataStore` built by `TestSecurity`: a
> throw-away vault's master key in the `KeyMakerProvider`, the controller + key maker on the mock's
> configuration as `NoSneakStore.secure` sets them, `NoSneakStore.bootstrap` run). Success paths
> assert `assertDoesNotThrow`, failures assert the thrown `AccessSecurityException` (message = the
> reason): `RegisterRoundTripTest`, `ProfileRoundTripTest`, `APIKeyRoundTripTest` (generate →
> create → read back as the owner, never a login; edit/clear; delete; rotate; vendor domain/app
> normalization + validation on external keys, the fixed scope of internal ones; external-flag +
> provider/base-url/auth-type/header-name metadata), `ChangePasswordRoundTripTest`,
> `IdentifierRoundTripTest`, `AddressRoundTripTest`, `AssistantStorageTest`,
> `SessionAICredentialSourceTest`, `AppIDDefaultTest` (the domain + app-id filters directly), and
> **`DataStoreSetupFlowTest`** on a real installation set up by `H2PSetup` (vault + encrypted H2
> file + `shiro.ini`, access check on, manager attached to the INI realm — the suites where
> the subject binding and the app login gate are enforced), and **`StoreHardeningTest`** on the
> same kind of installation (the chat delete cascade and the duplicate identifier, two rules the
> mock store cannot exercise; 2026-10-27). Subjects the mock-store suites need
> come from `TestSecurity.createUser`, which creates and grants `app_user` as sign-up does.
> Surefire cannot fetch its provider offline here; run them per class in IntelliJ (10 classes,
> 79 tests on 2026-10-21), or through the `.claude/tools` launcher with the app classpath (module
> output dirs + the jars IntelliJ lists for `no-sneak-app`, JUnit 6.1.3).

## `ui.utility` — application services

### `AppContext`
Lightweight per-application service locator. Constructed in `Main.AppFrame` with the
`ShiroDSDomainSecurityManager`, from which it builds the single `Session`; also holds the `Navigator`
(injected by `AppShell` once the card host exists). Accessors: `session()`, `nav()`,
`setNavigator(...)`. Passed down to screens and the menu factory so they share one session and one
navigator.

### `Session`
Authentication/session state built on `PropertyChangeSupport`, holding the shared
`ShiroDSDomainSecurityManager`, the current `principalID` (the username, *not* the GUID; accessor
`getPrincipalID()`), its `subjectIdentifier`, and — since 2026-10-05 — the logged-in Shiro
`Subject`, **kept unbound**. Three things hang off that subject:
- `getDataStore()` — a `java.lang.reflect.Proxy` over the store's interfaces whose every call
  runs inside `try (SubjectSwap swap = new SubjectSwap(subject))`: the h2p store judges each row
  against the subject bound to the *calling* thread, and the callers are `SwingWorker` pool
  threads, so the binding is per call and the pool never keeps a subject. Every screen and
  `AssistantStorage` use this view; the manager's `getDataStore()` is for system work only.
- `asSubject(Supplier|Runnable)` — the same swap around arbitrary work.
- `runAsSystem(Supplier)` — the store controller's system context, for the whole-store
  dump/restore in `SubjectPanel` (the store refuses those from a subject) and for the one
  **app-wide record** below.
Signed out, `subject` is null, the swap binds nothing, and the store returns no rows.

**MAC vendors (2026-10-25, maintainer's spec).** `loadMacVendors()` runs after a login, before
the shell is shown (`NoSneakMain.AppFrame.loadMacVendorsThenShow`): in the system context it
looks for the `DataContent` whose `full_name` is `Mac-Vendor-Content` (`MAC_VENDOR_CONTENT_NAME`);
missing → `OUIDB.getRawContent(OUIDB.XLOG_MANUF_URL)` downloads the Wireshark manuf file
(3.2 MB, ~58k entries), which is stored as that row (`source_id` = the URL, `data` = the bytes)
after a throw-away `OUIDB` has parsed it to at least one entry (an error page is refused and not
stored); either way the bytes go into `NSNetUtil.MAC_VENDORS.load(...)`, the process-wide table
`ScanReport` consults for the host JSON's `macVendor`. The row has **no owner** on purpose: read
and written under `runAsSystem`, so every subject shares it and the first one to log in does not
own it — the one exception to the "everything is subject-scoped" rule in *Data boundary*. Loads
once per process; a download failure throws `IOException`, nothing is stored, the next login tries
again. The download sits behind a package-private seam (`setMacVendorSource`) so
`SessionMacVendorsTest` runs against a real store without reaching wireshark.org.
`syncMacVendors()` (the Settings page's Sync button) downloads again on demand, replaces the row's
bytes (`update` on the full row, a `synced_ts` property stamped on it — the store sets
`last_update_ts` on insert too, so that column cannot tell a sync from the first store) or creates
it, and `load`s the live table — which only adds or replaces entries, so a scan running at that
moment keeps resolving. `macVendorStatus()` is the projected read behind the page's status line
(entries in the live table, `creation_ts`, the `synced_ts` property).

Result convention: the account/auth mutators return **`void`** and **throw
`AccessSecurityException`** on failure — the exception message is the human-readable reason the
panel shows; success returns normally. This covers `loginUsernamePassword`,
`registerUsernamePassword`, `addIdentifier`, `removeIdentifier`, `changePassword`, `storeAPIKey`,
`changeAPIDetails`,
`rotateAPIKey`, `deleteAPIKey`, `saveProfile`, and the address mutators. `SecurityException` is
**unchecked**, so callers aren't forced to catch it — `BackgroundTask.runCatching` centralizes the
error dialog off the EDT. Failure is thrown, never a broadcast event. Two exceptions:
- **No-op / `void` stubs** — `loginPasskey` / `registerPasskey` are empty stubs; `logout` always
  succeeds.
- **`generateAPIKey()`** returns a `SubjectAPIKey` value and **throws** `SecurityException` when
  signed out (`"Not signed in"`) or on a crypto failure (`"Could not generate a key"`).

Auth (username/password is real against the store):
- `loginUsernamePassword` builds `new Subject.Builder(dsm.getSecurityManager()).buildSubject()`
  and logs it in with a `DomainUsernamePasswordToken(principal, password, false, null,
  NO_SNEAK_DOMAIN_ID, NO_SNEAK_APP_ID)` — the login is scoped to `xlogistx.com-nosneak` (the realm
  loads only the grants of that app; a scoped password login needs no grant to succeed). Any
  failure (unknown or inactive principal, bad password, an invalid principal id from the manager)
  becomes `AccessSecurityException("Invalid Credentials")`. On success it resolves the
  `SubjectIdentifier` by the subject's GUID, keeps the Shiro subject (ending a previous one),
  stores the `principalID` as the realm normalized it, flips `authenticated`, fires the event.
  Nothing is bound to the calling thread. Use `new String(password)`, **not** `Arrays.toString`.
- `registerUsernamePassword` gates on `FilterType.PASSWORD` (throws the rules message on failure),
  persists a bcrypt `CIPassword` via `createSubjectID` (the manager creates the subject key with
  it) and maps the duplicate-principal failure to `"That username is already taken"`; every other
  reason surfaces as `"Registration failed: <root cause>"`. It does **not** auto-login. Sign-up is
  this direct creation, not the manager's registrar path; since 2026-10-21 it grants the no-sneak
  app's **`app_user`** role (`NoSneakStore.grantAppUser`), the one grant the app login gate needs.
- `logout` ends the kept Shiro subject and clears the state; `loginAPIKey` **no longer exists**.

API-key lifecycle (failures throw `AccessSecurityException`; the raw key is sealed by the store
and read back in clear by its owner):
- `generateAPIKey()` — a fresh AES-256 key, URL-Base64 encoded, wrapped in a `SubjectAPIKey`; no
  persistence. Throws `"Not signed in"` when signed out and `"Could not generate a key"` on a
  crypto failure.
- `storeAPIKey(label, description, domainID, appID, rawKey, provider, baseURI, authScheme,
  headerName, external)` — stores the raw key verbatim (`setAPIKey(rawKey)`, no hashing) in a
  `SubjectAPIKey` (`STATUS` = ACTIVE) via `createCredential`. The `external` flag drives the
  scope: when **external** it sets the `external` property `true` and, when **both**
  `domainID`/`appID` are non-blank, records the **vendor's** domain and app as the properties
  `vendor-domain` / `vendor-app` (normalized and validated through an `AppIDDefault`:
  `FilterType.DOMAIN` + `AppIDNameFilter`, lower case) — never as the key's `app_id`, which the
  Shiro manager resolves to an app record of this store; when **not** external it scopes the key
  to `xlogistx.com-nosneak`. An invalid domain/app id → `AccessSecurityException("Invalid domain
  or app ID")`. AI-assistant metadata is written to the property bag via a `putIfPresent` helper
  keyed by the `Session.APIKeyInfo` enum: `provider`, `base-url`, `auth-type`, `header-name`,
  each only when non-blank. Guards: `"Not signed in"` / `"Key cannot be empty"`. *(No key-format
  validation — a malformed paste is accepted as a third-party secret.)*
- `changeAPIDetails(key, label, description, domainID, appID, provider, baseURI, authScheme,
  headerName)` — updates the key in place via `updateCredential`. Unlike create it **sets**
  blanks (passing empty clears label/description) and **rewrites** the metadata properties every
  save — a blank or null value **removes** the entry (`putOrRemove`, 2026-10-27; it used to write
  `""`, a provider the assistant could not resolve any better than a missing one); when both
  `domainID`/`appID` are non-blank **and the key is external** it records them as
  the vendor properties (invalid pair → thrown); an internal key's scope is not editable.
- `isExternalKey(key)` / `providerOf(key)` / `baseUrlOf(key)` / `authTypeOf(key)` /
  `headerNameOf(key)` / `vendorDomainOf(key)` / `vendorAppOf(key)` — read the metadata back off
  the property bag via the `APIKeyInfo` enum.
- `rotateAPIKey(key)` — generates a fresh secret, replaces the stored one via `updateCredential`
  (old key stops working). Guards against persisting a `null` secret.
- `deleteAPIKey(key)` — deletes the credential via `deleteCredential`. Guards: `"Not signed in"` /
  `"Empty Key"`.

Addresses (stored as an `NVGenericMapList("addresses")` in the subject's property bag — each
address its own `NVGenericMap` with keys `label`/`street`/`city`/`state`/`postal`/`country`).
`NVGenericMapList` was chosen because it was the one list container the property-bag serializer
round-tripped — an `NVEntityReferenceList` of `AddressDAO` was silently dropped on write. *(Worth
re-verifying the round-trip on the H2P datastore.)*
- `getAllAddresses()` — the live `List<NVGenericMap>` (empty when signed out); returned maps are
  the stored instances, so mutating one and calling `changeAddressDetails` persists the edit.
- `addAddress(NVGenericMap)` — creates the list on first use, appends, persists via
  `updateSubjectID`.
- `changeAddressDetails(NVGenericMap)` — persists after an in-place mutation. Guarded: the map
  must be in the stored list (identity check), else throws `"Address not found"`.
- `deleteAddress(NVGenericMap)` — removes by reference and persists.
  All throw `"Not signed in"` when signed out (the one guard, `requireSignedIn`, 2026-10-27).

Account data (backed by `DomainSecurityManager`, keyed off the signed-in subject):
- `getAllPrincipalIDForLoggedInUser()` — identifiers, via
  `lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID())`; empty when signed out.
- `getAllCredentialForLoggedInUser()` — credentials, via `lookupAllPrincipalCredentials(principalID)`.
- `getAllCredentialForUserByType(CredentialInfo.Type)` — credentials of one type, via
  `lookupCredentialsBySubjectGUID(subjectIdentifier.getSubjectGUID(), type)`; guards both null args.
- `addIdentifier` — the signed-in guard, then `addPrincipalID`; validation is the manager's (a
  blank is `"Invalid principal ID: …"`, one already in use — by any subject — is
  `"Principal ID already exists: …"`, backed by the store's unique index), so the session adds no
  guard of its own (the commented-out ones went on 2026-10-27; `StoreHardeningTest` pins the
  duplicate on a real store, the mock cannot refuse one).
- `removeIdentifier` — rejects a `null` principal (`"Identifier cannot be empty"`), the signed-in
  guard, then `"Cannot remove the only identifier"` when the subject has one left (the manager
  refuses that too, under a row lock, as a bare `false` → `"Could not remove identifier"`), then
  `deletePrincipalID`. If you remove the identifier you logged in as, it **repoints `principalID`**
  to a survivor so credential lookups keep working.
- `changePassword` — verifies the current password, validates the new one, then updates the
  existing `CIPassword` **in place** via `updateCredential(subjectIdentifier, credential)`
  (the entity keeps its GUID) — atomic, never a password-less window. Also refreshes the
  credential's **`canonicalID`** (the `$2a$…` bcrypt string validation reads); updating only
  salt/hash/rounds would leave the old password working.
- `saveProfile(Map)` / `loadProfile(String...)` — name/DOB only (flat keys) in the subject's
  property bag, persisted via `updateSubjectID`.

Scan data (`ReportContent` / `ProbeContent`, both from `no-sneak-core`'s
`io.xlogistx.nosneak.data`, owner-scoped by subjectGUID and stored in the same H2P
`APIDataStore`). `saveScanResult` / `saveProbe` branch on `getGUID()` — non-empty updates and
stamps `lastTimeUpdated`, empty stamps the owner and inserts — the same upsert-by-GUID shape
`AssistantStorage` uses, and for the same reason (see the timestamp note in `ai-model/CLAUDE.md`).
`getAllScanResults` / `getAllProbes` return empty when signed out.

> **`getAllScanResults()` is a projected read** — it names its columns and **omits `content`**,
> because a single `/24` report is ~53 KB of JSON and the list only renders a name, the command
> and a timestamp. That creates the same save-path obligation `getAllCaptures` has:
> `saveScanResult`'s update branch is `ds.update`, which writes every column, so it **throws**
> rather than nulling `content` if handed a row that came from the list. Anything that needs the
> body — view, send-to-chat — must re-read through `getScanResult(guid)` first and handle a miss.
> `getAllProbes` is deliberately *not* projected: probe bodies are small and the editor needs them.

The scanner also borrows a **shared `NIOSocket`** from the session. `getNio()` opens it on first
use (a subject who never scans never pays for a selector and its reader threads) and throws an
`IllegalStateException` if it cannot, rather than leaving a null field for a later NPE;
`closeNio()` is called from `AppFrame`'s `windowClosing` alongside the datastore. It is built on
`TaskUtil.default*`, so this class is the app's composition root for those pools in the same way
`NMap.main` is the CLI's.

State changes fire an `"authenticated"` property event; listeners subscribe via `onAuthChange(...)`
— how `AppFrame` toggles the menu bar and `AppShell`/`SubjectPanel` react on login/logout.
API-key mutations (`storeAPIKey` / `changeAPIDetails` / `rotateAPIKey` / `deleteAPIKey`) also fire
a `"credentials"` event (`onCredentialsChange(...)`), which is how a key created or deleted from
the **AI assistant's** Providers page shows up in `SubjectPanel`'s Credentials list without a
re-login. `loadMacVendors()` and `syncMacVendors()` fire a `"macVendors"` event
(`onMacVendorsChange(...)`, new value = the table's size; 2026-10-27) that the shell's status bar
follows. The mutators run off the EDT, so those events fire off the EDT too — listeners hop via
`SwingUtilities.invokeLater` before touching Swing. **`setAssistantEnabled` deliberately does not
fire it**: the assistant flips that property on every provider add/remove and nothing on the
Credentials page renders it, so broadcasting would be a refresh storm for no visible change. `SubjectPanel`'s logout branch also resets
the section selector back to **Profile** (`cardStack.show("Profile")` + re-selecting the toggle),
so a re-login always lands on the profile view rather than whatever section was open at logout.

### `SessionAICredentialSource` (in `ui.assistant`)
The adapter that lets the `ai-assistant` module reach NoSneak's keys without depending on
`no-sneak-app` — it implements `io.xlogistx.nosneak.ai.AICredentialSource` over a `Session`. Its
`APIKeys()` walks `getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)` and returns every
API key as a `List<APIKey<String>>` (the module reads the AI metadata off each key's property bag
itself, e.g. `getProperties().getValue("provider")`). Returns an empty list when signed out. It
also implements `enabledAPIKeys()` (the subset the subject has linked to the assistant) and
`setEnabled(key, on)`, which persists the choice on the credential's `assistant-enabled` property
via `Session.setAssistantEnabled` — so a key is used only once picked, never auto-added. Together
with `AssistantStorage` this is where the app meets the AI-assistant module; the dependency is
one-way.

### `AssistantStorage` (in `ui.assistant`)
The `io.xlogistx.nosneak.ai.AIRepository` implementation — persistence for chats, skills,
**`AIProviderConfig` rows** (a configured provider: key GUID + type + base URL + default model +
enabled label; see `ai-model/CLAUDE.md`), **and `AICapture` rows** (saved screenshots) —
constructed from the `Session` and reading **`Session.getDataStore()`** off it (the subject view:
each call binds the signed-in Shiro subject, which the store's access check and field encryption
need on the assistant's own executor threads too), owner-scoped by `subjectGUID`. `saveChat` / `saveSkill` /
`saveProviderConfig` / `saveCapture` all branch on **`getGUID()`**: non-empty → `ds.update`,
empty → stamp the owner and `ds.insert` (the store assigns the GUID). This must be `getGUID()`,
**not `getReferenceID()`** — `referenceID` is deprecated in zoxweb and the H2P store never sets
it, so branching on it made every save an insert and duplicated the row on each edit. The same
GUID keying is what `AssistantContext`'s canonical caches rely on; see the identity note in
`ai-model/CLAUDE.md`. `getAllChats` / `getAllSkills` return empty when signed out.

> **`getAllCaptures` is a projected read** — it names its columns explicitly and **omits
> `image`**, so list rows carry a thumbnail but no full png. Since `saveCapture`'s update branch
> is `ds.update`, which writes every column, saving a row that came from `getAllCaptures` nulls
> the stored image. Anything that mutates a capture must re-read it through `getCapture(guid)`
> first — and must handle that read returning **null** (signed out, or deleted meanwhile) rather
> than falling back to the projected instance.

Both saves also **stamp `lastTimeUpdated` on the update branch only**. The store's
`MetaUtil.initTimeStamp` writes a timestamp *only when the current value is 0*, so it sets
creation once and never advances "last updated" — the History rows' `updated` column would
otherwise show the insert time forever. Stamping only on update (not insert) keeps creation and
update from landing a millisecond apart on a fresh row. See the timestamp note in
`ai-model/CLAUDE.md`.

> **Every delete cascades** (`withReference=true` on all four; since 2026-10-27 for chats and
> skills). The H2P cascade is DB-driven: it collects the stored row's references before deleting
> it and follows them down, keeping any child another row still references, so a deleted chat
> takes its `ai_message` / `ai_request` / `ai_response` (and attachment) rows with it. Until that
> day `deleteChat` passed `false` and every message row of a deleted chat stayed in the database.
> `StoreHardeningTest` pins the cascade on a real `H2PSetup` installation (the mock store has no
> references to follow).
>
> **Tests** (`AssistantStorageTest`, 9 green, over `TestSecurity`'s mock store): insert assigns GUID +
> owner, update stamps `lastTimeUpdated`, save is an upsert by GUID (an edit must not duplicate
> the row), skills mirror chats, signed-out reads return empty, and — for provider configs — a
> full field round-trip, **one key backing several configs**, upsert-by-GUID, and delete.

### `Navigator`
Routes a `Screen` (`SCAN, SCAN_HISTORY, PROBES, CHAT, CAPTURE, SKILLS, PROVIDERS, PROFILE,
API_KEYS, SETTINGS, ACL` — the sidebar's items, in order; each carries its sidebar label through
zoxweb's `GetDisplayName` (2026-10-26) and a one-line purpose through `GetDescription` (2026-10-27,
the sidebar and View-menu tooltips); `CHAT_HISTORY` went on the 26th with the merge of Chat
History into Chat) to a `Route(ref, card, section)` — since 2026-10-27 the shell registers the
hosting *panel* (`register(screen, panel, section)`), the navigator adds it to the content host as
a card the first time a screen names it and keeps a `ComponentRef<Screen>` over it (`ref(screen)`,
`isShowing(panel)`; the shell's `CARD_*` names are gone):
`show(screen)` flips the `CardLayout` to the card, runs the section `Runnable` (the panel's
`show(section)` / `showPage(page)`), records `current()` and tells the `onShow` listeners;
`sync(screen)` records a move a panel made by itself and tells the listeners without running the
route. `AppShell` registers every route; a screen without one throws. EDT only.

### `CardStack`
A small wrapper around a `CardLayout` + backing `JPanel` for **in-panel** section switching
(distinct from the top-level `Navigator`). API: `view()` returns the card host, `add(Component,
name)` registers a card, `show(name)` flips to it. Used by `LoginPanel`, `SubjectPanel`, and
`SubjectSecManagerPanel`.

### `PanelBuilder`
Shared Swing layout helpers:
- `buildHorizontalSplitView(left, right, divLocation, resizeWeight)` — a configured `JSplitPane`.
- `buildDefaultSplitPanel(content, JComponent...)` — the master–detail shell: a left sidebar of
  sidebar rows and the supplied `content` on the right. Every `JToggleButton` joins one
  `ButtonGroup`; **anything else** (a `JSeparator`, a header label) is laid out but not grouped,
  which is how the assistant divides its nav into sections. Do not also build your own
  `ButtonGroup` over the same buttons — a button model holds exactly one group reference, so the
  second `add` silently replaces the first.
- `row(label, JButton...)` / `row(label, subtitle, JButton...)` — a list row; the subtitle
  variant stacks label over a muted second line in a `BoxLayout` (this is what `ListSection`'s
  `.sublabel(...)` renders through). A null/empty subtitle returns the single-line row.
- `buildJPanelWithFields(JComponent...)` — a single-column `GridBagLayout` form.
- `detail(title, onBack, content)` — a back-linked detail view (change-password, edit-API-key). Its
  body is a `MigLayout` single left-aligned column so fields keep their preferred size.
- `title(text)` — a heading `JLabel` styled via FlatLaf `STYLE_CLASS` `h2`.
- **Two-column form helpers** (used by the sectioned Add-API-key form): `textField(placeholder[,
  width])`, `sectionHeader(title)`, `addRow(form, label, field)` (into a `MigLayout("wrap 2",
  "[left][grow,fill]")` grid), `addSection(form, title)` (full-width header + `JSeparator`).
- Also `row(...)`, `group(...)`, and `listPage(...)` — the last superseded by `ListSection` for
  data-driven lists, kept only for static ones.

### `ListSection`
A titled, refreshable list component, built through a fluent builder:
`ListSection.of(Supplier<List<T>>)` plus `.title(...)`, `.description(...)`,
`.label(Function<T,String>)`, `.sublabel(Function<T,String>)`, `.addButton(label, onAdd)`,
`.onEdit(...)` / `.onRemove(...)`, extra `.action(RowAction)`s, `.emptyText(...)`, and
`.scrollable()` / `.search(placeholder)`. `refresh()` rebuilds every row from the supplier — call
it after any mutation. Omitting `.addButton` omits the add button (the read-only Password
section); a row with no handlers is a plain label line (empty states).

- **`.description(...)`** is a panel-level blurb under the title (a wrapping `JTextArea`, not a
  `JLabel`, so long copy wraps to the panel width instead of stretching it). Per *item* detail is
  `.sublabel(...)`, which is a different thing.
- **`.sublabel(...)`** renders a muted second line **under the row's own label** — 2pt smaller,
  `Label.disabledForeground`, via `PanelBuilder.row(label, subtitle, buttons...)`. A null or empty
  result falls through to the single-line row, so one list can mix one- and two-line rows; a
  two-line row also drops the fixed 36px height cap.
- **Convention: the label is the identity, the sublabel is the metadata.** Don't cram
  `name · type · date` into one label — split it. `filter()` matches label **or** sublabel, so
  nothing falls out of search when you move it down a line.
- **A sublabel lambda runs per row, on the EDT, on every refresh and every keystroke in the search
  box.** Keep it to fields already in memory — no store queries.

> `.label(...)` **assigns**, it does not accumulate — calling it twice silently drops the first
> lambda. `.search(...)` filters client-side over the supplier's list, which is why History and
> Skills can search without any store support.

### `BackgroundTask`
A `SwingWorker` helper so blocking work never runs on the EDT. `run(owner, toDisable, work,
onDone)` runs `work` (a `Callable<T>`) off the EDT and delivers the result to `onDone` on the EDT,
disabling `toDisable` while in flight. If `work` throws, it shows an error dialog instead — a
`SecurityException`'s message as-is (expected validation failure), anything else prefixed
`"Unexpected error: "`. `runCatching(owner, toDisable, work, onSuccess)` runs a throwing `work` and
**only on success** runs `onSuccess` on the EDT. Post-work UI (refresh, navigation, confirmation
dialogs) belongs in the `onSuccess` callback so it runs after the work completes.

## How it fits together

```
Main.AppFrame
  └─ AppContext ── Session (auth state, PropertyChange events)
                └─ Navigator (CardLayout screen switching)
  ├─ MenuBarFactory.buildMenu(ctx)   → View menu drives Navigator; File → Logout
  └─ AppShell(ctx)                   → CardLayout host for all screens
        ├─ LoginPanel           (LOGIN)   → Session.login*/register*  ──┐
        ├─ PQCRegistryPanel     (MAIN)                                  │ onAuthChange
        ├─ SubjectPanel         (SUBJECT)                               │  → nav to SUBJECT
        ├─ SubjectSecManagerPanel (MANAGER)                            │  + show menu bar
        ├─ ScanPanel            (SCAN)     → no-sneak-core engine       │  (logout → LOGIN)
        │        │      ▲                                              │
        │        │      └── addSaveTarget("probe", …)  ── response → probe
        │        └───────── sendToChat(content, name) ── report → chat  │
        └─ AssistantPanel       (ASSISTANT) ← AssistantContext          │
                                                              Session ◄─┘
```

The flow is event-driven through `Session`'s property-change events: screens and the frame react
to auth changes rather than calling each other directly, with `AppContext` providing the shared
`Session`/`Navigator` and `Navigator` centralizing top-level screen transitions (in-panel section
transitions go through each panel's own `CardStack`).

## Target behaviour (not yet built)

Design intent for the parts of `SubjectPanel` that aren't built yet.

### Tier toggle (Simple / Technical)
A single Technical-mode flag mirrored in two synced controls: the `Mode` menu's "Technical Mode"
checkbox and a top-right toggle in `SubjectPanel` — **neither wired yet**. **Technical** reveals
underlying detail (schema field names, `NS*` tokens, SPKI fingerprints, KEM/algorithm specifics);
**Simple** hides them. Presentational only — it changes *how much* is shown, never *what you can
do*.

### Login-credential types
Intended per-type behaviour (today **Password** and the **full API-key lifecycle** are built;
**passkey** is not):
- **Password** — *write-only*: never shown or recovered; the only op is *replace*. Stored as a
  verifier.
- **API key** — built: create → edit → rotate → delete; **not a login** since 2026-10-05. The
  store seals the secret at rest under the owner's key chain and serves it in clear to its
  logged-in owner, so the `editAPI` card can still reveal/copy it on demand.
- **Passkey** — only the *public key* is held; manage = view device + remove.

> **API-key ↔ subject linkage.** A key is keyed by **`sak.getSubjectGUID()`** — the same
> subjectGUID keying password credentials. So an API key **survives identifier churn**: removing
> the identifier it was minted under does not orphan it. The keys no-sneak generates itself
> (`generateAPIKey`, the hidden "Generate local" path, `rotateAPIKey`) existed for the API-key
> login that is gone; they still work as plain stored secrets scoped to `xlogistx.com-nosneak`,
> and whether to drop them or turn them into signing keys is decision D5 of the plan, open.

### Identifier & profile metadata
All target-only, because the model has nowhere to store them: per-identifier **status**
(primary/alias/verified) and **type** (email/username/handle), identifier **rename**,
**verification-before-active**, a minimum-one-email rule, and a gated **Canonical ID** field.
`PrincipalIdentifier` carries just the id string.

## Needed fixes / updates

### Register flow (`UnlockPanel`, step 2)
- **Confirmation warning on Register.** Clicking **Register** should prompt a confirmation dialog
  before proceeding (e.g. "Register using this email / username?"). Register currently proceeds
  straight to the filter/persist call.

### Subject panel (`SubjectPanel`)
- **Tier toggle not wired.** The `Mode` menu's "Technical Mode" `JCheckBoxMenuItem` has no action
  listener, and `SubjectPanel` has no toggle. Add the toggle, back both controls with a single
  shared flag, and make Simple/Technical actually show/hide the underlying detail.
- **Principal ID needs a status.** Each identifier should carry a status (primary / alias /
  verified / pending) shown in the Identifiers `ListSection` and settable from its edit
  affordance. Blocked on the model: `PrincipalIdentifier` holds only the id string.
- **Address mandatory-field convention.** The address card blocks saving unless at least a **Label
  or Street** is filled. Still target-only: a consistent convention across profile + address forms
  marking mandatory fields with a trailing `*` and everything else explicitly optional.

### Scan panel (`ScanPanel`)
- **`ProbeContent` carries one param.** Just `content`; the Probe library parses every stored
  blob once per reload (`ProbeLibraryModel.rows`, off the EDT) to show service, ports and
  priority. Adding columns is no longer a store hazard — H2P has done `ALTER TABLE ADD COLUMN`
  for a new param since 2026-09-23 — so the only reason left to add them is a search that
  should not parse. Not pressing.
- ~~**A scan cannot be cancelled.**~~ **Done 2026-09-11:** the Stop button cancels through
  `NMapScanner.ScanHandle`, and a timeout cancels too.
- **Reports go on the wire as JSON.** `send to chat` attaches the stored render verbatim, so a
  `/24` is ~53 KB (~15k tokens). The `NORMAL` render is far more compact and more legible to a
  model, but the `ScanReport` is not stored — only its JSON — so switching means also persisting
  the normal render at scan time. Cheaper to decide before the store fills up.
- ~~**`ScanPanelTest` is an empty `try {} catch {}`**~~ — it pins `ProbeSelection` (ticks → config,
  identity keys, no-ticks = no probing) since 2026-10-24.
- **The probe editor's title field is now output, not input** — `fillProbe` overwrites it from the
  parsed definition. **Done 2026-10-26:** the field is gone; the editor shows the parsed name as a label.

### ACL Tool (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects / Permissions /
  Roles / Role groups / Grants tables to the `DomainSecurityManager` catalog (`getPermissions()`,
  `getRoles()`, `getRoleGroups()`, the grant getters) and make the per-section search bars filter.
  The backend exists; the H2 store has no seeded catalog data.

### Hardening
From a review pass over the app's own code (issues fixable here, not in the zoxweb dependency),
ordered by priority.

- ~~**A third-party key can be stored without the `external` flag**~~ — **fixed.**
  `Session.storeAPIKey` now writes the `external` property unconditionally in the external
  branch (the AppID attachment stays conditional on both parts being present), so an imported
  vendor key always reads external and `rotateAPIKey` can never overwrite a secret NoSneak did
  not mint. Guarded by `APIKeyRoundTripTest.createSkipsAppIDWhenOnlyOnePartProvided` and
  `SessionAICredentialSourceTest`. `storeAPIKey` also **returns the created `SubjectAPIKey`**
  now — `SessionAICredentialSource.addAPIKey` (the assistant Providers page's New Key path)
  needs it to enable the key and hand it back for discovery.
- ~~**`loginAPIKey` can authenticate with a null principal**~~ — **fixed.** Zero identifiers now
  clears `subjectIdentifier` and throws instead of flipping `authenticated`.
- ~~**Clipboard secret never cleared**~~ — **fixed 2026-10-27.** Both **Copy** actions of
  `SubjectPanel` go through gui-audio's `GUIUtil.copyToClipboard(text, SECRET_CLIPBOARD_MILLIS)`:
  a one-shot Swing `Timer` wipes the clipboard after 60 s, and only when it still holds exactly
  that secret (`clearClipboardIfHolding`; a later copy by the user is left alone). The tooltip
  says so. `GUIUtilClipboardTest` pins the guard on a private clipboard.
- **`char[]` secrets are never zeroed** (`LoginPanel`/`SubjectPanel`). Wipe the arrays
  (`Arrays.fill(pwd, '\0')`) in a `finally`. Partial only: `Session` immediately does `new
  String(secret)` for the backend API, and that immutable copy can't be wiped — so this shrinks
  the exposure window but can't close it without a `char[]`-accepting backend.
- ~~**Inconsistent signed-in guards in `Session`.**~~ — **fixed 2026-10-27.** One private
  `requireSignedIn()` (both fields, one wording `"Not signed in"`) replaced the twelve inline
  checks and their three spellings; the tests that pinned `"Not Logged in"` follow.
- ~~**Identifier validation was dropped.**~~ — **settled 2026-10-27.** The backend enforces both:
  `addPrincipalID` refuses a blank and a duplicate (store unique index), `deletePrincipalID`
  refuses the last principal in a transaction. The commented-out guards are deleted;
  `addIdentifier` gained the signed-in guard it lacked and `removeIdentifier` a readable
  `"Cannot remove the only identifier"` ahead of the manager's refusal. `StoreHardeningTest`
  covers the duplicate on a real store.
- ~~**`showEditAPIKey` calls `setText(null)`**~~ — gone; no `setText(null)` remains in `SubjectPanel`
  (verified 2026-10-26).
- ~~**External favicon fetch on the login screen** (`LoginPanel`)~~ — gone with the redesign: the
  app fetches nothing at start-up and `LoginPanel` is `UnlockPanel` now (verified 2026-10-26).

### Correctness issues found in the last review pass (`no-sneak-app`)

- ~~**The Edit-API-key card shared the Add dialog's provider combo**~~ — **fixed.** `inProvider`
  was on both the add input card (rebuilt per dialog open) and the edit card (built once), so
  Swing's one-parent rule let Add steal the control, the edit card read *its* selection on save
  (silently rewriting the key's `provider`, which is what `AIAPIProvider.resolveType` keys off),
  and `Objects.requireNonNull(getSelectedItem())` threw after a cancelled Add. `keyProvider` is
  now an editable `JComboBox` owned by the edit card — it was already being populated, just
  never displayed. Both call sites read through `comboText(...)`, which takes the **editor's**
  item when the combo is editable, so a typed custom provider is not dropped when you click
  Save without committing.
- ~~**Deleting a chat orphans its message rows.**~~ — **fixed 2026-10-27**: `deleteChat` passes
  `withReference=true`; the cascade semantics were read off `H2PDataStore.deleteByGuid` (DB-driven,
  shared children kept) and `StoreHardeningTest` pins the result on a real store.
- **Clearing the Provider field unlinks a key from the assistant** — by design, and reported:
  `reloadProviders` says "unrecognized provider type" at login while `assistant-enabled` stays
  `true`. Since 2026-10-27 `changeAPIDetails` removes the entry instead of writing `""`, so the
  key reads as *no provider* rather than an empty one; same behaviour, clean property bag.
- ~~**Every registration failure reads "That username is already taken"**~~ — **fixed 2026-10-05**:
  only the duplicate-principal failure maps to it; anything else reads
  `"Registration failed: <root cause>"` (which is how the ≥ 8-character principal rule showed up).
- ~~**`Main.main` does not handle a failed `connect()`** on the `ds.*` param path~~ — the param
  path now prints the reason and exits with status 2 (no stack trace, no window); the setup
  screen still surfaces it in a dialog.
- ~~**`LoginPanel`'s Enter binding always runs `passwordAction()`**~~ — obsolete: `LoginPanel` was
  replaced by `UnlockPanel` in the 2026-10-24 redesign, which has one password form and no
  ancestor-level Enter binding (verified 2026-10-26).

> Considered and **not** treated as issues: menu items are unreachable while signed out (the whole
> `JMenuBar` is hidden until auth); values render in `JTextField`s with no HTML, and AppID/domain
> are filter-validated. **Re-check for the H2 store:** the store is now **SQL** (H2), so injection
> safety rests on `H2PDataStore` issuing parameterized JDBC rather than string-built SQL — confirm
> that before relying on it. Store location/credentials come from the `ds.*` params or the setup
> screen, not a hardcoded URL.
