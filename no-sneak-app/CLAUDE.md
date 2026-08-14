# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak security tooling. Contains the application entry point
and the **`ui`** package that wires together the screens, navigation, and the session/security
layer. It began as a UX prototype but now runs a **real** session/security layer and a **working
network scanner screen** over `no-sneak-core`; the PQC file-sharing screen is still a placeholder.

> **Status.** The session layer (`ui.utility.Session`) is backed by zoxweb's
> **`DomainSecurityManagerDefault`** — a real `DomainSecurityManager` over an **encrypted H2**
> `H2PDataStore` (`jdbc:h2:file:<dir>/no-sneak;MODE=PostgreSQL;CIPHER=AES`, built by
> `H2PDSCreator`). `Main` opens the store from either `ds.*` launch parameters or the first-run
> **Data Store Setup** screen. The store **persists across restarts** and is **not seeded**, so
> a fresh database has no accounts — register one before you can log in.
>
> Working end-to-end: username/password **register + login**, **change password**,
> **add/remove identifiers**, **profile save/load** (name/DOB), a **multi-address book**, and the
> **full API-key lifecycle** (generate or import → login → edit → rotate → delete). API keys are
> stored **plain** (raw URL-Base64, no hashing), so `loginAPIKey` looks them up as-is; imported
> keys also carry AI-assistant metadata (`provider`, `base-url`, `auth-type`, `header-name`) on
> their property bag. All blocking `Session` calls run **off the EDT** via
> `BackgroundTask.runCatching` (failures surface as a dialog from the thrown `SecurityException`).
>
> **The `SCAN` screen is real now.** `ScanPanel` fronts `no-sneak-core`'s v2 engine: the command
> box takes the full `NMap` CLI surface through `NMap.parseCommand`, a probe selector ticks
> bundled and subject-authored probes into the run, results persist as `ReportContent` rows, and
> probes persist as `ProbeContent` rows (both DAOs live in `no-sneak-core`'s
> `io.xlogistx.nosneak.v2.data`). It is also wired to the assistant **both ways** — a scan result
> can be sent into a chat, and a chat response can be saved back as a probe. See `ScanPanel` below.
>
> **Still stubbed:** passkey (login/register are empty `void` no-ops), the security-manager admin
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

## Layout

```
io.xlogistx.nosneak.app
├── Main.java                      ← entry point; opens the H2P store (ds.* params or setup screen) + JFrame
└── ui/                            ← UI (screens, menu, session/security wiring)
    ├── AppShell.java              ← root content pane, CardLayout host (mounts ai-assistant's AssistantPanel)
    ├── LoginPanel.java            ← login/register screen (method + mode toggle)
    ├── DataStoreSetupPanel.java   ← first-run screen: choose location + DB/encryption credentials
    ├── PQCRegistryPanel.java      ← PQC file-sharing registry view
    ├── SubjectPanel.java          ← subject account view (master–detail)
    ├── SubjectSecManagerPanel.java← security-manager admin view (master–detail)
    ├── ScanPanel.java             ← network scanner: command box, probe selector, results, probe editor
    ├── MenuBarFactory.java        ← builds the application menu bar
    ├── assistant/                 ← app-side bindings for the ai-assistant module
    │   ├── SessionAICredentialSource.java ← the subject's API keys + which are assistant-enabled (AICredentialSource)
    │   └── AssistantStorage.java  ← AIRepository impl (chats + skills + provider configs), GUID-keyed over the H2P APIDataStore
    └── utility/
        ├── AppContext.java        ← per-app service locator (Session + Navigator)
        ├── Session.java           ← auth + identifiers + credentials + profile + addresses (over DomainSecurityManager)
        └── Navigator.java         ← top-level screen switching over a CardLayout

(The `CardStack` / `PanelBuilder` / `ListSection` / `BackgroundTask` helpers live in the shared
`io.xlogistx.gui` toolkit — `xlogistx-gui-audio` — not in this module.)
```

## Entry point

### `Main`
Bootstraps the app. `main` first parses `ds.*` launch parameters (`ParamUtil.parse("=", args)`):
`ds.user`, `ds.password`, `ds.enc-password`, `ds.location` (a directory). If **all four** are
present it opens the encrypted H2 store directly — `createDataStore(...)` builds the JDBC URL via
`H2PUtil.defaultH2JdbcURL(location, "no-sneak")`, creates the `H2PDataStore` through
`H2PDSCreator`, connects, and wraps it in a `DomainSecurityManager` (`createDomainSecManager`:
`OPSecUtil.singleton()` + a `DomainSecurityManagerDefault` with `CIPassword` and `SubjectAPIKey`
registered). It then installs FlatLaf **FlatLightLaf** and launches on the EDT.

Two entry paths, chosen by whether a manager was built from the params:
- **Params present** → `launchApp(dsm)` goes straight to the app.
- **No params** → `showSetup(...)` displays `DataStoreSetupPanel` (choose location + DB
  username / password / encryption password); on completion it builds the store the same way and
  then `launchApp(dsm)`.

`launchApp(DomainSecurityManager)` opens `Main.AppFrame` (a `JFrame` titled "NoSneak", sized
**relative to the display** — 60 % of screen width × 70 % of screen height from
`Toolkit.getDefaultToolkit().getScreenSize()`, then centred; the old fixed 800×600 is commented
out just above it. `getScreenSize()` reports the **primary** display, so on a multi-monitor setup
the frame is sized off that one regardless of where it opens),
which creates the single `AppContext` from the manager, builds the menu bar via `MenuBarFactory`,
and installs `AppShell` as the content pane. The menu bar starts hidden and is toggled by
`session().onAuthChange(...)` — it only appears once authenticated. `AppFrame` is `EXIT_ON_CLOSE`
and adds a `windowClosing` handler that calls `ctx.session().closeNio()` and then
`domainSecurityManager.getDataStore().close()`, so the
encrypted H2 store is flushed/closed on exit rather than left to the JVM teardown. (The datastore is
closed on **app close only**, not on logout — logout keeps it open for the next sign-in.)

> Passing secrets via `ds.*` on the command line exposes them (process list, shell history,
> run-config files), so treat that path as a dev convenience and prefer the setup screen.
> Pointing the params at an existing store with the **wrong encryption password** fails
> `connect()` (surfaced as the setup panel's error dialog).

## `ui` — UI screens & wiring

### `AppShell`
The root panel (`BorderLayout`). Hosts a `CardLayout` content area registering one card per
`Navigator.Screen` (`LOGIN`, `MAIN`, `SUBJECT`, `SCAN`, `MANAGER`, `ASSISTANT`) plus a footer
status bar. On construction it builds the `Navigator`, registers it on the `AppContext`, and
wires `session().onAuthChange(...)` so a successful auth navigates to `SUBJECT` and a logout back
to `LOGIN`. The same handler also drives the assistant across the auth boundary: on **login** it
calls `assistantPanel.reloadProviders()` + `refreshHistory()` + `refreshSkills()`; on **logout**
`refreshHistory()` + `refreshSkills()` (empty-owner → cleared) + `clearProviders()` + `resetPanel()`
(blanks the composer/transcript and drops the previous subject's selection). The footer (left:
`session: … | subject: …`, right: status) also subscribes to auth changes. Starts on `LOGIN`.

**`AppShell` is also where the scanner and the assistant are joined**, and the order matters:
`assistantPanel` is built first, then `ScanPanel` takes `assistantPanel::sendToChat`, then
`assistantPanel.addSaveTarget("probe", scanPanel::saveProbeFromEditor)` registers the reverse
direction. Both are plain callbacks, so the dependency stays one-way (`no-sneak-app →
ai-assistant`) in both directions of the data flow.

The `ASSISTANT` card is the `ai-assistant` module's
`io.xlogistx.nosneak.ai.assistant.AssistantPanel`, constructed with an `AssistantContext`:
`new AssistantPanel(new AssistantContext(new SessionAICredentialSource(ctx.session()), new
AssistantStorage(ctx.session())))` (`AssistantStorage` takes the `Session` and reads the H2P
`APIDataStore` off it). The context holds
the credential source, the chat/skill repository (`AssistantStorage`, over the same H2P `APIDataStore`
the security manager uses), an internally built `AIProviderRegistrar`, and the current
chat/credential/model selection. This is the **only** coupling point — the dependency runs
`no-sneak-app → ai-assistant`, never the reverse.

### `LoginPanel`
The `LOGIN` card. A `GridBagLayout` with NoSneak branding above the credential area, and two
orthogonal selectors:

- **Method** (a `JToggleButton` group over a `CardStack`): `Subject / Password`, `API Key`,
  `Passkey` — switches which credential card is shown.
- **Mode** (a toggle button): flips between **Login** and **Register**. It re-labels each
  method's action button and changes which `Session` call it makes (`login*` vs `register*`); it
  is not a separate set of cards.

`applyMode()` adapts the password card and selectors to the current mode:
- In **Register** mode the password card reveals a **Confirm Password** field; submission
  compares it against the password and blocks (error dialog) on mismatch. Switching back to
  **Login** hides and clears it.
- **API key is login-only**: the API Key selector is hidden in Register mode, and selecting it
  while switching to Register falls back to the Password card.
- **Passkey is hidden everywhere** (`passkeySelector.setVisible(false)`); its card is a
  "NOT IMPLEMENTED" placeholder.

The password card also has an optional **DomainAppID** field; field rows are laid out by
`PanelBuilder.buildJPanelWithFields(...)`.

The password action captures field values on the EDT, then runs the `Session` call **off the
EDT** via `BackgroundTask.runCatching(...)` (so bcrypt/round-trips never freeze the UI, and the
action button is disabled while in flight). Failures throw a `SecurityException` whose message
the worker shows as an error dialog. Reporting: failed login → "Invalid Credentials"; register
confirm-mismatch → "Passwords do not match" (an instant EDT check before the worker); register
success → "Registered Successfully" (clears fields and flips to Login). Login success shows no
dialog — the `"authenticated"` event navigates away. The **API-key** action calls
`Session.loginAPIKey` (paste a key → sign in) via `runCatching`. The **passkey** action is wired
to a `Session` stub that does nothing.

> `registerUsernamePassword` throws a `SecurityException` on failure, so a **taken username**
> shows "That username is already taken" (distinct from the password-rules message).

### `PQCRegistryPanel`
The `MAIN` screen — PQC file-sharing registry. A `JSplitPane` with a `TreeTextWidget` (file tree,
from `io.xlogistx.gui`) on the left and a `JTable` global registry (columns: *Public Key*,
*Documents*) on the right.

### `SubjectPanel`
The `SUBJECT` screen — the signed-in subject's own account view, a **master–detail**
(`JToggleButton` selectors + `CardStack`, assembled by `buildDefaultSplitPanel`). Both sections
are wired to `Session` for real. Because the panel is built once (before login), it subscribes to
`onAuthChange` and, on **both** login and logout, calls `identifiers.refresh()` /
`credentials.refresh()` / `populateProfile()` — repopulating on login, clearing on logout (the
`Session` getters return empty when signed out).

The **Profile** screen is itself a nested `CardStack` (`profileCards`, built by
`buildProfileArea`) with a **profile** card (the form) and an **editAddress** detail card.

- **Profile** (card key `profile`) — First/Last name, Date of birth, an **Identifiers** list, an
  **Addresses** list, plus **Save Changes**. Wrapped in a `JScrollPane`.
  - **Identifiers** — a `ListSection` bound to `Session.getAllPrincipalIDForLoggedInUser()`.
    **+ Add identifier** prompts for a value → `Session.addIdentifier`; per-row **Remove** (trash
    icon) → `Session.removeIdentifier`. Both surface the thrown `SecurityException`'s message on
    failure.
  - **Addresses** — a `ListSection` bound to `Session.getAllAddresses()`. **+ Add address** opens
    the **editAddress** card blank; each row's **Edit** (pencil) opens it pre-filled; **Remove**
    (trash) confirms then `Session.deleteAddress`. The editAddress card (`buildEditAddress`, via
    `PanelBuilder.detail` for a back arrow) has Label / Street / City / State-region / Postal
    fields, a **Country** combo (from `DataConst.COUNTRIES`), and **Save address** — Add stores a
    fresh `NVGenericMap` via `Session.addAddress`, Edit mutates the selected map in place and
    persists via `Session.changeAddressDetails`. Save requires at least a **Label or Street**
    (blocks with a "Missing information" dialog otherwise).
  - **Save Changes** collects only name/DOB and calls `Session.saveProfile(...)`;
    `populateProfile()` reads them back via `Session.loadProfile`.
- **Credentials** (card key `Credentials`) — a nested `CardStack` (`credentialCards`) with three
  views: a **list**, a **change-password** form, and an **edit-API-key** form (`editAPI`). The
  list card stacks **two** `ListSection`s in a `BorderLayout` (Password `NORTH`, API keys
  `CENTER`), each with an empty-state row ("No password set" / "No API keys yet"):
  - **Password section** (no add button) — the Password row's **Edit** (pencil) flips to the
    change-password form (current/new/confirm → `Session.changePassword` via `BackgroundTask`).
  - **API keys section** — one row per key (`"API key — " + SubjectAPIKey.getName()`); the row's
    **Edit** opens the `editAPI` card. **+ Add API Key** opens the add dialog. The **Generate
    local** path is hidden, so the dialog opens on the **Add third party key** form — a sectioned
    form (`Key` / `Scope` / `Provider endpoint`, built with `PanelBuilder.addSection` + `addRow`):
    **Label**, **Description**, the **API Key** in a masked `JPasswordField` (reveal button),
    App Id / Domain ID, a **Provider** editable combo (Claude / OpenAI / Gemini, or type your
    own), and a **Base URL**. On **Create key** it stores via `Session.storeAPIKey(label,
    description, domainID, appID, rawKey, provider, baseURI, authScheme, headerName, external)`
    with `external = true`; the AppID filters validate the optional domain/app-id pair (invalid →
    `SecurityException`), provider/baseURI go to the property bag, and the list refreshes.
    `storeAPIKey` enforces a non-blank key.
    > Known rework: broader mandatory-field validation (label/description) on this dialog is still
    > to come, and the dialog currently closes on click even on error.
  - The `editAPI` card is fully wired: the secret shows in a masked `JPasswordField` with a
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
    card** (`keyView.add(rotateKey)`) — read the `external`-flag hazard under *Security
    hardening* before putting it back.

> **Icon buttons.** Actions render as `io.xlogistx.gui.IconUtil` SVG icons with tooltips, and the
> vocabulary is deliberately one-meaning-per-icon: **EditIcon** (pencil), **DeleteIcon** (trash),
> **RefreshIcon** (rotate/regenerate **only** — restore-from-backup uses **RollbackIcon**),
> **CopyIcon** → **CheckIcon** on success, **VisibleIcon/InvisibleIcon** (reveal, and as a pair
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
The `MANAGER` screen — an admin view over the security model (the UI front for zoxweb's
`DomainSecurityManager`). Same master–detail shape as `SubjectPanel`, with five sections, each a
header + description + search bar + `JTable` (wrapped in a `JScrollPane`, with a trailing
unlabeled actions column reserved for per-row controls):

- **Subjects** — subjects and their principals, credentials, grants (Name, Primary principal, Owns).
- **Permissions** — permission definitions, scoped by AppID (Permission, Description).
- **Roles** — named bundles of permissions (Role, Description).
- **Role groups** — bundles of roles granted together (Role Group, Roles).
- **Grants** — permission/role/role-group grants bound to subjects (Subject, Grant Type, Granted).

All tables are empty `DefaultTableModel` stubs; search and the actions column are not wired.
Reached from **View → Subject Security Manager**.

> Scope: `SubjectPanel` manages **your own** account; `SubjectSecManagerPanel` is the **admin**
> view over all subjects/permissions/roles/grants.

### `ScanPanel`
The `SCAN` screen — the front end for `no-sneak-core`'s v2 scanning engine. Same master–detail
shape as the other screens (`buildDefaultSplitPanel` + a `CardStack`), with three selectors —
**Scanner** / **Result List** / **Probe Library** — over five cards: `Scan`, `Probe`, `Result`,
`View_scan`, `Edit_probe`.

Constructed as `new ScanPanel(ctx, assistantPanel::sendToChat)`; the second argument is a
`BiConsumer<String,String>` (content, name), so the panel can hand a report to the assistant
without `no-sneak-app` reaching into it for anything else.

**Scanner card.** A `Command` text field plus Run and a usage button, over a split of the probe
selector (left) and the raw result text (right).

- **The command box is the real CLI.** `NMap.parseCommand(String)` — extracted from `NMap.main`
  so the two cannot drift — accepts `-p`, `-sV`, `-Pn`, `-sn`, `-PR`, `-PE`, `--probes`,
  `--icmp-probes`, `--max-inflight`, `--max-rate`, `-t`. The output-file flags (`-oN`…`-oA`) are
  **rejected**, not ignored: a caller holding a string has nowhere to write. Parsing happens on
  the EDT (it is instant and non-blocking) and a bad command shows a dialog with the message plus
  `NMap.usageText()`, rather than reaching `BackgroundTask`'s generic "Unexpected error".
- **Ticked probes are merged into the command, not applied behind it.** `effectiveCommand(...)`
  appends `-sV --probes a,b` (or bare `-sV` when everything is ticked) and the *effective* string
  is what runs, what is shown in the muted `effective:` line under the field, and what is stored
  with the report. Ticking implies `-sV` deliberately: `probeStage` returns early when
  `probeScan` is false, so ticked probes with no `-sV` would silently do nothing.
- Subject-authored probes additionally ride along as `NMapConfig.extraProbes` (parsed
  `ProbeDefinition`s), which is what lets `buildChecker` resolve their names at all.
- **The scan itself** is `scanNetwork(NMapConfig)` → `NMapScanner.scan` on `Session.getNio()`,
  bounded by the shared `NMap.maxWaitMs(cfg)`, rendered as JSON. It runs through `BackgroundTask`
  and **throws** rather than swallowing, so a failure is a dialog and no row is written.

**Probe selector.** A rebuilt-per-refresh panel of checkboxes in two sections — *Bundled probes*
(the 18 classpath definitions, loaded once off the EDT and cached) and *My probes* (stored
`ProbeContent` rows) — each with an "All" box and an empty state. **Ticks are keyed by probe
name**, held in a plain `Set<String>` on the panel: not identity (the stored rows are fresh
instances on every read) and not GUID (bundled definitions have none), and the name is exactly
what `cfg.probe(name)` takes. The All box is placed after the empty-list early return, so
`allMatch` over an empty list can never read as ticked.

**Result List / View scan.** A `ListSection` over `Session.getAllScanResults()` — a **projected**
read that omits `content` — with rows labelled by target and a sublabel of
`<full command>  ·  <timestamp>`. Row actions are *Send to chat*, *View*, and remove. Both View
and Send **re-fetch the full row** by GUID first and bail with a dialog if it misses; sending a
list instance would attach empty content.

**Probe Library / Edit probe.** A searchable `ListSection` over `Session.getAllProbes()` with
add, edit and remove. Both save paths — the editor's Save and `saveProbeFromEditor` (the
assistant's) — go through one `fillProbe(...)` helper that strips a markdown fence, runs
`ProbeDefinitionLoader.parse` (so `validate` rejects unknown actions, dangling transitions and
unreachable terminals), and **takes the name from the parsed definition**. That last part is
load-bearing: the engine matches `--probes` on the name *inside* the JSON, so a typed name that
disagrees yields a probe you can tick but that resolves to `unknown probe '…' (ignored)`.

> **Two-way assistant wiring.** Out: the scan panel, the result rows and the View card all call
> `setSendToChat(content, name)` → the injected `BiConsumer` → `AssistantPanel.sendToChat`, then
> navigate to `ASSISTANT`. A missing chat throws a `SecurityException` whose message the panel
> shows. In: `AppShell` registers `assistantPanel.addSaveTarget("probe", scanPanel::saveProbeFromEditor)`,
> which puts **probe** in the skill editor's "Save as" combo — choosing it routes the editor's
> content here instead of to the skill store. See `ai-assistant/CLAUDE.md` §5.

### `MenuBarFactory` & the navigation model
Builds the `JMenuBar`: `File`, `View`, `Tools`, `Help`, and a right-aligned `Mode` menu (with a
"Technical Mode" checkbox). **File** has a placeholder *Test* item and **Logout**
(`session().logout()`).

The app uses **two independent navigation layers**, deliberately separate:

- **Top menu bar** — app-level destinations. The **View** menu drives the `Navigator` between
  top-level screens: *Network scanner* → `SCAN`, *PQC file sharing* → `MAIN`, *Subject Profile* →
  `SUBJECT`, *Subject Security Manager* → `MANAGER`, *AI Chat* → `ASSISTANT`. (There is no
  separate "Subject" menu.)
- **Left selector inside a panel** — sub-section switching *within* a screen, via a local
  `CardStack` (e.g. `SubjectPanel`'s Profile / Credentials). Local to the panel; does **not** go
  through the top-level `Navigator`.

The top menu chooses *which screen*; a panel's left selector chooses *which section*. They are
separate `CardLayout`s (the in-panel ones wrapped by `CardStack`).

### Security backend — `DomainSecurityManagerDefault` (zoxweb)
`Main.createDomainSecManager(dataStore)` constructs
`org.zoxweb.server.security.DomainSecurityManagerDefault` over the encrypted H2 `H2PDataStore`,
registers `CIPassword` and `SubjectAPIKey` as credential types, and passes it to `AppContext` →
`Session`. It implements the full security model — subject/principal/credential CRUD, the
permission/role/role-group catalog, and grants — with the keying the code relies on:
`login(principalID, credential)` resolves the principal to its subject and validates the
`PASSWORD` `CIPassword` via `SecUtil.isPasswordValid` (throws `SecurityException` on mismatch);
identifiers are keyed by **subjectGUID**, credentials by **principalID**.

- **Persistent, not seeded** — data lives in the encrypted H2 file store and survives restarts,
  but a fresh database has no accounts.
- **`createSubjectID` throws on a duplicate** principal; `registerUsernamePassword` catches this
  and rethrows `SecurityException("That username is already taken")`.

> Profile fields (name/DOB) and the address book are stored in the `SubjectIdentifier`'s inherited
> `PropertyDAO` property bag (`getProperties()` → `NVGenericMap`) — name/DOB as flat keys,
> addresses as a nested `NVGenericMapList` — persisted via `updateSubjectID`; the schema itself
> has no such fields.
>
> **Tests** (`src/test/...`, over an in-memory `MockAPIDataStore`; each registers the credential
> types via `addCredentialType`, mirroring `Main`). Success paths assert `assertDoesNotThrow`,
> failures assert the thrown `SecurityException` (message = the reason): `RegisterRoundTripTest`,
> `ProfileRoundTripTest`, `APIKeyRoundTripTest` (generate → create → login, edit/clear, delete,
> rotate, domain/app-id normalization + validation, external-flag + provider/base-url/auth-type/
> header-name metadata), `ChangePasswordRoundTripTest`, `IdentifierRoundTripTest`,
> `AddressRoundTripTest`, and `AppIDDefaultTest` (the domain + app-id filters directly).
> Surefire is skipped by the parent POM — run with `-DskipTests=false -Dmaven.test.skip=false`.

## `ui.utility` — application services

### `AppContext`
Lightweight per-application service locator. Constructed in `Main.AppFrame` with the
`DomainSecurityManager`, from which it builds the single `Session`; also holds the `Navigator`
(injected by `AppShell` once the card host exists). Accessors: `session()`, `nav()`,
`setNavigator(...)`. Passed down to screens and the menu factory so they share one session and one
navigator.

### `Session`
Authentication/session state built on `PropertyChangeSupport`, holding the shared
`DomainSecurityManager`, the current `principalID` (the username, *not* the GUID; accessor
`getPrincipalID()`) and its `subjectIdentifier`.

Result convention: the account/auth mutators return **`void`** and **throw `SecurityException`**
on failure — the exception message is the human-readable reason the panel shows; success returns
normally. This covers `loginUsernamePassword`, `registerUsernamePassword`, `loginAPIKey`,
`addIdentifier`, `removeIdentifier`, `changePassword`, `storeAPIKey`, `changeAPIDetails`,
`rotateAPIKey`, `deleteAPIKey`, `saveProfile`, and the address mutators. `SecurityException` is
**unchecked**, so callers aren't forced to catch it — `BackgroundTask.runCatching` centralizes the
error dialog off the EDT. Failure is thrown, never a broadcast event. Two exceptions:
- **No-op / `void` stubs** — `loginPasskey` / `registerPasskey` are empty stubs; `logout` always
  succeeds.
- **`generateAPIKey()`** returns a `SubjectAPIKey` value and **throws** `SecurityException` when
  signed out (`"Not signed in"`) or on a crypto failure (`"Could not generate a key"`).

Auth (username/password is real against the store):
- `loginUsernamePassword` calls `login(principalID, new String(password))`, catching the backend
  `SecurityException` and rethrowing `SecurityException("Invalid Credentials")`; on success it
  stores the `principalID` and `subjectIdentifier`, flips `authenticated`, fires the event. Use
  `new String(password)`, **not** `Arrays.toString`.
- `registerUsernamePassword` gates on `FilterType.PASSWORD` (throws the rules message on failure),
  persists a bcrypt `CIPassword` via `createSubjectID`, and catches the duplicate-principal
  `SecurityException` → rethrows `"That username is already taken"`. It does **not** auto-login.
- `loginAPIKey` passes the presented key **as-is** (no hashing) to
  `DomainSecurityManager.loginApiKey(...)`, throwing `SecurityException("API Key Invalid")` on a
  bad key, then resolves the signed-in principal from the returned subject's identifiers.

API-key lifecycle (failures throw `SecurityException`; the raw key is stored **plain**):
- `generateAPIKey()` — a fresh AES-256 key, URL-Base64 encoded, wrapped in a `SubjectAPIKey`; no
  persistence. Throws `"Not signed in"` when signed out and `"Could not generate a key"` on a
  crypto failure.
- `storeAPIKey(label, description, domainID, appID, rawKey, provider, baseURI, authScheme,
  headerName, external)` — stores the raw key verbatim (`setAPIKey(rawKey)`, no hashing) in a
  `SubjectAPIKey` (`STATUS` = ACTIVE) via `createCredential`. The `external` flag drives the
  AppID: when **external** and **both** `domainID`/`appID` are non-blank it attaches an
  `AppIDDefault` (run through `FilterType.DOMAIN` + `AppIDNameFilter`: normalizes case, strips
  `www.`/subdomains) and sets the `external` property `true`; when **not** external it falls back
  to the default `xlogistx.io/nosneak` AppID. An invalid domain/app id → `SecurityException(
  "Invalid domain or app ID")`. AI-assistant metadata is written to the property bag via a
  `putIfPresent` helper keyed by the `Session.APIKeyInfo` enum: `provider`, `base-url`,
  `auth-type`, `header-name`, each only when non-blank. Guards: `"Not signed in"` /
  `"Key cannot be empty"`. *(No key-format validation — a malformed paste is accepted and simply
  never matches at login.)*
- `changeAPIDetails(key, label, description, domainID, appID, provider, baseURI, authScheme,
  headerName)` — updates the key in place via `updateCredential`. Unlike create it **sets**
  blanks (passing empty clears label/description) and **rewrites** the metadata properties every
  save; when both `domainID`/`appID` are non-blank it re-attaches an `AppIDDefault` (invalid pair
  → thrown).
- `isExternalKey(key)` / `providerOf(key)` / `baseUrlOf(key)` / `authTypeOf(key)` /
  `headerNameOf(key)` — read the metadata back off the property bag via the `APIKeyInfo` enum.
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
  All throw `"Not Logged in"` when signed out.

Account data (backed by `DomainSecurityManager`, keyed off the signed-in subject):
- `getAllPrincipalIDForLoggedInUser()` — identifiers, via
  `lookupAllPrincipalIdentifiers(subjectIdentifier.getGUID())`; empty when signed out.
- `getAllCredentialForLoggedInUser()` — credentials, via `lookupAllPrincipalCredentials(principalID)`.
- `getAllCredentialForUserByType(CredentialInfo.Type)` — credentials of one type, via
  `lookupCredentialsBySubjectGUID(subjectIdentifier.getSubjectGUID(), type)`; guards both null args.
- `addIdentifier` — delegates straight to `addPrincipalID`; the Session-side blank/duplicate
  guards are currently **commented out** (see *Needed fixes*).
- `removeIdentifier` — rejects a `null` principal (`"Identifier cannot be empty"`), then calls
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
`io.xlogistx.nosneak.v2.data`, owner-scoped by subjectGUID and stored in the same H2P
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
re-login. The mutators run off the EDT, so that event fires off the EDT too — listeners hop via
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
constructed from the `Session` and reading the H2P
`APIDataStore` off it, owner-scoped by `subjectGUID`. `saveChat` / `saveSkill` /
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

> **`deleteChat` orphans children.** It calls `ds.delete(chat, false)`, and `withReference=false`
> means H2P deletes the chat row plus the cascading join rows but **not** the child entities — the
> `ai_message` / `ai_request` / `ai_response` rows stay in the database indefinitely. Note
> `deleteProviderConfig` passes `true` — the two are inconsistent, deliberately or not; settle it
> once the cascade semantics are confirmed.
>
> **Tests** (`AssistantStorageTest`, 9 green, over a `@TempDir` H2P store): insert assigns GUID +
> owner, update stamps `lastTimeUpdated`, save is an upsert by GUID (an edit must not duplicate
> the row), skills mirror chats, signed-out reads return empty, and — for provider configs — a
> full field round-trip, **one key backing several configs**, upsert-by-GUID, and delete.

### `Navigator`
Thin top-level screen-switcher over a `CardLayout`. Defines the `Screen` enum (`LOGIN, REGISTER,
MAIN, SCAN, SUBJECT, MANAGER, ASSISTANT`) and `show(Screen)` flips the shared content panel to the
matching card (keyed by `Screen.name()`). `REGISTER` is currently **unused** — register is a
*mode* of the `LOGIN` screen, not its own card.

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
        ├─ ScanPanel            (SCAN)     → no-sneak-core v2 engine    │  (logout → LOGIN)
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
- **API key** — built: create → login → edit → rotate → delete. Stored **plain**, so the secret is
  viewable on the `editAPI` card via reveal-on-demand and copyable at any time.
- **Passkey** — only the *public key* is held; manage = view device + remove.

> **API-key ↔ subject linkage.** In zoxweb-core 2.4.0 the backend `loginApiKey` finds the key by
> its stored value (plain, no hash) and resolves the subject via **`sak.getSubjectGUID()`** — the
> same subjectGUID keying password credentials. So an API key **survives identifier churn**:
> removing the identifier it was minted under does not orphan it.
>
> **Storage note.** Keys are persisted **plain** — a deliberate prototype choice so the `editAPI`
> card can reveal/copy the secret on demand. For production you'd hash at rest (`storeAPIKey`
> hashes on store, `loginAPIKey` hashes the presented key the same way), which makes reveal
> impossible and shifts the UX to show-once + rotate-to-recover.

### Identifier & profile metadata
All target-only, because the model has nowhere to store them: per-identifier **status**
(primary/alias/verified) and **type** (email/username/handle), identifier **rename**,
**verification-before-active**, a minimum-one-email rule, and a gated **Canonical ID** field.
`PrincipalIdentifier` carries just the id string.

## Needed fixes / updates

### Register flow (`LoginPanel`)
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
- **`ProbeContent` carries one param.** Just `content`. Everything the list and selector would
  want to show or search on — `service`, `transport`, `ports`, `priority`, `port_scoped`,
  `enabled` — means parsing every blob per row on the EDT. **This is time-sensitive:** H2P's
  `ensureTable` is `CREATE TABLE IF NOT EXISTS` with no `ALTER TABLE`, so once a `probe_content`
  table exists in a store, adding a param makes every save fail until the store is dropped or the
  column added by hand. See the note in `ai-model/CLAUDE.md`.
- **A scan cannot be cancelled.** `future.get` times out but the scan keeps running — pcap
  handles, in-flight connects and the `HostScanner` session all continue with nothing holding a
  reference. `IconUtil.StopIcon` is unused and waiting for this.
- **Reports go on the wire as JSON.** `send to chat` attaches the stored render verbatim, so a
  `/24` is ~53 KB (~15k tokens). The `NORMAL` render is far more compact and more legible to a
  model, but the `ScanReport` is not stored — only its JSON — so switching means also persisting
  the normal render at scan time. Cheaper to decide before the store fills up.
- **`ScanPanelTest` is an empty `try {} catch {}`** that passes unconditionally. The logic worth
  testing moved into `NMap` / `ProbeDefinitionLoader` and is covered there, so this should
  probably be deleted rather than filled in.
- **The probe editor's title field is now output, not input** — `fillProbe` overwrites it from the
  parsed definition. It should be made read-only or relabelled so that reads as intentional.

### Subject Security Manager (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects / Permissions /
  Roles / Role groups / Grants tables to the `DomainSecurityManager` catalog (`getPermissions()`,
  `getRoles()`, `getRoleGroups()`, the grant getters) and make the per-section search bars filter.
  The backend exists; the H2 store has no seeded catalog data.

### Security hardening
From a security pass over the app's own code (issues fixable here, not in the zoxweb dependency),
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
- **Clipboard secret never cleared** (`SubjectPanel`, the **Copy** actions). A copied API-key
  secret sits on the clipboard indefinitely. Add an auto-clear after a timeout (Swing `Timer`,
  ~60 s), guarded to only clear if the clipboard still holds that value.
- **`char[]` secrets are never zeroed** (`LoginPanel`/`SubjectPanel`). Wipe the arrays
  (`Arrays.fill(pwd, '\0')`) in a `finally`. Partial only: `Session` immediately does `new
  String(secret)` for the backend API, and that immutable copy can't be wiped — so this shrinks
  the exposure window but can't close it without a `char[]`-accepting backend.
- **Inconsistent signed-in guards in `Session`.** Some methods guard on `principalID`, others on
  `subjectIdentifier`. Standardize on `subjectIdentifier`.
- **Identifier validation was dropped.** `addIdentifier`'s blank/duplicate guards are commented out
  and `removeIdentifier`'s last-identifier guard was removed, so duplicates can be added and the
  only identifier can be (attempted to be) removed — it fails now only because the backend refuses.
  Restore the guards (or confirm the backend enforces both).
- **`showEditAPIKey` calls `setText(null)`** for keys created without a label/description
  (`getName()`/`getDescription()` return `null`). Null-coalesce to `""`. Low impact, defensive.
- **External favicon fetch on the login screen** (`LoginPanel`). Startup pulls
  `https://xlogistx.io/favicon.ico` (exceptions swallowed) — a minor privacy / supply-chain
  "phone home." Bundle a local icon or drop it.

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
- **Deleting a chat orphans its message rows.** `AssistantStorage.deleteChat` passes
  `withReference=false` to `ds.delete`, so H2P removes the chat row and the join rows but never
  the child entities — every `ai_message` / `ai_request` / `ai_response` row survives, forever.
  Not fixed; confirm the cascade semantics before flipping it to `true`.
- **Clearing the Provider field still unlinks a key from the assistant** — but no longer
  silently. `changeAPIDetails` writes `""` rather than removing the property, `resolveType("")`
  returns null, `AIAPIProvider.create` returns null, and `reloadProviders` skips the key while
  `assistant-enabled` stays `true`. The skip is now **reported** at login ("unrecognized provider
  type"), so the symptom is explained; writing `""` in the first place is the part still to fix.
- **Every registration failure reads "That username is already taken"**
  (`registerUsernamePassword` catches `SecurityException` broadly), so a store or IO failure is
  misreported as a duplicate.
- **`Main.main` does not handle a failed `connect()`** on the `ds.*` param path — a wrong
  encryption password kills the app with a console stack trace and no window, unlike the setup
  screen, which surfaces it in a dialog.
- **`LoginPanel`'s Enter binding always runs `passwordAction()`** regardless of which card is
  showing (`WHEN_ANCESTOR_OF_FOCUSED_COMPONENT`). Harmless while the API-key and passkey
  selectors are hidden; wrong the moment the commented-out `applyMode()` lines are restored.

> Considered and **not** treated as issues: menu items are unreachable while signed out (the whole
> `JMenuBar` is hidden until auth); values render in `JTextField`s with no HTML, and AppID/domain
> are filter-validated. **Re-check for the H2 store:** the store is now **SQL** (H2), so injection
> safety rests on `H2PDataStore` issuing parameterized JDBC rather than string-built SQL — confirm
> that before relying on it. Store location/credentials come from the `ds.*` params or the setup
> screen, not a hardcoded URL.
