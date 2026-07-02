# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak security tooling. This package contains the
application entry point and a **mock** UI prototype that wires together the screens,
navigation, and a stubbed session/security layer. The mock exists to prove out the UX
and screen flow ahead of binding the real PQC scanner and security backend.

> **Status:** prototype. The session layer (`mock.utility.Session`) is backed by zoxweb's
> **`DomainSecurityManagerDefault`** — a real `DomainSecurityManager` over a
> `MockAPIDataStore` wired in `Main`, which also **seeds a `kailen` / `Password1!` user** so
> you can log in without registering each run. Working end-to-end against it:
> username/password **register + login**, **change password**, **add/remove identifiers**,
> and **profile save/load** (name/address stored in the subject's property bag). Blocking
> calls (login/register/change-password) run **off the EDT** via `BackgroundTask`.
> Still stubs: **API-key/passkey** (login/register return `false`), the security-manager
> admin tables, and the scanner/file-sharing screens.

## Layout

```
io.xlogistx.nosneak.app
├── Main.java                      ← entry point + top-level JFrame
└── mock/                          ← prototype UI (screens, menu, mock security)
    ├── AppShell.java              ← root content pane, CardLayout host
    ├── LoginPanel.java            ← login/register screen (method + mode toggle)
    ├── PQCRegistryPanel.java      ← PQC file-sharing registry view
    ├── SubjectPanel.java          ← subject account view (master–detail)
    ├── SubjectSecManagerPanel.java← security-manager admin view (master–detail)
    ├── ScanPanel.java             ← network scanner view (placeholder)
    ├── MenuBarFactory.java        ← builds the application menu bar
    └── utility/
        ├── AppContext.java        ← per-app service locator (Session + Navigator)
        ├── Session.java           ← auth + identifiers + credentials + profile (over DomainSecurityManager)
        ├── Navigator.java         ← top-level screen switching over a CardLayout
        ├── CardStack.java         ← reusable CardLayout wrapper (in-panel sections)
        ├── PanelBuilder.java      ← shared Swing layout helpers
        ├── ListSection.java       ← titled, refreshable list (rows + add/edit/remove)
        └── BackgroundTask.java    ← SwingWorker helper: run work off the EDT, result back on it
```

## Entry point

### `Main`
Bootstraps the app: installs the FlatLaf **FlatLightLaf** look-and-feel and shows
`Main.AppFrame` on the Swing EDT. The nested `AppFrame` (a `JFrame`, 800×600,
title "NoSneak") constructs `new DomainSecurityManagerDefault().setDataStore(new
MockAPIDataStore())`, **seeds a `kailen` / `Password1!` subject** (`createSubjectID` +
bcrypt) so there's a login on a fresh run, creates the single `AppContext` from it, builds
the menu bar via `MenuBarFactory`, and installs `AppShell` as the content pane. The menu
bar starts hidden and is toggled visible/invisible by subscribing to
`session().onAuthChange(...)` — it only appears once the user is authenticated.

## `mock` — UI screens & wiring

### `AppShell`
The root panel (`BorderLayout`). Hosts a `CardLayout` content area registering one card
per `Navigator.Screen` (`LOGIN`, `MAIN`, `SUBJECT`, `SCAN`, `MANAGER`) plus a footer
status bar. On construction it builds the `Navigator`, registers it on the `AppContext`,
and wires `session().onAuthChange(...)` so that a successful auth navigates to `SUBJECT`
and a logout navigates back to `LOGIN`. The footer (left: `session: … | subject: …`,
right: status) also subscribes to auth changes. Starts on the `LOGIN` screen.

### `LoginPanel`
The authentication screen, registered as the `LOGIN` card. Built on a `GridBagLayout`
with the NoSneak branding (icon/title/wordmark) above the credential area. Two orthogonal
selectors:

- **Method** (a `JToggleButton` group over a `CardStack`): `Subject / Password`,
  `API Key`, `Passkey` — switches which credential card is shown.
- **Mode** (a toggle button): flips between **Login** and **Register**. The mode
  re-labels each method's action button and changes which `Session` call it makes
  (`login*` vs `register*`); it is not a separate set of cards.

`applyMode()` adapts the password card and selectors to the current mode:
- In **Register** mode the password card reveals a **Confirm Password** field;
  submission compares it against the password and blocks (error dialog) on mismatch.
  Switching back to **Login** hides and clears it.
- **API key is login-only**: the API Key selector is hidden in Register mode (you can't
  register with an API key), and selecting it while switching to Register falls back to
  the Password card.
- **Passkey is hidden everywhere** for now (`passkeySelector.setVisible(false)`); its card
  is a "NOT IMPLEMENTED" placeholder.

The password card also has an optional **DomainAppID** field. Field rows are laid out by
`PanelBuilder.buildJPanelWithFields(JComponent...)`.

The password action captures the field values on the EDT, then runs the `Session` call
**off the EDT** via `BackgroundTask.runReason(...)` (so bcrypt/round-trips never freeze the
UI, and the action button is disabled while in flight). Reporting: failed login →
"Invalid Credentials"; register confirm-mismatch → "Passwords do not match" (an instant
EDT check *before* the worker); register success → "Registered Successfully" (clears fields
and flips to Login mode). Login *success* shows no dialog — the `"authenticated"` event
navigates away. The API-key/passkey actions are wired to `Session` but those methods are
stubs that return `false`, so those tabs currently do nothing (no feedback).

> Known gap: register only returns `boolean`, so a **taken username** currently shows the
> password-rules message. See *Needed fixes → Register flow*.

### `PQCRegistryPanel`
The `MAIN` screen — PQC file-sharing registry. A `JSplitPane` with a `TreeTextWidget`
(file tree, from `io.xlogistx.gui`) on the left and a `JTable` global registry
(columns: *Public Key*, *Documents*) on the right.

### `SubjectPanel`
The `SUBJECT` screen — the signed-in subject's own account view, a **master–detail**
(`JToggleButton` selectors + `CardStack`, assembled by `buildDefaultSplitPanel`). Both
sections are wired to `Session` for real. Because the panel is built once (before login),
it subscribes to `onAuthChange` and, on **both** login and logout, calls
`identifiers.refresh()` / `credentials.refresh()` / `populateProfile()` — repopulating on
login and clearing on logout (the `Session` getters return empty when signed out).

- **Profile** — First/Last name, an **Identifiers** list, Date of birth, and a **Mailing
  address** block (Street/City/State/Postal/Country), plus **Save Changes**. Wrapped in a
  `JScrollPane`.
  - **Identifiers** is a `ListSection` bound to `Session.getAllPrincipalIDForLoggedInUser()`.
    **+ Add identifier** prompts for a value → `Session.addIdentifier` (dedupe/validation),
    per-row **Remove** → `Session.removeIdentifier` (guarded against removing the last one).
    Both surface the returned reason string on failure. There is no *Principal IDs* card —
    identifiers live here.
  - **Save Changes** collects the name/DOB/address fields into a map and calls
    `Session.saveProfile(...)`; `populateProfile()` reads them back via `Session.loadProfile`
    (stored in the subject's property bag). *(No verification/canonical-ID/status metadata —
    the model has no such fields; see below.)*
- **Login credential** (card key `Credentials`) — a nested `CardStack` (`credentialCards`)
  with a **list** view and a **change-password** view. The list is a `ListSection` bound to
  `Session.getAllCredentialForLoggedInUser()`: the **Password** row's **Edit** flips to the
  change-password form (current/new/confirm → `Session.changePassword` via `BackgroundTask`,
  off the EDT); non-password credentials render as "… — not editable". **+ Add login
  method** is a stub dialog (no non-password credential impl exists).

The **Simple/Technical** toggle is still not built — see *Target behaviour*.

### `SubjectSecManagerPanel`
The `MANAGER` screen — an admin view over the security model (the UI front for zoxweb's
`DomainSecurityManager`). Same **master–detail** shape as `SubjectPanel`
(`JToggleButton` selectors + `CardStack` + `PanelBuilder.buildDefaultSplitPanel`), with
five sections, each a header + description + search bar + `JTable` stub. Each table is
wrapped in a `JScrollPane` so its column header row renders, and each carries a trailing
unlabeled (`""`) actions column reserved for per-row controls (edit/remove):

- **Subjects** — security subjects and their principals, credentials, and grants
  (columns: Name, Primary principal, Owns, ⋯actions).
- **Permissions** — permission definitions, scoped by application/AppID
  (columns: Permission, Description, ⋯actions).
- **Roles** — named bundles of permissions (columns: Role, Description, ⋯actions).
- **Role groups** — bundles of roles granted together (columns: Role Group, Roles, ⋯actions).
- **Grants** — permission/role/role-group grants bound to subjects
  (columns: Subject, Grant Type, Granted, ⋯actions).

All tables are empty `DefaultTableModel` stubs; search and the actions column are not
wired. Reached from **View → Subject Security Manager**.

> Scope distinction: `SubjectPanel` manages **your own** account; `SubjectSecManagerPanel`
> is the **admin** view over all subjects/permissions/roles/grants.

### `ScanPanel`
The `SCAN` screen — network scanner view. Placeholder ("NOT IMPLEMENTED"); intended to
front the NMap/PQC scanning backend.

### `MenuBarFactory`
Builds the application `JMenuBar`: `File`, `View`, `Tools`, `Help`, and a right-aligned
`Mode` menu (with a "Technical Mode" checkbox). **File** has a placeholder *Test* item and
**Logout** (`session().logout()`). The **View** items navigate via the `AppContext`'s
`Navigator` — *Network scanner* → `SCAN`, *PQC file sharing* → `MAIN`, *Subject Profile* →
`SUBJECT`, *Subject Security Manager* → `MANAGER`.

#### Navigation model
The app uses **two independent navigation layers**, deliberately kept separate:

- **Top menu bar (`JMenuBar`)** — app-level destinations. The **View** menu drives the
  `Navigator` between top-level screens: *Network scanner* → `SCAN`, *PQC file sharing* →
  `MAIN`, *Subject Profile* → `SUBJECT`, *Subject Security Manager* → `MANAGER`. (There is
  no separate "Subject" menu; the subject screen is reached from **View → Subject
  Profile**.)
- **Left selector inside a panel** — sub-section switching *within* a screen, via a local
  `CardStack` (e.g. `SubjectPanel`'s Profile / Login credential, or
  `SubjectSecManagerPanel`'s Subjects / Permissions / Roles / Role groups / Grants). This
  is local to the panel and does **not** go through the top-level `Navigator`.

In short: the top menu chooses *which screen*; a panel's left selector chooses *which
section of that screen*. They are separate `CardLayout`s (the in-panel ones wrapped by
`CardStack`).

### Security backend — `DomainSecurityManagerDefault` (zoxweb)
`Main.AppFrame` constructs zoxweb's `org.zoxweb.server.security.DomainSecurityManagerDefault`
over a `MockAPIDataStore` and passes it to `AppContext` → `Session`. It implements the full
security model — subject/principal/credential CRUD, the permission/role/role-group catalog,
and grants — with the same keying the code relies on: `login(principalID, credential)`
resolves the principal to its subject and validates the `PASSWORD` `CIPassword` via
`SecUtil.isPasswordValid` (throws `SecurityException` on mismatch); identifiers are keyed by
**subjectGUID** and credentials by **principalID**. Two behaviours to know:
- **Seeded, not empty** — `Main` seeds `kailen` / `Password1!`, so you can log in immediately;
  the store is still in-memory (wiped on restart).
- **`createSubjectID` throws on a duplicate** principal (`"principal already exists"`) — unlike
  the old mock. `registerUsernamePassword` catches this and returns `false`.

> The subject's profile fields (name/DOB/address) are stored in the `SubjectIdentifier`'s
> inherited `PropertyDAO` property bag (`getProperties()` → `NVGenericMap`), persisted via
> `updateSubjectID` — the schema itself has no such fields. Round-trip (save/load, overwrite,
> across logout/login) is covered by `ProfileRoundTripTest`.

## `mock.utility` — application services

### `AppContext`
Lightweight per-application service locator. Constructed in `Main.AppFrame` with the
`DomainSecurityManager`, from which it builds the single `Session`; also holds the
`Navigator` (injected by `AppShell` once the card host exists). Accessors: `session()`,
`nav()`, `setNavigator(...)`. Passed down to screens and the menu factory so they share
one session and one navigator.

### `Session`
Authentication/session state built on `PropertyChangeSupport`, holding the shared
`DomainSecurityManager`, the current `subject` (**principalID** — the username, *not* the
GUID) and its `subjectIdentifier`. Two result conventions coexist deliberately:
- **`boolean`** for auth (`loginUsernamePassword` / `registerUsernamePassword` /
  `loginAPIKey` / `loginPasskey` / `register*` / `logout`) — success/failure.
- **reason `String`** for account edits (`addIdentifier`, `removeIdentifier`,
  `changePassword`) — `null` = success, else a human-readable message the panel shows.
  Failure is a return value, never a broadcast event.

Auth (username/password is real against the store):
- `loginUsernamePassword` calls `login(subject, new String(password))`, catching
  `SecurityException` → `false`; on success it stores `subject` (the **principalID**, since
  `SubjectIdentifier.getSubjectID()` returns the GUID) and the `subjectIdentifier`, flips
  `authenticated`, fires the event. Use `new String(password)`, **not** `Arrays.toString`.
- `registerUsernamePassword` gates on `FilterType.PASSWORD`, persists a bcrypt `CIPassword`
  via `createSubjectID`, and catches the duplicate-principal `SecurityException` → `false`.
- `loginAPIKey` / `loginPasskey` / `registerAPIKey` / `registerPasskey` are stubs that
  **return `false`** (no concrete non-password credential impl exists).

Account data (all backed by `DomainSecurityManager`, keyed off the signed-in subject):
- `getAllPrincipalIDForLoggedInUser()` — identifiers, via `lookupAllPrincipalIdentifiers(
  subjectIdentifier.getGUID())` (keyed by GUID); returns empty when signed out.
- `getAllCredentialForLoggedInUser()` — credentials, via `lookupAllPrincipalCredentials(subject)`.
- `addIdentifier` — rejects blank/duplicate (`lookupPrincipalID`), else `addPrincipalID`.
- `removeIdentifier` — refuses to remove the **last** identifier; if you remove the one you
  logged in as, it **repoints `subject`** to a survivor so credential lookups keep working.
- `changePassword` — verifies the current password, validates the new one, then updates the
  existing `CIPassword` **in place** (`updateCredential`, keyed by GUID) — atomic, never a
  password-less window.
- `saveProfile(Map)` / `loadProfile(String...)` — name/DOB/address in the subject's
  `PropertyDAO` property bag (`getProperties()`), persisted via `updateSubjectID`.

State changes fire an `"authenticated"` property event; listeners subscribe via
`onAuthChange(...)` — how `AppFrame` toggles the menu bar and `AppShell`/`SubjectPanel`
react on login/logout.

### `Navigator`
Thin top-level screen-switcher over a `CardLayout`. Defines the `Screen` enum
(`LOGIN, REGISTER, MAIN, SCAN, SUBJECT, MANAGER`) and `show(Screen)` flips the shared
content panel to the matching card (cards are keyed by `Screen.name()`). Note: `REGISTER`
is currently **unused** — register is a *mode* of the `LOGIN` screen, not its own
screen/card.

### `CardStack`
A small reusable wrapper around a `CardLayout` + backing `JPanel`, used for **in-panel**
section switching (distinct from the top-level `Navigator`). API: `view()` returns the
card host, `add(Component, name)` registers a card, `show(name)` flips to it. Used by
`LoginPanel` (method cards), `SubjectPanel`, and `SubjectSecManagerPanel` (section cards).

### `PanelBuilder`
Shared Swing layout helpers (formerly `PaneBuilder`):
- `buildHorizontalSplitView(left, right, divLocation, resizeWeight)` — a configured
  `JSplitPane`.
- `buildDefaultSplitPanel(content, JToggleButton...)` — the standard master–detail shell:
  a left sidebar of grouped toggle buttons (a `ButtonGroup`) and the supplied `content` on
  the right, wired through `buildHorizontalSplitView`.
- `buildJPanelWithFields(JComponent...)` — a single-column `GridBagLayout` form stacking
  the given components vertically.
- Also has `row(...)`, `group(...)`, `detail(title, onBack, content)` (a back-linked detail
  view, used by the change-password form), and `listPage(...)` — the last is **superseded by
  `ListSection`** for data-driven lists and kept only for static ones.

### `ListSection`
A titled, refreshable list component. Constructed with a title, an add-button label + action,
and a `Supplier<List<Entry>>` data source; `refresh()` rebuilds the rows from the supplier
(call it after any mutation). Each `Entry(label, onEdit, onRemove)` renders a row with
optional per-row **Edit**/**Remove** buttons (null handler hides that button). Used by
`SubjectPanel` for the Identifiers and Login-credentials lists.

### `BackgroundTask`
A `SwingWorker` helper so blocking work never runs on the EDT. `run(owner, toDisable, work,
onDone)` runs `work` (a `Callable<T>`) off the EDT and delivers the result to `onDone` on the
EDT, disabling `toDisable` while in flight and showing any thrown exception as a dialog.
`runReason(owner, toDisable, work, onSuccess)` is the convenience for the reason-string
convention: a non-null reason is shown as an error dialog, `null` runs `onSuccess`. Used by
`LoginPanel` (login/register) and `SubjectPanel` (change password).

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
        └─ ScanPanel            (SCAN)                                  │  (logout → LOGIN)
                                                              Session ◄─┘
```

The flow is event-driven through `Session`'s property-change events: screens and the
frame react to auth changes rather than calling each other directly, with `AppContext`
providing the shared `Session`/`Navigator` and `Navigator` centralizing all top-level
screen transitions (in-panel section transitions go through each panel's own `CardStack`).

## Target behaviour (not yet built)

Design intent for the parts of `SubjectPanel` that aren't built yet — what *is* built is
described under `SubjectPanel` above.

### Tier toggle (Simple / Technical)
A single Technical-mode flag mirrored in two synced controls: the `Mode` menu's "Technical
Mode" checkbox (`MenuBarFactory`) and a top-right toggle in `SubjectPanel` — **neither wired
yet**. **Technical** reveals underlying detail (schema field names, `NS*` tokens, SPKI
fingerprints, KEM/algorithm specifics); **Simple** hides them. Presentational only — it
changes *how much* is shown, never *what you can do*.

### Login-credential types (security model)
Intended per-type behaviour once non-password credentials exist (today only **Password** is
built; the rest render as "not editable"):
- **Password** — *write-only*: never shown or recovered; the only op is *replace* (current +
  new × confirm). Stored as a verifier.
- **API key** — a *retrievable shared secret*: masked by default, with **Reveal**, **Copy**,
  **Rotate** (new + invalidate old), **Revoke**. *(Reveal-on-demand implies the backend keeps
  the raw secret; show-once-at-creation + store-a-hash is an open alternative.)*
- **Passkey** — only the *public key* is held; manage = view device + remove.

**+ Add login method** would register an additional credential of any type.

### Identifier & profile metadata
All target-only, because the model has nowhere to store them: per-identifier **status**
(primary/alias/verified) and **type** (email/username/handle), identifier **rename**,
**verification-before-active** for new/changed identifiers, a minimum-one-email rule, and a
gated **Canonical ID** field. `PrincipalIdentifier` carries just the id string.

## Needed fixes / updates

Tracked work items for the `mock` UI.

### Register flow (`LoginPanel` / `Session`)
- ~~**Password filter / validation fails silently.**~~ **Done.** A filter rejection now
  surfaces a detailed password-requirements dialog and keeps the user on the register form.
  Remaining gap: because `registerUsernamePassword` returns `boolean`, a **duplicate
  username** also shows that same password-rules message — switch to the reason-string
  convention to distinguish "username already taken".
- **Confirmation warning on Register.** Clicking **Register** must prompt a confirmation
  dialog before proceeding (e.g. "Register using this email / username?"). *(Still
  missing — register proceeds straight to the filter/persist call.)*

### Method availability (`LoginPanel`)
- **API key is add-only, never register.** Registration via API key is already removed
  from the UI; API keys are *attached* to an existing account from the Subject panel's
  *Login credentials*, not created at registration.
- **Passkey hidden everywhere.** The Passkey method is not implemented — it stays hidden in
  **both** login and register modes via `passkeySelector.setVisible(false)` until built
  out.

### Subject panel (`SubjectPanel`)
- **Tier toggle not wired.** The `Mode` menu's "Technical Mode" `JCheckBoxMenuItem` has no
  action listener, and `SubjectPanel` has no toggle. Add the toggle, back both controls
  with a single shared Technical-mode flag, and make Simple/Technical actually
  show/hide the underlying detail (per the *Tier toggle* contract above).
- ~~**Profile is static.**~~ **Done** (persistence). **Save Changes** writes name/DOB/address
  to the subject's property bag (`Session.saveProfile`) and reloads via `loadProfile`. Still
  target-only: Email-change verification and a gated Canonical ID field.
- ~~**Identifiers folded into Profile, not yet built.**~~ **Done** (core). Built as a
  `ListSection` with add + guarded remove. Still target-only (no model fields): per-entry
  status/type, Edit/rename, verification-before-active, and a minimum-one-email rule.
- **Login credentials — password done, rest stubbed.** Password replace is built (change
  form → `Session.changePassword`, atomic, off-EDT). Still stubbed: passkey
  view-device/remove and API-key reveal/copy/rotate/revoke, and **+ Add login method** —
  all blocked on a non-password `CredentialInfo` implementation.

### Subject Security Manager (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects /
  Permissions / Roles / Role groups / Grants tables to the `DomainSecurityManager`
  catalog (`getPermissions()`, `getRoles()`, `getRoleGroups()`, the grant getters, etc.)
  and make the per-section search bars filter. The backend exists
  (`DomainSecurityManagerDefault`); the panel just isn't wired to it yet, and the in-memory
  store has no seeded catalog data.

> These are UI/UX gaps in the prototype. The username/password session path — plus
> identifiers, change-password, and profile save/load — is real against
> `DomainSecurityManagerDefault`, but the API-key/passkey `Session` methods still return
> `false` (no non-password credential impl) and the security-manager admin tables are
> unbound, so those areas still need wiring alongside the UI work.