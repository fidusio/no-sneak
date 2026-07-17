# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak security tooling. This package contains the
application entry point and a **mock** UI prototype that wires together the screens,
navigation, and a stubbed session/security layer. The mock exists to prove out the UX
and screen flow ahead of binding the real PQC scanner and security backend.

> **Status:** prototype. The session layer (`mock.utility.Session`) is backed by zoxweb's
> **`DomainSecurityManagerDefault`** — a real `DomainSecurityManager` over a **MongoDB**
> `XlogistxMongoDataStore` wired in `Main` (against a local `mongodb://localhost:27017`
> instance). The store **persists across restarts** and is **not seeded**, so a fresh
> database has no accounts — create one via the Register flow before you can log in.
> Working end-to-end against it: username/password **register + login**, **change password**,
> **add/remove identifiers**, **profile save/load** (name/DOB in the subject's property bag),
> a **multi-address book** (add/edit/remove addresses, each a nested `NVGenericMap`), and the
> **full API-key lifecycle** — generate or import a key, **create**, **login**, **edit
> label/description**, **rotate**, and **delete** from the Subject panel. Imported (third-party)
> keys also carry **AI-assistant metadata** — a `provider`, a `base-url`, a free-text **auth scheme**
> (`auth-type`, e.g. `Bearer`), and an optional **header name** (`header-name`, e.g. `x-api-key`) —
> captured on the add/edit form and stored on the key's property bag. API keys are stored **plain** (the raw
> URL-Base64 key, no hashing), so `loginAPIKey` looks them up as-is. The **AI Assistant** screen
> (`ASSISTANT`, reached via **View → AI Chat**) hosts the `ai-assistant` module's `AssistantPanel`,
> fed **all** the subject's API keys through a `SessionAICredentialSource` adapter. All blocking `Session` calls (login/register/change-password, add/remove identifier,
> create/rotate/delete/edit API key, add/edit/remove address, save profile) run **off the EDT** via
> `BackgroundTask.runCatching` (failures surface as a dialog from the thrown `SecurityException`).
> Row actions render as **`IconUtil` SVG icons** (edit/delete/refresh/copy/visible/search/back). Still stubs:
> **passkey** (login/register are empty `void` no-ops), the security-manager admin tables, the
> scanner/file-sharing screens, and the AI assistant's Chat/History/Skills pages (only Providers is wired).

## Layout

```
io.xlogistx.nosneak.app
├── Main.java                      ← entry point + top-level JFrame
└── mock/                          ← prototype UI (screens, menu, mock security)
    ├── AppShell.java              ← root content pane, CardLayout host (mounts ai-assistant's AssistantPanel)
    ├── LoginPanel.java            ← login/register screen (method + mode toggle)
    ├── PQCRegistryPanel.java      ← PQC file-sharing registry view
    ├── SubjectPanel.java          ← subject account view (master–detail)
    ├── SubjectSecManagerPanel.java← security-manager admin view (master–detail)
    ├── ScanPanel.java             ← network scanner view (placeholder)
    ├── MenuBarFactory.java        ← builds the application menu bar
    └── utility/
        ├── AppContext.java        ← per-app service locator (Session + Navigator)
        ├── Session.java           ← auth + identifiers + credentials + profile + addresses (over DomainSecurityManager)
        ├── SessionAICredentialSource.java ← exposes the subject's API keys to ai-assistant (implements AICredentialSource.APIKeys())
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
title "NoSneak") builds the security manager via `createDomainSecManager()` — which stands
up a **MongoDB-backed** `XlogistxMongoDataStore` (config built by `XlogistxMongoDSCreator`
from the `DB_URL` constant, `mongodb://localhost:27017/xlog_datastore_test?replicaSet=rs0`),
initializes `OPSecUtil.singleton()`, and returns a `DomainSecurityManagerDefault` over that
store with `CIPassword` and `SubjectAPIKey` registered as credential types. It then creates
the single `AppContext` from it, builds the menu bar via `MenuBarFactory`, and installs
`AppShell` as the content pane. The menu bar starts hidden and is toggled visible/invisible
by subscribing to `session().onAuthChange(...)` — it only appears once the user is
authenticated.

> The store is **not seeded** — a fresh database has no login, so register an account first.
> Construction also assumes the Mongo instance in `DB_URL` is reachable (and its replica set
> initialized); if it isn't, `createDomainSecManager()` throws on the EDT during frame
> construction and the app fails to start with no user-facing dialog.

## `mock` — UI screens & wiring

### `AppShell`
The root panel (`BorderLayout`). Hosts a `CardLayout` content area registering one card
per `Navigator.Screen` (`LOGIN`, `MAIN`, `SUBJECT`, `SCAN`, `MANAGER`, `ASSISTANT`) plus a footer
status bar. On construction, it builds the `Navigator`, registers it on the `AppContext`,
and wires `session().onAuthChange(...)` so that a successful auth navigates to `SUBJECT`
and a logout navigates back to `LOGIN`. The footer (left: `session: … | subject: …`,
right: status) also subscribes to auth changes. Starts on the `LOGIN` screen.

The `ASSISTANT` card is the `ai-assistant` module's `gui.AssistantPanel`, constructed with a
`new SessionAICredentialSource(ctx.session())` so it can list the subject's API keys. Because
the panel is built once (before login), `AppShell` calls `assistantPanel.refresh()` on login (the
credential source is empty until then) and `assistantPanel.cleanup()` on logout (which re-runs the
refresh, clearing the list). This is the **only** coupling point — the dependency runs
`no-sneak-app → ai-assistant`, never the reverse.

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
**off the EDT** via `BackgroundTask.runCatching(...)` (so bcrypt/round-trips never freeze the
UI, and the action button is disabled while in flight). Failures are signalled by a thrown
`SecurityException` whose message the worker shows as an error dialog. Reporting: failed login →
"Invalid Credentials"; register confirm-mismatch → "Passwords do not match" (an instant
EDT check *before* the worker); register success → "Registered Successfully" (clears fields
and flips to Login mode). Login *success* shows no dialog — the `"authenticated"` event
navigates away. The **API-key** action is now real — it calls `Session.loginAPIKey` (paste a
key → sign in) via `BackgroundTask.runCatching`, so a bad key surfaces its error dialog (the
thrown message). The **passkey** action is still wired to a `Session` stub that returns
`false`, so that tab does nothing (no feedback).

> `registerUsernamePassword` **throws a `SecurityException`** on failure, so a **taken
> username** shows "That username is already taken" (distinct from the password-rules
> message). Register runs off the EDT via `runCatching`.

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

The **Profile** screen is itself a nested `CardStack` (`profileCards`, built by
`buildProfileArea`) with a **profile** card (the form) and an **editAddress** detail card —
mirroring how the Credentials screen switches between its list and detail cards.

- **Profile** (card key `profile`) — First/Last name, Date of birth, an **Identifiers**
  list, and an **Addresses** list, plus **Save Changes**. Wrapped in a `JScrollPane`.
  - **Identifiers** is a `ListSection` bound to `Session.getAllPrincipalIDForLoggedInUser()`.
    **+ Add identifier** prompts for a value → `Session.addIdentifier` (validation currently
    delegated to the backend — see *Needed fixes*), per-row **Remove** (trash icon) →
    `Session.removeIdentifier`. Both surface the thrown `SecurityException`'s message on failure. There is no
    *Principal IDs* card — identifiers live here.
  - **Addresses** is a `ListSection` bound to `Session.getAllAddresses()`. **+ Add address**
    opens the **editAddress** card blank; each row's **Edit** (pencil) opens it pre-filled;
    **Remove** (trash) confirms then `Session.deleteAddress`. The editAddress card
    (`buildEditAddress`, via `PanelBuilder.detail` so it gets a back arrow) has Label / Street /
    City / State-region / Postal fields plus a **Country** combo box (populated from
    `DataConst.COUNTRIES`) and a **Save address** button — Add stores a fresh `NVGenericMap` via
    `Session.addAddress`, Edit mutates the selected map in place and persists via
    `Session.changeAddressDetails`. Save requires at least a **Label or Street** (blocks with a
    "Missing information" dialog otherwise). Each address is its own `NVGenericMap` (keys
    `label`/`street`/`city`/`state`/`postal`/`country`) inside an `NVGenericMapList("addresses")`
    in the subject's property bag.
  - **Save Changes** collects only name/DOB into a map and calls `Session.saveProfile(...)`;
    `populateProfile()` reads them back via `Session.loadProfile`. *(Address lives in the
    nested list above, not the flat profile map. No verification/canonical-ID/status metadata —
    the model has no such fields; see below.)*
- **Credentials** (card key `Credentials`) — a nested `CardStack` (`credentialCards`)
  with three views: a **list**, a **change-password** form, and an **edit-API-key** form
  (`editAPI`). The list card is a header + description over **two** `ListSection`s stacked
  in a `BorderLayout` (Password `NORTH`, API keys `CENTER`), each with its own supplier and
  an empty-state row ("No password set" / "No API keys yet"):
  - **Password section** (no add button) — the **Password** row's **Edit** (pencil) flips to
    the change-password form (current/new/confirm → `Session.changePassword` via
    `BackgroundTask`, off the EDT).
  - **API keys section** — one row per key showing its label (`"API key — " +
    SubjectAPIKey.getName()`); the row's **Edit** opens the `editAPI` card for that key. Its
    **+ Add API Key** button opens the add dialog: a **Generate local / Add third party**
    selector with Label + Description. *Generate* shows a freshly `Session.generateAPIKey()`'d
    key in a read-only, copyable field with a **Refresh** button (regenerates the shown key)
    and a **Copy** button; *Add third party* is a **sectioned form** (`Key` / `Scope` / `Provider
    endpoint`, built with `PanelBuilder.addSection` + `addRow` over placeholder-hint `textField`s):
    a pasted key plus App Id / Domain ID and the **AI-assistant fields** — **Provider** (e.g.
    `anthropic`), **Base URL**, a free-text **API auth type** (e.g. `Bearer`), and an optional
    **Header name** (e.g. `x-api-key`). The displayed generate field is the source of truth — copy
    and **Create key** both read it, so a refreshed key is the one actually stored. On **Create key**
    it stores via `Session.storeAPIKey(label, description, domainID, appID, rawKey, provider,
    baseURI, authScheme, headerName, external)` (off the EDT), passing `external = !generating` so a
    third-party key is flagged external while an internal one falls back to the default
    `xlogistx.io/nosneak` AppID. The AppID filters validate the optional domain/app-id pair (an
    invalid domain/app id now surfaces as a `SecurityException`, not a raw
    `IllegalArgumentException`), and provider/baseURI/authScheme/headerName are written to the key's
    property bag — then the list refreshes. (The *Generate local* path passes the metadata blank and
    `external = false`, since a locally-minted login key is never an AI provider.)
  - The `editAPI` card is **fully wired**: the secret shows in a masked `JPasswordField`
    with a **Show/Hide** reveal toggle (`VisibleIcon` / `InvisibleIcon`, re-masked on every open) and a
    **Copy** button (copies `getAPIKey()`); editable **Label**/**Description**, plus editable
    **Provider** / **Base URI** / **API auth type** / **Header name** fields — all populated
    from the key on open (`providerOf` / `baseUrlOf` / `authTypeOf` / `headerNameOf`) and saved
    together via
    `Session.changeAPIDetails(key, label, description, provider, baseURI, authScheme, headerName)`.
    App ID / Domain ID show read-only. **Rotate** (`Session.rotateAPIKey`, disabled for external
    keys) and **Delete** (`Session.deleteAPIKey`) each confirm first, run off the EDT, and refresh —
    Rotate re-populates the card with the new secret, Delete navigates back to the list.

> **Icon buttons.** The credential/identifier/address actions render as `io.xlogistx.gui.IconUtil`
> icons (jsvg-rendered `SVGIconWidget`s bundled with `xlogistx-gui-audio`) with tooltips rather
> than text: **EditIcon** (pencil), **DeleteIcon** (trash), **RefreshIcon** (rotate / regenerate),
> **CopyIcon** → **SaveIcon** check on success, **VisibleIcon/InvisibleIcon** (reveal), plus
> **SearchIcon** (`SubjectSecManagerPanel`) and **BackIcon** (`PanelBuilder.detail`
> back). Icon-only buttons are built through **`GUIUtil.iconButton(Icon)`** (from
> `io.xlogistx.gui`), which sizes the button tight to the icon. The **back arrow** uses
> **32×32** — larger than the 16×16 action icons. Primary/confirming buttons keep their text; the
> save-style ones (Save Changes, Change password, Save address) additionally carry a **SaveIcon**.
> Create key and Login/Register stay text-only. `SVGIconButtonTest` (test sources) is a runnable
> visual check — its `main` shows every icon the app uses on real buttons plus the disabled state.
> The app-bundled `src/main/resources/icons/*.svg` files are **no longer referenced** (the
> `IconUtil` icons ship inside `xlogistx-gui-audio`) and can be removed.

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
`SUBJECT`, *Subject Security Manager* → `MANAGER`, *AI Chat* → `ASSISTANT`.

#### Navigation model
The app uses **two independent navigation layers**, deliberately kept separate:

- **Top menu bar (`JMenuBar`)** — app-level destinations. The **View** menu drives the
  `Navigator` between top-level screens: *Network scanner* → `SCAN`, *PQC file sharing* →
  `MAIN`, *Subject Profile* → `SUBJECT`, *Subject Security Manager* → `MANAGER`, *AI Chat* →
  `ASSISTANT`. (There is no separate "Subject" menu; the subject screen is reached from
  **View → Subject Profile**.)
- **Left selector inside a panel** — sub-section switching *within* a screen, via a local
  `CardStack` (e.g. `SubjectPanel`'s Profile / Credentials, or
  `SubjectSecManagerPanel`'s Subjects / Permissions / Roles / Role groups / Grants). This
  is local to the panel and does **not** go through the top-level `Navigator`.

In short: the top menu chooses *which screen*; a panel's left selector chooses *which
section of that screen*. They are separate `CardLayout`s (the in-panel ones wrapped by
`CardStack`).

### Security backend — `DomainSecurityManagerDefault` (zoxweb)
`Main.AppFrame.createDomainSecManager()` constructs zoxweb's
`org.zoxweb.server.security.DomainSecurityManagerDefault` over a **MongoDB**
`XlogistxMongoDataStore` (config from `XlogistxMongoDSCreator.toAPIConfigInfo(DB_URL)`),
registers `CIPassword` and `SubjectAPIKey` as credential types, and passes it to
`AppContext` → `Session`. It implements the full security model —
subject/principal/credential CRUD, the permission/role/role-group catalog, and grants —
with the same keying the code relies on: `login(principalID, credential)` resolves the
principal to its subject and validates the `PASSWORD` `CIPassword` via
`SecUtil.isPasswordValid` (throws `SecurityException` on mismatch); identifiers are keyed by
**subjectGUID** and credentials by **principalID**. Two behaviours to know:
- **Persistent, not seeded** — data lives in MongoDB and **survives restarts**, but nothing
  is seeded, so a fresh database has no accounts; register one before you can log in.
- **`createSubjectID` throws on a duplicate** principal (`"principal already exists"`).
  `registerUsernamePassword` catches this and rethrows `SecurityException("That username is
  already taken")`.

> The subject's profile fields (name/DOB) and its address book are stored in the
> `SubjectIdentifier`'s inherited `PropertyDAO` property bag (`getProperties()` →
> `NVGenericMap`) — name/DOB as flat keys, addresses as a nested `NVGenericMapList` — persisted
> via `updateSubjectID`; the schema itself has no such fields. Round-trips are covered by
> `ProfileRoundTripTest` (name/DOB) and `AddressRoundTripTest` (the nested address list).
>
> **Tests** (`src/test/...`, over an in-memory `MockAPIDataStore`; each registers the credential
> types via `addCredentialType`, mirroring `Main`). Success paths assert `assertDoesNotThrow`
> and failures assert the thrown `SecurityException` (message = the reason), matching the
> exception convention: `RegisterRoundTripTest` (register → login, weak-password +
> duplicate-username rejection, no auto-login), `ProfileRoundTripTest` (save/load, overwrite,
> across logout-login, signed-out guard), `APIKeyRoundTripTest` (generate → create → login,
> label/description round-trip, `changeAPIDetails` edit + clear, **delete** removes-and-blocks-
> login, **rotate** old-dies/new-works, domain/app-id store + case-normalization, invalid
> domain/app-id → `SecurityException`, **external-flag** marking + provider/base-url/auth-type/
> header-name metadata round-trip, bad-input guards), `ChangePasswordRoundTripTest` (old rejected /
> new works across logout-login, plus failure modes), `IdentifierRoundTripTest` (add/remove, blank
> rejection, null + non-active removal, subject repoint), `AddressRoundTripTest` (add → list, multiple, edit-in-
> place replace-not-append, remove-by-reference, all-fields + edit-all-fields round-trip,
> persistence across logout/login, signed-out guards), and `AppIDDefaultTest` (the domain + app-id filters directly: case/`www.`/subdomain
> normalization, invalid-domain and non-alphanumeric-app-id rejection, `create(domainAppID)`
> parsing, canonical form, case-insensitive equality).
> Surefire is skipped by the parent POM — run with `-DskipTests=false -Dmaven.test.skip=false`.

## `mock.utility` — application services

### `AppContext`
Lightweight per-application service locator. Constructed in `Main.AppFrame` with the
`DomainSecurityManager`, from which it builds the single `Session`; also holds the
`Navigator` (injected by `AppShell` once the card host exists). Accessors: `session()`,
`nav()`, `setNavigator(...)`. Passed down to screens and the menu factory so they share
one session and one navigator.

### `Session`
Authentication/session state built on `PropertyChangeSupport`, holding the shared
`DomainSecurityManager`, the current `principalID` (the username, *not* the GUID — the field
was formerly named `subject`; accessor `getPrincipalID()`) and its `subjectIdentifier`.

Result convention (migrated from the old reason-string model): the account/auth mutators
return **`void`** and **throw `SecurityException`** on failure — the exception message is the
human-readable reason the panel shows; success returns normally. This covers
`loginUsernamePassword`, `registerUsernamePassword`, `loginAPIKey`, `addIdentifier`,
`removeIdentifier`, `changePassword`, `storeAPIKey`, `changeAPIDetails`, `rotateAPIKey`,
`deleteAPIKey`, `saveProfile`, and the address mutators (`addAddress` / `changeAddressDetails` /
`deleteAddress`). `SecurityException` is **unchecked** (extends `RuntimeException`), so callers
aren't forced to catch it — `BackgroundTask.runCatching` centralizes the error dialog off the
EDT. Failure is thrown, never a broadcast event. Two exceptions to the pattern:
- **No-op / `void` stubs** — `loginPasskey` / `registerPasskey` are empty `void` stubs (not
  implemented — the passkey tab does nothing); `logout` returns `void` and always succeeds.
- **`generateAPIKey()`** returns a `SubjectAPIKey` value (its `getAPIKey()` is the raw
  secret) and **throws** `SecurityException` when signed out (`"Not signed in"`) or on a
  crypto failure (`"Could not generate a key"`).

Auth (username/password is real against the store):
- `loginUsernamePassword` calls `login(principalID, new String(password))`, catching the
  backend `SecurityException` and rethrowing `SecurityException("Invalid Credentials")`; on
  success it stores the `principalID` (since `SubjectIdentifier.getSubjectID()` returns the
  GUID) and the `subjectIdentifier`, flips `authenticated`, fires the event. Use
  `new String(password)`, **not** `Arrays.toString`.
- `registerUsernamePassword` gates on `FilterType.PASSWORD` (throws the rules message on
  failure), persists a bcrypt `CIPassword` via `createSubjectID`, and catches the
  duplicate-principal `SecurityException` → rethrows `"That username is already taken"`;
  returns normally on success. It does **not** auto-login.
- `loginAPIKey` is **real** and matches the plain-storage model: it passes the presented key
  **as-is** (no hashing) to `DomainSecurityManager.loginApiKey(...)`, throwing
  `SecurityException("API Key Invalid")` on a bad key, then resolves the signed-in principal
  from the returned subject's identifiers. `loginPasskey` / `registerPasskey` remain empty
  **`void` no-op stubs**.

API-key lifecycle (failures throw `SecurityException`; the raw key is stored **plain**):
- `generateAPIKey()` — a fresh AES-256 key, URL-Base64 encoded, wrapped in a `SubjectAPIKey`
  (`getAPIKey()` is the raw secret); no persistence. **Throws** `"Not signed in"` when signed
  out and `"Could not generate a key"` on a crypto failure (no longer returns `null`).
- `storeAPIKey(String label, String description, String domainID, String appID, String rawKey,
  String provider, String baseURI, String authScheme, String headerName, Boolean external)` — stores
  the raw key verbatim (`setAPIKey(rawKey)`, no hashing) in a `SubjectAPIKey` (`STATUS` = ACTIVE,
  optional `name`/`description`) via `createCredential`. The `external` flag drives the AppID: when
  **`external`** and **both** `domainID`/`appID` are non-blank it attaches an `AppIDDefault` (run
  through `FilterType.DOMAIN` + `AppIDNameFilter`: normalizes case, strips `www.`/subdomains) and sets
  the `external` property `true`; when **not** external it falls back to the default
  `xlogistx.io/nosneak` AppID. An invalid domain/app id is caught and rethrown as
  `SecurityException("Invalid domain or app ID")` (no longer a raw `IllegalArgumentException`). The
  **AI-assistant metadata** is written to the key's property bag via a `putIfPresent` helper — keyed by
  the `Session.APIKeyInfo` enum (`GetName`): `provider` (`PROVIDER`), `base-url` (`BASE_URL`),
  `auth-type` (`AUTH_SCHEME`), and `header-name` (`HEADER_NAME`), each only when non-blank. Guards
  (thrown): `"Not signed in"` / `"Key cannot be empty"`.
  *(No key-format validation today — a malformed paste is accepted and simply never matches at login.)*
- `changeAPIDetails(key, label, description, provider, baseURI, authScheme, headerName)` — updates the
  key in place via `updateCredential`. Unlike create it **sets** blanks, so passing empty clears them;
  it also **rewrites** the `provider` / `base-url` / `auth-type` / `header-name` properties every save,
  so clearing a field or changing the scheme actually sticks (create only ever *writes* them).
- `isExternalKey(key)` / `providerOf(key)` / `baseUrlOf(key)` / `authTypeOf(key)` / `headerNameOf(key)`
  — read the metadata back off the property bag (the `external` boolean, and the `provider` /
  `base-url` / `auth-type` / `header-name` strings via the `APIKeyInfo` enum).
  `SessionAICredentialSource` exposes the keys to the AI assistant.
- `rotateAPIKey(key)` — generates a fresh secret, replaces the stored one via
  `updateCredential` (old key stops working, new one works). Guards against persisting a
  `null` secret; the new secret is read back from the mutated `key.getAPIKey()`.
- `deleteAPIKey(key)` — deletes the credential via `deleteCredential` (the key can no longer
  log in). Guards (thrown): `"Not signed in"` / `"Empty Key"`. *(Formerly `revokeAPIKey`.)*

Addresses (stored as an `NVGenericMapList("addresses")` inside the subject's property bag —
each address its own `NVGenericMap` with keys `label`/`street`/`city`/`state`/`postal`/`country`;
the profile map holds them as a nested list rather than flat fields. `NVGenericMapList` is used
deliberately: it is the one list container the Mongo property-bag serializer round-trips — an
`NVEntityReferenceList` of `AddressDAO` is silently dropped on write, so addresses aren't stored
as entity references):
- `getAllAddresses()` — the live `List<NVGenericMap>` (empty when signed out); returned maps are
  the stored instances, so mutating one and calling `changeAddressDetails` persists the edit.
- `addAddress(NVGenericMap)` — creates the `addresses` list on first use, appends, and persists
  via `updateSubjectID`.
- `changeAddressDetails(NVGenericMap)` — persists after an address has been mutated in place (the
  edit path). Guarded: the map must actually be in the stored list (identity check), else throws
  `"Address not found"` — so a detached map can't be a silent no-op.
- `deleteAddress(NVGenericMap)` — removes by reference and persists.
  All throw `"Not Logged in"` when signed out.

Account data (all backed by `DomainSecurityManager`, keyed off the signed-in subject):
- `getAllPrincipalIDForLoggedInUser()` — identifiers, via `lookupAllPrincipalIdentifiers(
  subjectIdentifier.getGUID())` (keyed by GUID); returns empty when signed out.
- `getAllCredentialForLoggedInUser()` — credentials, via
  `lookupAllPrincipalCredentials(principalID)`.
- `getAllCredentialForUserByType(CredentialInfo.Type)` — credentials of one type, via
  `lookupCredentialsBySubjectGUID(subjectIdentifier.getSubjectGUID(), type)` (keyed by
  subjectGUID); guards both null args.
- `addIdentifier` — delegates straight to `addPrincipalID`; the Session-side blank/duplicate guards
  are currently **commented out**, so a blank value surfaces the backend's `"Principal ID can't be
  empty"` and duplicates are no longer rejected here (see *Needed fixes*).
- `removeIdentifier` — rejects a `null` principal (`"Identifier cannot be empty"`), then calls
  `deletePrincipalID` (failure → `"Could not remove identifier"`); the dedicated **last-identifier**
  guard has been removed, though the backend still refuses to delete the only one. If you remove the
  identifier you logged in as, it **repoints `principalID`** to a survivor so credential lookups keep
  working.
- `changePassword` — verifies the current password, validates the new one, then updates the
  existing `CIPassword` **in place** via `updateCredential(subjectIdentifier, credential)` (the
  two-arg backend signature; the entity keeps its GUID so it's an in-place update) — atomic,
  never a password-less window. Crucially it also refreshes the credential's **`canonicalID`**
  (the `$2a$…` bcrypt string bcrypt validation actually reads); updating only salt/hash/rounds
  would leave the old password working.
- `saveProfile(Map)` / `loadProfile(String...)` — **name/DOB only** (flat keys) in the
  subject's `PropertyDAO` property bag (`getProperties()`), persisted via `updateSubjectID`.
  Address moved out to the nested `addresses` list (see above).

State changes fire an `"authenticated"` property event; listeners subscribe via
`onAuthChange(...)` — how `AppFrame` toggles the menu bar and `AppShell`/`SubjectPanel`
react on login/logout.

### `SessionAICredentialSource`
The adapter that lets the `ai-assistant` module reach NoSneak's keys without depending on
`no-sneak-app` — it implements the module's `agent.AICredentialSource` over a `Session`. Its
`APIKeys()` walks `getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)` and returns **every**
API key as a `List<APIKey<String>>` (the earlier AI-only filter and the per-credential `AICredential`
adaptation are gone — the module now reads the metadata off each key's property bag itself, e.g.
`getProperties().getValue("provider")`). Returns an empty list when signed out, so
`AssistantPanel.refresh()` (called by `AppShell` on login) shows the provider list only for the
signed-in subject. This is the single point where the app meets the AI-assistant module; the
dependency is one-way (`no-sneak-app → ai-assistant`).

### `Navigator`
Thin top-level screen-switcher over a `CardLayout`. Defines the `Screen` enum
(`LOGIN, REGISTER, MAIN, SCAN, SUBJECT, MANAGER, ASSISTANT`) and `show(Screen)` flips the shared
content panel to the matching card (cards are keyed by `Screen.name()`). Note: `REGISTER`
is currently **unused** — register is a *mode* of the `LOGIN` screen, not its own
screen/card. `ASSISTANT` hosts the `ai-assistant` module's `AssistantPanel` (reached via
**View → AI Chat**).

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
- `detail(title, onBack, content)` — a back-linked detail view (used by the change-password
  and edit-API-key forms). Its body is a **`MigLayout`** single left-aligned column so fields
  keep their preferred size instead of stretching to the panel width (the old `BoxLayout`
  behaviour).
- `title(text)` — a heading `JLabel` styled via FlatLaf `STYLE_CLASS` `h2`; used for section/page
  headings so titles are bigger/consistent.
- **Two-column form helpers** (used by the sectioned Add-API-key form, moved here from `SubjectPanel`):
  `textField(placeholder)` / `textField(placeholder, width)` — a `JTextField` with a FlatLaf
  `JTextField.placeholderText` hint; `sectionHeader(title)` — an uppercased, muted bold header row;
  `addRow(form, label, field)` — adds a `JLabel` + a `growx` field into a `MigLayout("wrap 2",
  "[left][grow,fill]")` grid; `addSection(form, title)` — a full-width `sectionHeader` + `JSeparator`
  spanning both columns.
- Also has `row(...)`, `group(...)`, and `listPage(...)` — the last is **superseded by
  `ListSection`** for data-driven lists and kept only for static ones.

### `ListSection`
A titled, refreshable list component. Constructed with a title, an add-button label + action,
and a `Supplier<List<Entry>>` data source; `refresh()` rebuilds the rows from the supplier
(call it after any mutation). A **null `onAdd`** omits the add button (used by the read-only
Password section). The title renders as a `PanelBuilder.title` **h2** label inside an etched
box (not a `TitledBorder`). Each `Entry(label, onEdit, onRemove)` renders a row with optional
per-row **Edit**/**Remove** buttons (null handler hides that button); an `Entry` with both
handlers null is a plain label row (used for the empty-state lines). Used by `SubjectPanel`
for the Identifiers list and the Password / API keys sections.

### `BackgroundTask`
A `SwingWorker` helper so blocking work never runs on the EDT. `run(owner, toDisable, work,
onDone)` runs `work` (a `Callable<T>`) off the EDT and delivers the result to `onDone` on the
EDT, disabling `toDisable` while in flight. If `work` throws, `run` shows an error dialog on
the EDT instead of calling `onDone` — a `SecurityException`'s message is shown **as-is** (an
expected validation failure), anything else is prefixed `"Unexpected error: "` (a genuine
crash). `runCatching(owner, toDisable, work, onSuccess)` is the convenience for the exception
convention: it runs a throwing `work` (a `ThrowingRunnable`) off the EDT and, **only on
success**, runs `onSuccess` on the EDT; any thrown exception is surfaced by `run`'s handler
and `onSuccess` is skipped. Used by `LoginPanel` (login/register/API-key login) and
`SubjectPanel` (change password, add/remove identifier, create/rotate/delete/edit API key,
add/edit/remove address,
save profile). Post-work UI (refresh, navigation, confirmation dialogs) belongs in the
`onSuccess` callback so it runs after the background work completes, not before.

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
        ├─ ScanPanel            (SCAN)                                  │  (logout → LOGIN)
        └─ AssistantPanel       (ASSISTANT) ← SessionAICredentialSource │  + assistant.refresh()
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
Intended per-type behaviour (today **Password** and the **full API-key lifecycle** are built;
**passkey** is not):
- **Password** — *write-only*: never shown or recovered; the only op is *replace* (current +
  new × confirm). Stored as a verifier.
- **API key** — **fully built**: create (generate or import) → login → edit label/description
  → **Rotate** (new secret, invalidates the old) → **Revoke** (delete). Stored **plain**, so
  the secret is viewable on the `editAPI` card via reveal-on-demand and copyable at any time —
  *not* show-once-only. (See the design note below: plain storage was a deliberate choice for
  the prototype; a hash-at-rest model would make reveal impossible and force show-once +
  rotate-to-recover.)
- **Passkey** — only the *public key* is held; manage = view device + remove.

> **API-key ↔ subject linkage.** In zoxweb-core 2.4.0 the backend `loginApiKey` finds the key
> by its stored value (plain, no hash) and resolves the subject via **`sak.getSubjectGUID()`** —
> the same subjectGUID keying password credentials use. So an API key **survives identifier
> churn**: removing the identifier it was minted under does not orphan it. (An earlier version
> resolved by principalID, which did orphan keys — no longer the case.)
>
> **Storage note.** Keys are persisted **plain** — a deliberate prototype choice so the
> `editAPI` card can reveal/copy the secret on demand. For production you'd hash at rest
> (`storeAPIKey` hashes on store, `loginAPIKey` hashes the presented key the same way), which
> makes reveal impossible and shifts the UX to show-once + rotate-to-recover.

**+ Add login method** would register an additional credential of any type (today only
**API Key** is offered from the API keys section).

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
- ~~**Duplicate username shows the password-rules message.**~~ **Done.**
  `registerUsernamePassword` now throws a `SecurityException` on failure, so a taken username
  shows "That username is already taken" (verified by `RegisterRoundTripTest`).
- **Confirmation warning on Register.** Clicking **Register** must prompt a confirmation
  dialog before proceeding (e.g. "Register using this email / username?"). *(Still
  missing — register proceeds straight to the filter/persist call.)*

### Method availability (`LoginPanel`)
- **API key is add-only, never register.** Registration via API key is already removed
  from the UI; API keys are *attached* to an existing account from the Subject panel's
  *Credentials* section, not created at registration.
- **Passkey hidden everywhere.** The Passkey method is not implemented — it stays hidden in
  **both** login and register modes via `passkeySelector.setVisible(false)` until built
  out.

### Subject panel (`SubjectPanel`)
- **Tier toggle not wired.** The `Mode` menu's "Technical Mode" `JCheckBoxMenuItem` has no
  action listener, and `SubjectPanel` has no toggle. Add the toggle, back both controls
  with a single shared Technical-mode flag, and make Simple/Technical actually
  show/hide the underlying detail (per the *Tier toggle* contract above).
- ~~**Profile is static.**~~ **Done** (persistence). **Save Changes** writes name/DOB to the
  subject's property bag (`Session.saveProfile`) and reloads via `loadProfile`; addresses persist
  separately through the address book (see *Addresses* above). Still target-only: Email-change
  verification and a gated Canonical ID field.
- ~~**Identifiers folded into Profile, not yet built.**~~ **Done** (core). Built as a
  `ListSection` with add + guarded remove. Still target-only (no model fields): per-entry
  status/type, Edit/rename, verification-before-active, and a minimum-one-email rule.
- ~~**Login credentials — password done, rest stubbed.**~~ **Done** (except passkey). Password
  replace (change form → `Session.changePassword`, atomic, off-EDT) and the **full API-key
  lifecycle** are built: **+ Add API Key** generates or imports a key (`generateAPIKey` /
  `storeAPIKey`), it logs in via `loginAPIKey`, and the `editAPI` card supports reveal/copy,
  **edit** label/description (`changeAPIDetails`), **Rotate** (`rotateAPIKey`) and **Delete**
  (`deleteAPIKey`) — each confirmed, off-EDT, with refresh. Still stubbed: passkey
  view-device/remove.
- **Principal ID needs a status.** Each identifier should carry a status (e.g.
  primary / alias / verified / pending) shown in the Identifiers `ListSection` and settable
  from its edit affordance. Blocked on the model: `PrincipalIdentifier` currently holds only
  the id string, so this needs a status field (and its persistence) before the UI can surface
  it — until then all identifiers render statusless.
- **Address optional / `*`-for-mandatory convention.** *Partially done* — the address card now
  blocks saving unless at least a **Label or Street** is filled ("Missing information" dialog).
  Still target-only: a consistent convention across profile + address forms marking mandatory
  fields with a trailing `*` in the label and everything else explicitly "— optional" (decide the
  full mandatory set, e.g. Street + City + Country), replacing the ad-hoc "— optional" suffixes.

### Subject Security Manager (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects /
  Permissions / Roles / Role groups / Grants tables to the `DomainSecurityManager`
  catalog (`getPermissions()`, `getRoles()`, `getRoleGroups()`, the grant getters, etc.)
  and make the per-section search bars filter. The backend exists
  (`DomainSecurityManagerDefault`); the panel just isn't wired to it yet, and the MongoDB
  store has no seeded catalog data.

### Security hardening
From a security pass over the app's own code (issues fixable here, not in the zoxweb
dependency). Ordered by priority.

- **`loginAPIKey` can authenticate with a null principal** (`Session.loginAPIKey`, ~line 100).
  When a key resolves to a subject with **zero** identifiers, `principalID` is set to `null`
  but `authenticated` is still flipped to `true` — the footer then shows `subject: null` and
  `principalID`-guarded methods silently no-op on a session that looks logged in. Fix: if
  `principals.length == 0`, clear `subjectIdentifier` and throw rather than authenticating.
- **Clipboard secret never cleared** (`SubjectPanel`, the generate-card **Copy** and `editAPI`
  **Copy** actions). A copied API-key secret sits on the system clipboard indefinitely
  (readable by any process / clipboard-history tool). Add an auto-clear after a timeout
  (Swing `Timer`, e.g. 60 s), guarded to only clear if the clipboard still holds that value —
  the password-manager pattern.
- **`char[]` secrets are never zeroed** (`LoginPanel`/`SubjectPanel` — `password.getPassword()`
  and the change-password fields). Wipe the arrays (`Arrays.fill(pwd, '\0')`) in a `finally`
  after use. **Partial only:** `Session` immediately does `new String(secret)` for the backend
  API, and that immutable copy can't be wiped — so this shrinks the exposure window but can't
  close it without a `char[]`-accepting backend. Same limitation applies to `JPasswordField`'s
  internal buffer on `setText("")`.
- **Inconsistent signed-in guards in `Session`.** Some methods guard on `principalID`
  (`getAllCredentialForLoggedInUser`, `changeAPIDetails`) while others guard on
  `subjectIdentifier`. Standardize on `subjectIdentifier`.
- **Identifier validation was dropped.** `addIdentifier`'s blank/duplicate guards are commented out
  and `removeIdentifier`'s last-identifier guard was removed, so duplicates can be added and the only
  identifier can be (attempted to be) removed — it fails now only because the backend refuses.
  Restore the guards (or confirm the backend enforces both) — the tests were relaxed to match, not to
  bless the loss.
- **`showEditAPIKey` calls `setText(null)`** (`SubjectPanel`, ~line 393) for keys created
  without a label/description (`getName()`/`getDescription()` return `null`). Null-coalesce to
  `""`. Low impact, defensive.
- **External favicon fetch on the login screen** (`LoginPanel`, ~lines 101-108). Startup pulls
  `https://xlogistx.io/favicon.ico` (HTTPS, exceptions swallowed) — a minor privacy /
  supply-chain "phone home." Bundle a local icon or drop it.

> Explicitly considered and **not** treated as issues here: menu items are unreachable while
> signed out (the whole `JMenuBar` is hidden until auth — `Main` toggles it); profile /
> identifier / AppID fields need no injection hardening (single-user local app, Mongo backend
> so no SQL, values render in `JTextField`s with no HTML, and AppID/domain are already filter-
> validated); the hardcoded `DB_URL` is a credential-less localhost test URL.

> These are UI/UX gaps in the prototype. The username/password session path — plus
> identifiers, change-password, profile save/load, the **address book**, and the **full
> API-key lifecycle** (create/login/edit/rotate/delete, stored plain) — is real against
> `DomainSecurityManagerDefault`. Still outstanding: **passkey** (`Session` stubs are empty
> `void` no-ops), the **Simple/Technical** tier toggle, and the security-manager admin tables
> (unbound), which need wiring alongside the UI work.