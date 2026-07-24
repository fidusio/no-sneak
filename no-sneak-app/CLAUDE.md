# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak security tooling. Contains the application entry point
and the **`ui`** package that wires together the screens, navigation, and the session/security
layer. It began as a UX prototype but now runs a **real** session/security layer; the PQC
scanner and file-sharing screens are still placeholders.

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
> **Still stubbed:** passkey (login/register are empty `void` no-ops), the security-manager admin
> tables, the scanner/file-sharing screens, the AI assistant's Job-queue page and Chat send path.

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
    ├── ScanPanel.java             ← network scanner view (placeholder)
    ├── MenuBarFactory.java        ← builds the application menu bar
    ├── assistant/                 ← app-side bindings for the ai-assistant module
    │   ├── SessionAICredentialSource.java ← exposes the subject's API keys (implements AICredentialSource.APIKeys())
    │   └── AssistantStorage.java  ← AIChatRepository impl, datastore-backed over the H2P APIDataStore
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

`launchApp(DomainSecurityManager)` opens `Main.AppFrame` (a `JFrame`, 800×600, title "NoSneak"),
which creates the single `AppContext` from the manager, builds the menu bar via `MenuBarFactory`,
and installs `AppShell` as the content pane. The menu bar starts hidden and is toggled by
`session().onAuthChange(...)` — it only appears once authenticated.

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
to `LOGIN`. The footer (left: `session: … | subject: …`, right: status) also subscribes to auth
changes. Starts on `LOGIN`.

The `ASSISTANT` card is the `ai-assistant` module's
`io.xlogistx.nosneak.ai.assistant.AssistantPanel`, constructed with an `AssistantContext`:
`new AssistantPanel(new AssistantContext(new SessionAICredentialSource(ctx.session()), new
AssistantStorage(ctx.session().getDomainSecurityManager().getDataStore())))`. The context holds
the credential source, the chat repository (`AssistantStorage`, over the same H2P `APIDataStore`
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
    button; editable **Label** / **Description**, **App ID** / **Domain ID**, and **Provider** /
    **Base URI** — all populated from the key on open. **Label and Description are required**.
    Saved via `Session.changeAPIDetails(key, label, description, domainID, appID, provider,
    baseURI, authScheme, headerName)` — App ID / Domain ID persist when both non-blank
    (re-validated through the AppID filters). **Rotate** (`Session.rotateAPIKey`, disabled for
    external keys) and **Delete** (`Session.deleteAPIKey`) each confirm first, run off the EDT,
    and refresh — Rotate re-populates the card with the new secret, Delete navigates back.

> **Icon buttons.** Credential/identifier/address actions render as `io.xlogistx.gui.IconUtil`
> SVG icons with tooltips: **EditIcon** (pencil), **DeleteIcon** (trash), **RefreshIcon**
> (rotate/regenerate), **CopyIcon** → **SaveIcon** check on success, **VisibleIcon/InvisibleIcon**
> (reveal), **SearchIcon** (`SubjectSecManagerPanel`), and **BackIcon** (`PanelBuilder.detail`).
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
The `SCAN` screen — network scanner view. Placeholder ("NOT IMPLEMENTED"); intended to front the
NMap/PQC scanning backend.

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

State changes fire an `"authenticated"` property event; listeners subscribe via `onAuthChange(...)`
— how `AppFrame` toggles the menu bar and `AppShell`/`SubjectPanel` react on login/logout.

### `SessionAICredentialSource` (in `ui.assistant`)
The adapter that lets the `ai-assistant` module reach NoSneak's keys without depending on
`no-sneak-app` — it implements `io.xlogistx.nosneak.ai.AICredentialSource` over a `Session`. Its
`APIKeys()` walks `getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)` and returns every
API key as a `List<APIKey<String>>` (the module reads the AI metadata off each key's property bag
itself, e.g. `getProperties().getValue("provider")`). Returns an empty list when signed out. This
is the single point where the app meets the AI-assistant module; the dependency is one-way.

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
- `buildDefaultSplitPanel(content, JToggleButton...)` — the master–detail shell: a left sidebar of
  grouped toggle buttons (a `ButtonGroup`) and the supplied `content` on the right.
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
A titled, refreshable list component. Constructed with a title, an add-button label + action, and
a `Supplier<List<Entry>>` data source; `refresh()` rebuilds the rows (call after any mutation). A
**null `onAdd`** omits the add button (the read-only Password section). Each `Entry(label, onEdit,
onRemove)` renders a row with optional per-row Edit/Remove buttons (null handler hides that
button); an `Entry` with both handlers null is a plain label row (empty-state lines).

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
        ├─ ScanPanel            (SCAN)                                  │  (logout → LOGIN)
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

### Subject Security Manager (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects / Permissions /
  Roles / Role groups / Grants tables to the `DomainSecurityManager` catalog (`getPermissions()`,
  `getRoles()`, `getRoleGroups()`, the grant getters) and make the per-section search bars filter.
  The backend exists; the H2 store has no seeded catalog data.

### Security hardening
From a security pass over the app's own code (issues fixable here, not in the zoxweb dependency),
ordered by priority.

- **`loginAPIKey` can authenticate with a null principal** (`Session.loginAPIKey`). When a key
  resolves to a subject with **zero** identifiers, `principalID` is set to `null` but
  `authenticated` is still flipped `true` — the footer shows `subject: null` and
  `principalID`-guarded methods silently no-op. Fix: if `principals.length == 0`, clear
  `subjectIdentifier` and throw rather than authenticating.
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

> Considered and **not** treated as issues: menu items are unreachable while signed out (the whole
> `JMenuBar` is hidden until auth); values render in `JTextField`s with no HTML, and AppID/domain
> are filter-validated. **Re-check for the H2 store:** the store is now **SQL** (H2), so injection
> safety rests on `H2PDataStore` issuing parameterized JDBC rather than string-built SQL — confirm
> that before relying on it. Store location/credentials come from the `ds.*` params or the setup
> screen, not a hardcoded URL.
