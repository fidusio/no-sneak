# What loads when — eager vs lazy across the desktop app

A map of when the running application does work: what is built or fetched up front, what waits
until it is needed, and what is re-queried on every call. Written as a handoff; the point is that
the next person can answer "why is login slow" or "why is this list stale" without re-reading
three modules.

Scope is the desktop app as a whole — `no-sneak-app` plus the `ai-assistant` and `ai-model`
modules it mounts, and now `no-sneak-core` too: `ScanPanel` drives the core engine, so probe
definitions, the shared `NIOSocket` and scan reports are part of the loading picture.
`no-sneak-net` is still reached only *through* the engine, never from the UI.

> **Line references are as of the working tree on 2026-10-26** (after the `Navigator.Screen`
> rename: `SCAN` (named `NEW_SCAN` for a day), display names on the enum; `CHAT_HISTORY` was removed later that day when
> Chat History merged into the Chat page) and will drift. The class and
> method names are the durable part; grep for those if a number is stale. Every claim below was
> re-read from the source files that day.

---

## 1. Eager — built or fetched before anything asks for it

### Startup, before a window exists

| What | Where | Note |
|---|---|---|
| H2 datastore opened + `connect()` | `NoSneakMain.main` / `UnlockPanel` step 1 | From `ds.*` params before the window exists, else when the unlock screen's first step opens or creates the store (`NoSneakStore.openOrCreate`, off the EDT). **Held open across logout**; closed only in `windowClosing`. |
| `OPSecUtil.singleton()` | `NoSneakStore.java:179,284,329`, `NoSneakMain.java:211` | Once per create / open / secure of the store (and in the legacy `createDomainSecManager`). |
| FlatLaf, Roboto, theme defaults | `NoSneakMain.java:81-84` | Before the EDT hop. |
| Menu bar | `AppShell.menuBar()` from `NoSneakMain.AppFrame.storeOpened` | Built when the store opens, installed on the frame only while a subject is signed in (2026-10-24). |
| `AppPrefs` (java.util.prefs of the OS user) | `AppShell:178`, `DataStoreSetupPanel`, `SubjectPanel` | Read for the last store location (pre-filled on the setup screen, shown in the header) and the last backup / restore directory; written only after a successful open or a chooser use (2026-10-22). No secrets, microseconds. |
| ~~Login-screen favicon~~ | — | Gone with `LoginPanel` (2026-10-24): the unlock screen's brand mark is the bundled shield SVG, nothing is fetched. |

### Screens

**Every top-level screen is constructed when the store opens, before anyone signs in.**
`AppFrame.storeOpened` (2026-10-24) builds the `AppContext`, the menu bar and the `AppShell`, whose
constructor instantiates `AssistantPanel`, `SubjectPanel` (Profile, Credentials and the Settings
page with Sync, Backup and Restore), `ScanPanel` (New scan, History, the Probe library, the probe
editor and the probe-definition card) and `SubjectSecManagerPanel`, and registers them all as
`CardLayout` cards behind the `SideNavPanel`. Until then the window holds only the `UnlockPanel`.
With `ds.*` launch parameters this happens before the window is shown, as before.

`Navigator` controls **visibility only, never construction** (`Navigator.java:83-99`: `show`
flips the `CardLayout` and runs the section runnable, `sync` only records). The same holds one
level down: the assistant's five pages — Chat (the list of chats and the conversation, one panel
since 2026-10-26), Providers, Skills, Job Queue, Capture — are
all instantiated in `AssistantPanel`'s constructor (`AssistantPanel.java:68-72`), including the
`JobQueuePanel` stub and `CapturePanel`'s two-column page. First paint therefore pays for the
four panels and the six assistant pages regardless of where you navigate.

`AssistantStorage` binds the datastore handle in its constructor (`AssistantStorage.java:34`,
the subject view off `Session.getDataStore()`), so the assistant holds a live store reference
from the moment the store opens.

### Network work at login

This is the big one. `AssistantPanel`'s constructor ends with `reloadProviders()`
(`AssistantPanel.java:87`) — i.e. it runs once before anyone is signed in — and `AppShell` calls
it again on every login (`AppShell.java:115`).

`reloadProviders` (`ProvidersPanel.java:498-549`), off the EDT:

1. reads every `AIProviderConfig`,
2. resolves each `keyGUID` against the credential source,
3. builds an `AIAPIProvider` — whose constructor already builds the `AIAPI` caller
   (`AIAPIProvider.java:53-60`),
4. and calls `getModelCatalog().refresh()` on each: **one HTTP round trip per configured
   provider, at login**. A failure is no longer swallowed: each pass collects its issues (a
   missing credential, an unrecognized provider type, a refresh that threw) and reports them once
   on the EDT, but the provider still registers, with an empty catalog.

`adoptEnabledKeys()` (`ProvidersPanel.java:556-567`) additionally runs — and *writes* a config row
per enabled key — whenever the subject has zero configs (`:507`). It is a one-time migration, but
the zero-configs check is the only thing gating it.

### MAC vendors at login (2026-10-25)

The signed-in shell is **not shown until the MAC vendor table is loaded.** `AppFrame.storeOpened`'s
auth listener runs `loadMacVendorsThenShow()`: the unlock screen shows *Loading MAC vendors…* and
`Session.loadMacVendors()` runs on a `BackgroundTask`, once per process (`macVendorsLoaded`):

1. in system context, look for the store's app-wide `DataContent` named `Mac-Vendor-Content`;
2. **first run on a store only:** download the Wireshark `manuf` file (~3.2 MB) from
   wireshark.org, validate it parses, store it — one network round trip, the only one the app
   itself ever makes;
3. every run: read that row (~3 MB) and load its ~58,000 entries into `NSNetUtil.MAC_VENDORS`
   (`OUIDB.load(byte[])`), the table every scan report's `macVendor` comes from.

A failure (no network on a fresh store) warns once and the shell opens without vendor names; the
next sign-in tries again. *Account → Settings → Sync MAC vendors* repeats the download on demand
(`Session.syncMacVendors`, replaces the row and the live table). This is the one login-time cost
that is a few hundred milliseconds even when nothing is downloaded — the row read and the parse.

### Data reads

- **The whole chat graph, per History row.** `getAllChats()` returns full `AIChat`s with their
  `AIMessage` → `AIRequest`/`AIResponse` children, and the table's Messages column is
  `chat.getMessages().size()` (`ChatHistoryModel.getValueAt`, the Chat page's list since
  2026-10-26). Every transcript in the account is materialized to render a list of titles.
- **All capture thumbnails, on entry to the Capture page.** One image decode plus scale per row,
  off the EDT (`CapturePanel.refreshCaptures`, `:295-321`).
- **The full transcript, on every `currentChat` change.** `refreshPrompt()` clears and rebuilds
  every bubble, each an `MDViewerPanel` (`ChatPanel.java:470`), then re-frames the conversation
  page (`showConversation`, `:197` — a new `PagePanel` around the once-built transcript and
  composer, cheap). The event fires on open / create, reset and delete of the open chat only;
  `saveChat` does not fire it.
- **Scan results and probes, on login.** `ScanPanel`'s `onAuthChange` runs `reloadScanResults()`
  and `reloadProbes()`, both through `BackgroundTask`. The scan-result read is **projected** (see
  §2); the probe read is not, deliberately — probe bodies are small and the editor and the Probe
  library need them. The same background pass loads the **18 bundled probe definitions** once and
  caches them, reads their **JSON text** once as well (`ProbeDefinitionLoader.bundledSource`, for
  the library's read-only view and *Copy to my probes*), and builds the library's rows — every
  stored probe parsed once per reload, off the EDT (`ProbeLibraryModel.rows`, 2026-10-26) — so the
  EDT only installs the finished list.

---

## 2. Lazy — deferred until actually needed

- **The scanner's `NIOSocket`.** `Session.getNio()` opens it on first use and caches it, so a
  subject who never opens the scan screen never pays for a selector or its reader threads. It
  throws an `IllegalStateException` if it cannot open, rather than leaving a null field behind for
  a later NPE, and `closeNio()` runs from `AppFrame`'s `windowClosing` beside the datastore close.
- **Scan report bodies.** `Session.getAllScanResults()` is a **projected read** that omits
  `content` — a `/24` report is ~53 KB of JSON and the list renders only a name, the command and a
  timestamp. Same obligation as captures below: view and send-to-chat re-read through
  `getScanResult(guid)` and bail if it misses, and `saveScanResult` **throws** rather than writing
  a null `content` if handed a projected row.
- **Capture full-size PNG.** The deliberate one, and the pattern to copy.
  `AssistantStorage.getAllCaptures()` is a **projected read** that names its columns and omits
  `image` (`AssistantStorage.java:160-166`), so rows carry a thumbnail and nothing heavier. The
  bytes are fetched on demand: `CapturePanel.full()` → `ctx.getCapture(guid)` when previewing or
  renaming (`CapturePanel.java:379,446`), and the chat re-reads a capture by GUID itself when it
  is attached or sent (`ChatPanel.java:525,700,796`).
  > **The invariant this creates is load-bearing.** `saveCapture`'s update branch is `ds.update`,
  > which writes every column — so saving a row that came from `getAllCaptures()` writes a null
  > image over the stored PNG. Anything that mutates a capture must re-read it first, and must
  > handle that read missing. `full()` (`CapturePanel.java:479-482`) still falls back to the
  > projected row when `getCapture` misses, which is exactly the hole the storage javadoc
  > forbids; see the rough-edges list in `ai-assistant/CLAUDE.md`.
- **Model catalogs.** `AIModelCatalog.models()` returns the last discovered list and never touches
  the wire; only `refresh()` does (`AIAPIProvider.java:203-215`). Every combo population goes
  through `models()` (`PanelSupport.fillModels`, `:80-92`), so opening a picker costs nothing.
- **List rebuilds.** A `ListSection` only re-reads its supplier on `refresh()`, and the chat
  list, Skills, Capture and Providers tables only on `refreshHistory()` / `refreshSkills()` /
  `refreshCaptures()` / `refreshList()`. Skills,
  Providers and Capture therefore refresh **on the way in** from the sidebar
  (`AssistantPanel.showPage`, `:107-122`) — without that, a page switched back to would show
  whatever it held at the last mutation. Chat lands on the open conversation (no read), or
  refreshes the chat list when no chat is open (`ChatPanel.showCurrent`); *All chats* in the
  conversation's head refreshes it too. Job Queue does not refresh on entry.
- **`Navigator` injection.** Set after `AppShell` builds the card host
  (`AppContext.java:38`) — the one deliberately-late field on `AppContext`.
- **Canonical caches.** `chatCache` / `skillCache` / `configCache` fill on first read per GUID and
  dedupe thereafter, so list refreshes hand back the same instance
  (`AssistantContext.java:42-44`, `canonical` at `:124`; cleared on logout, `:238-240`).
- **The capture `Robot`.** One per capture area, created on the area's first shot and cached
  until its graphics device changes (`io.xlogistx.gui.CaptureArea.robot()`, in gui-audio).
- **Markdown preview.** A 250 ms non-repeating timer restarted per keystroke, so typing does not
  reparse per character (`io.xlogistx.gui.MDEditorPanel:135`, in gui-audio since 2026-10-22).
- **The probe definition document.** `PROBE-DEFINITION.md` (~42 KB of markdown on the classpath,
  served by core's pom) is read and rendered through `MDViewerPanel` on the first *Probe
  definition* show (`ScanPanel.showProbeDefinition`, 2026-10-26), never at start-up; the
  *Write with the assistant* action reads the text again when it attaches it to a chat.
- **Detail panes.** The host detail in a scan result and the probe detail in the library are
  filled on row selection from data already in memory; nothing is fetched on selection.
- **Capture areas and their pixels.** Defining an area is a drag and nothing more; nothing is shot
  until Send, and the PNG encode happens at send time inside a `BackgroundTask` — not at attach
  time.

---

## 3. Neither — re-queried on every call

No caching, so cost scales with how often the UI asks.

- **`Session` account reads.** `getAllPrincipalIDForLoggedInUser()`,
  `getAllCredentialForLoggedInUser()` and `getAllCredentialForUserByType()` hit the store on every
  invocation (`Session.java:693-712`).
- **`SessionAICredentialSource.enabledAPIKeys()`** calls `APIKeys()` and then `isAssistantEnabled`
  per key (`SessionAICredentialSource.java:33-48`).
- **The Settings page's Sync status.** Every `show(SECTION_SETTINGS)` runs
  `Session.macVendorStatus()` on a `BackgroundTask` — a projected read of the vendor row (name,
  source, timestamps, properties; never the 3 MB body) — so the *58,575 vendors loaded · stored …*
  line is current each time the page opens (2026-10-25).
- **`AssistantContext.configsUsing(keyGUID)`** is a full `getAllProviderConfigs()` store scan per
  call (`AssistantContext.java:170-176`). This is why `ProvidersPanel.providersUsing` — which
  walks the in-memory registrar instead — exists separately: since 2026-10-26 it runs once per
  key when the picker page opens (`refreshKeys` builds the `ProviderKeysTableModel` rows), on
  the EDT, and the providers table likewise reads each catalog once per `refreshList()`
  (`ProvidersTableModel.rowOf`), never from a renderer. Do not collapse the two.

---

## 4. What is worth changing, if you are picking this up

Three of the above are cost rather than design. In rough order of payoff:

1. **`getAllChats()` should be a projected read.** The History list needs title, provider, model,
   message count and two timestamps; it currently pulls every message body in the account to get
   the count. `getAllCaptures()` already demonstrates the fix in the same class — the same
   treatment for chats needs either a persisted count field or a projection plus a count query,
   and the Messages column of `ChatHistoryModel` is the only caller that forces the full graph.
2. **Login should not fan out N synchronous HTTP calls.** Discovery per provider at login makes
   sign-in latency scale with provider count. Failures are no longer *silent* — `reloadProviders`
   collects them and reports once on the EDT — but they are still paid for at sign-in, and a
   provider whose discovery failed still registers with an empty catalog. Discovering on first use
   of a provider (the catalog already caches, so it would happen once) makes login independent of
   provider count and gives the failure an obvious place to land.
3. **Screens could be built on first navigation.** Everything is constructed before login today.
   The `CardLayout` shape does not require that — cards can be added on first `show`. This is the
   least urgent of the three; it costs startup time but nothing recurring.

Two smaller ones: `reloadProviders()` firing from `AssistantPanel`'s constructor does a signed-out
pass whose results are always empty — `AppShell`'s `onAuthChange` call is the one that matters;
and the MAC vendor load gates the signed-in shell on every sign-in (§1), which is right for the
first run (a scan without vendors would be the surprise) but could become a background load with
the shell shown at once on later runs, since the table is only consulted when a report renders.
(The login favicon fetch this list used to name is gone with the redesign.)

---

## 5. Rules to keep

- **Projected reads are for the heavy column, and they create a save-path obligation.** If you add
  another one, the rule is: list reads may be projected; any code path that *writes* the row must
  re-fetch the full one first and bail — not fall back — if the re-fetch misses.
- **A `ListSection` supplier and a sublabel lambda both run on the EDT, per row, per keystroke.**
  Keep them to fields already in memory. Store queries belong behind an explicit refresh.
- **Anything blocking goes through `BackgroundTask`.** All `Session` mutators, provider discovery,
  capture decode and PNG encode already do. `RegionOverlay.select()` additionally throws an
  `IllegalStateException` if called on the EDT (`RegionOverlay.java:39-41`).
- **Construction order is: services → screens → navigator.** `AppContext` builds the `Session`,
  `AppShell` builds the screens, then registers the `Navigator` back onto the context. A screen
  that needs `ctx.nav()` during its own constructor will get null.