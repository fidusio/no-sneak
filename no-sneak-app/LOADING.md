# What loads when — eager vs lazy across the desktop app

A map of when the running application does work: what is built or fetched up front, what waits
until it is needed, and what is re-queried on every call. Written as a handoff; the point is that
the next person can answer "why is login slow" or "why is this list stale" without re-reading
three modules.

Scope is the desktop app as a whole — `no-sneak-app` plus the `ai-assistant` and `ai-model`
modules it mounts — because the interesting loading decisions cross those boundaries. Nothing in
`no-sneak-core` or `no-sneak-net` is reached from the UI yet, so the scanner engine does not
appear here.

> **Line references are as of commit `ad7e4f4`** and will drift. The class and method names are
> the durable part; grep for those if a number is stale.

---

## 1. Eager — built or fetched before anything asks for it

### Startup, before a window exists

| What | Where | Note |
|---|---|---|
| H2 datastore opened + `connect()` | `Main.java:42-44` | From `ds.*` params, else after the setup screen. **Held open across logout**; closed only in `windowClosing` (`Main.java:76-81`). |
| `OPSecUtil.singleton()` + credential types | `Main.java:94-99` | On every security-manager build. |
| FlatLaf, Roboto, theme defaults | `Main.java:48-51` | Before the EDT hop. |
| Menu bar | `Main.java:83-85` | Fully built at frame construction, then `setVisible(false)` until auth. |
| Login-screen favicon | `LoginPanel.java:94` | An outbound `https://xlogistx.io/favicon.ico` fetch during construction. Eager **and** off-machine — see the security-hardening list in `CLAUDE.md`. |

### Screens

**Every top-level screen is constructed before login.** `AppShell`'s constructor instantiates
`LoginPanel`, `PQCRegistryPanel`, `SubjectPanel`, `ScanPanel`, `SubjectSecManagerPanel` and
`AssistantPanel` and registers them all as `CardLayout` cards (`AppShell.java:26-33`).

`Navigator` controls **visibility only, never construction** (`Navigator.java:33-35`). The same
holds one level down: the assistant's six pages — Chat, History, Providers, Skills, Job Queue,
Capture — are all instantiated in `AssistantPanel`'s constructor
(`AssistantPanel.java:36-41`), including the `JobQueuePanel` stub and `CapturePanel`'s entire
two-tab UI. First paint therefore pays for six screens and six assistant pages regardless of
where you navigate.

`AssistantStorage` binds the datastore handle in its constructor (`AssistantStorage.java:20`), so
the assistant holds a live store reference from app start.

### Network work at login

This is the big one. `AssistantPanel`'s constructor ends with `reloadProviders()`
(`AssistantPanel.java:111`) — i.e. it runs once before anyone is signed in — and `AppShell` calls
it again on every login (`AppShell.java:42`).

`reloadProviders` (`ProvidersPanel.java:279-309`), off the EDT:

1. reads every `AIProviderConfig`,
2. resolves each `keyGUID` against the credential source,
3. builds an `AIAPIProvider` — whose constructor already builds the `AIAPI` caller
   (`AIAPIProvider.java:39-41`),
4. and calls `getModelCatalog().refresh()` on each: **one HTTP round trip per configured
   provider, at login**, with every exception swallowed.

`adoptEnabledKeys()` (`ProvidersPanel.java:317-328`) additionally runs — and *writes* a config row
per enabled key — whenever the subject has zero configs. It is a one-time migration, but the
zero-configs check is the only thing gating it.

### Data reads

- **The whole chat graph, per History row.** `getAllChats()` returns full `AIChat`s with their
  `AIMessage` → `AIRequest`/`AIResponse` children, and the row sublabel calls
  `chat.getMessages().size()` (`ChatHistoryPanel.java:144`). Every transcript in the account is
  materialized to render a list of titles.
- **All capture thumbnails, on entry to the Capture page.** One JPEG decode plus scale per row,
  off the EDT (`CapturePanel.java:167-190`).
- **The full transcript, on every `currentChat` change.** `refreshPrompt()` clears and rebuilds
  every bubble, each an `MDViewerPanel` (`ChatPanel.java:304`).

---

## 2. Lazy — deferred until actually needed

- **Capture full-size PNG.** The deliberate one, and the pattern to copy.
  `AssistantStorage.getAllCaptures()` is a **projected read** that names its columns and omits
  `image` (`AssistantStorage.java:135-140`), so rows carry a thumbnail and nothing heavier. The
  bytes are fetched on demand through `CapturePanel.full()` → `ctx.getCapture(guid)` only when
  previewing, sending, or renaming (`CapturePanel.java:383,400,421,444`).
  > **The invariant this creates is load-bearing.** `saveCapture`'s update branch is `ds.update`,
  > which writes every column — so saving a row that came from `getAllCaptures()` writes a null
  > image over the stored PNG. Anything that mutates a capture must re-read it first, and must
  > handle that read missing. `full()` currently falls back to the projected row when
  > `getCapture` misses, which is exactly the hole its own javadoc forbids; see the rough-edges
  > list in `ai-assistant/CLAUDE.md`.
- **Model catalogs.** `AIModelCatalog.models()` returns the last discovered list and never touches
  the wire; only `refresh()` does (`AIAPIProvider.java:164-191`). Every combo population goes
  through `models()` (`PanelSupport.java:56-70`), so opening a picker costs nothing.
- **List rebuilds.** A `ListSection` only re-reads its supplier on `refresh()`. History, Skills,
  Providers and Capture therefore refresh **on the way in** from the sidebar
  (`AssistantPanel.java:84-102`) — without that, a page switched back to would show whatever it
  held at the last mutation. Chat and Job Queue do not refresh on entry.
- **`Navigator` injection.** Set after `AppShell` builds the card host
  (`AppContext.java:38`) — the one deliberately-late field on `AppContext`.
- **Canonical caches.** `chatCache` / `skillCache` / `configCache` fill on first read per GUID and
  dedupe thereafter, so list refreshes hand back the same instance
  (`AssistantContext.java:112-117`).
- **The capture `Robot`.** Created on first sweep and cached, inside `io.xlogistx.gui`'s
  `CaptureAreaSet`.
- **Markdown preview.** A 250 ms non-repeating timer restarted per keystroke, so typing does not
  reparse per character (`MDFileViewer.java:122`).
- **Capture areas and their pixels.** Defining an area is a drag and nothing more; nothing is shot
  until Send, and the PNG encode happens at send time inside a `BackgroundTask` — not at attach
  time.

---

## 3. Neither — re-queried on every call

No caching, so cost scales with how often the UI asks.

- **`Session` account reads.** `getAllPrincipalIDForLoggedInUser()`,
  `getAllCredentialForLoggedInUser()` and `getAllCredentialForUserByType()` hit the store on every
  invocation (`Session.java:354-375`).
- **`SessionAICredentialSource.enabledAPIKeys()`** calls `APIKeys()` and then `isAssistantEnabled`
  per key (`SessionAICredentialSource.java:32-38`).
- **`AssistantContext.configsUsing(keyGUID)`** is a full `getAllProviderConfigs()` store scan per
  call (`AssistantContext.java:158-165`). This is why `ProvidersPanel.providersUsing` — which
  walks the in-memory registrar instead — exists separately. **A sublabel lambda runs per row, on
  the EDT, on every refresh and every keystroke in the search box**, so the registrar walk is the
  one that may appear in a renderer. Do not collapse the two.

---

## 4. What is worth changing, if you are picking this up

Three of the above are cost rather than design. In rough order of payoff:

1. **`getAllChats()` should be a projected read.** The History list needs title, provider, model,
   message count and two timestamps; it currently pulls every message body in the account to get
   the count. `getAllCaptures()` already demonstrates the fix in the same class — the same
   treatment for chats needs either a persisted count field or a projection plus a count query,
   and `ChatHistoryPanel.java:144` is the only caller that forces the full graph.
2. **Login should not fan out N synchronous HTTP calls.** Discovery per provider at login makes
   sign-in latency scale with provider count, and every failure is discarded silently — the only
   symptom a subject sees is a row reading `0 models · never synced`. Discovering on first use of
   a provider (the catalog already caches, so it would happen once) makes login independent of
   provider count and gives an obvious place to report the failure.
3. **Screens could be built on first navigation.** Everything is constructed before login today.
   The `CardLayout` shape does not require that — cards can be added on first `show`. This is the
   least urgent of the three; it costs startup time but nothing recurring.

Two smaller ones: the login favicon fetch (`LoginPanel.java:94`) should be a bundled icon, and
`reloadProviders()` firing from `AssistantPanel`'s constructor does a signed-out pass whose
results are always empty — `AppShell`'s `onAuthChange` call is the one that matters.

---

## 5. Rules to keep

- **Projected reads are for the heavy column, and they create a save-path obligation.** If you add
  another one, the rule is: list reads may be projected; any code path that *writes* the row must
  re-fetch the full one first and bail — not fall back — if the re-fetch misses.
- **A `ListSection` supplier and a sublabel lambda both run on the EDT, per row, per keystroke.**
  Keep them to fields already in memory. Store queries belong behind an explicit refresh.
- **Anything blocking goes through `BackgroundTask`.** All `Session` mutators, provider discovery,
  capture decode and PNG encode already do. `RegionOverlay.select()` additionally *asserts* it is
  not on the EDT.
- **Construction order is: services → screens → navigator.** `AppContext` builds the `Session`,
  `AppShell` builds the screens, then registers the `Navigator` back onto the context. A screen
  that needs `ctx.nav()` during its own constructor will get null.