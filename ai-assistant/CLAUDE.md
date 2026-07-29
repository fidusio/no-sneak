# NoSneak AI Assistant — UI Orientation

A top-level Swing window (`View > AI Assistant`) that lets the subject send their own network
data to third-party AI models and compare answers across them.

The assistant owns **no** API keys and adds **no** AI connections of its own. It reads keys from an
external `AICredentialSource` (the NoSneak credential store) and keeps a list of the ones the subject
has chosen to use.

> **Implementation status.** This document is the UI design spec; the sidebar labels have drifted
> from it (`AssistantPanel` currently uses **Chat / Capture / Job Queue / History / Skills /
> Providers** toggle buttons rather than the nav table in §1). What is wired today:
>
> - **Providers are real.** `AIAPIProvider` (this module) is a concrete `AIProvider` wrapping
>   `io.xlogistx.api.ai.AIAPI` (built by `AIAPIBuilder`), resolving the provider type from the
>   credential's `provider` property (`openai` / `gemini`+`google` / `anthropic`+`claude` /
>   `grok`+`xai`). `AssistantPanel.reloadProviders()` runs on login (from `no-sneak-app`'s
>   `onAuthChange`), off the EDT, adding a provider **per key** and then discovering each one's
>   models via `AIModelCatalog.refresh()` — i.e. providers are still **auto-added** from all of
>   the subject's keys. The Providers page lists the registered providers with a per-row
>   **Refresh** (`onRefreshProvider`, wired).
> - **Model discovery drives the pickers.** A provider→model helper pair (`fillProviders` /
>   `fillModels` / `bindProviderModels`) populates provider combos from the registrar and model
>   combos from the selected provider's cached catalog (`models()`, never hardcoded). Used by the
>   Chat header and the History create/edit forms.
> - **History has create / edit / delete + persistence.** `buildHistoryCards` is a nested
>   `CardStack` (`list` / `editor` / `creator`). `+ New Prompt` opens a Create form
>   (name + provider + model), a row's edit opens a pre-filled Edit form (both persist via
>   `context.saveChat`), and remove calls `context.deleteChat`. The list source is
>   `context.getAllChats()` (→ `AIRepository.getAllChats()`), refreshed by the public EDT-safe
>   `refreshHistory()`, which `no-sneak-app` calls on both login and logout.
> - **Skills have create / edit / delete + persistence.** `buildSkillCards` is a nested
>   `CardStack` (`list` / `editor` / `creator`). The list source is `context.getAllSkills()`
>   (→ `AIRepository.getAllSkills()`), refreshed by `refreshSkills()`. `+ New Skill` opens a
>   Create form (name / description / instructions), a row's edit opens a pre-filled Edit form
>   (`editSkill*` fields), remove calls `context.deleteSkill`; all saves run off the EDT via
>   `BackgroundTask.runCatching`. `AISkill.content` is the instruction text — a plain `String`,
>   so a skill authored in markdown is stored verbatim.
> - **Chat send is wired for a single provider, and persists.** `onSend` builds an `AIRequest`
>   (content, model from the header combo, maxTokens), attaches an `AIMessage` to `currentChat`,
>   calls `AIProvider.send(...)` on a `BackgroundTask`, and on success sets the response on the
>   message and calls `context.saveChat(...)` (so the transcript survives a chat switch). The
>   `currentChat` `PropertyChangeEvent` drives `refreshPrompt()`, which resets the title, model
>   combo, and transcript.
> - **Session reset is wired.** On logout `no-sneak-app` calls `clearProviders()` (wipes the
>   registrar) + `resetPanel()` → `context.resetContext()` (nulls `currentChat` / credential /
>   model, clears the chat + skill caches, fires `currentChat` so the transcript clears) and
>   blanks the composer / resets the card stacks. On app close, `Main` closes the datastore in a
>   `windowClosing` handler.
>
> **Still target-only / stubbed:** the multi-model **compare** path (`asyncSend` is an empty
> stub, no `AIRunner`); the **skill→request pipeline** (skills are stored, but nothing yet
> selects which apply to a chat or assembles them into `AIRequest.skillsPrompt`); manually
> **picking** which keys the assistant uses (see the rough edges — providers are still all
> auto-added); the **Job queue** and **Screen capture** pages (all handlers empty).
> `AICredentialSource` and `AIRepository` come from `no-sneak-app` (`SessionAICredentialSource`,
> `AssistantStorage` over the H2P `APIDataStore`); the DAOs and interfaces live in **`ai-model`**
> — see its CLAUDE.md. `no-sneak-app` builds
> `AssistantContext(SessionAICredentialSource, AssistantStorage(session))` and passes it to
> `AssistantPanel` on its `ASSISTANT` screen. The dependency is one-way
> (`no-sneak-app → ai-assistant → ai-model`).
>
> **Known rough edges** (see the code, not yet fixed): providers are **auto-added** from every
> key on login — the "pick a subset" flow (§6) is only **scaffolded** (`providerCards`,
> `providerAddList`, `buildProviderCardsPanel`, `buildAddProvider`) and **not wired** into the
> live Providers page, and `onAddProvider` / `onRemoveProvider` are empty (so the ✕ unlink is a
> no-op); `refreshSkills()` is missing a `return` after its off-EDT `invokeLater`, so it also
> touches the list once off the EDT; `onSend` silently returns when there is no current chat or
> selected model (no feedback); a failed send leaves the unanswered `AIMessage` in the in-memory
> chat (persist happens only on success).

---

## 1. Window shape

`JFrame` with its own `JMenuBar` (File / View / Tools / Help).

Left sidebar, **208 px, navigation only** — no actions, no lists. It selects which page renders in
the detail pane via `CardLayout`, matching the Subject panel master/detail pattern. Section label
`ASSISTANT` (uppercase, muted) above the items.

| Nav item | Page |
|---|---|
| Prompt | The conversation |
| Job queue | Items feedable to a prompt |
| History | Past prompts (rename / delete live here) |
| Skills | Reusable instruction sets (list + editor) |
| Providers | Keys the assistant may use (added from the source) |

Page-level actions live in each page's own toolbar (`New prompt`, `Add item`, `Add skill`,
`Add key`), never in the sidebar.

---

## 2. Prompt page

The conversation view. Bottom composer with:

- A `+` button that opens a **popup** (icon flips plus↔x, click-outside dismisses) with two sections:
  **Job queue** (attach ready items) and **Skills for this message** (per-message skill override).
- Selected items and skills appear as **removable chips** above the input.
- Send button.

Header shows the prompt title plus a compact binding:
- one model → `key · model` (mono chip)
- several → `N models` (and `· best <model>` once one is marked)
- an `Auto feed` chip when queue auto-feed is on.

### Single vs. multi-model answers

A prompt may be bound to one model or several (see New prompt). One question, one turn:

- **One model** → the answer renders inline under the assistant avatar, with `latency · tokens`
  beneath it.
- **Several models** → do **not** cram side-by-side columns. Instead:
  1. A small **comparison strip**: one compact card per model showing only `model name` and
     `latency · tokens`. This is the at-a-glance comparison and it wraps cleanly for 2 or 6 models.
  2. The **selected model's answer full width** below the strip. Clicking a strip card switches which
     answer is shown.
  - The visible answer carries `Mark best`, copy, and rerun. Marking best turns that model green
    (strip card + answer) and propagates to the prompt header and the History row.

---

## 3. Job queue page

Everything feedable to a prompt: scans, files, images. Each row shows name, kind, source, size, state.

States: `running` (a scan still finishing) → `ready` → `in prompt`, or `failed` with a reason
(e.g. "Exceeds 5 MB limit") and a `Retry`.

Feed modes:
- **Manual** — `Add to prompt` on a ready row (row flips to `in prompt`, chip appears on the composer).
- **Auto feed** — toolbar toggle. Every ready item, plus new arrivals, attaches to the next message
  automatically. A banner explains it; the Prompt header shows the `Auto feed` chip.

Every model in a multi-model run receives the **same** attachments, so the comparison stays fair.

---

## 4. History page

Every past prompt: title, the models it ran against, an `N models` badge, the winning model if one was
marked, date, message count. **Rename and delete live only here** (inline rename field; red confirm
strip for delete) — not in the prompt header.

---

## 5. Skills page

A skill is: `name`, `description`, `instructions`, `data access` scope. No global on/off flag.
Its instructions are prepended to the system prompt for **every model in the run** when active.

- List rows show name, description, and the data-access scope; each row has edit + delete.
- The **editor** has only a back arrow in the header and a single `Save`/`Create` action — no delete,
  no cancel inside it (back is cancel). Delete lives on the list rows.
- Activation is decided in exactly two places: per prompt (New prompt form) and per message (`+` popup).

Data-access options: `Scan data`, `Scan data and host inventory`, `Findings only`,
`Queue items only`, `No app data`.

> **Implementation status.** `buildSkillCards` (`list` / `editor` / `creator`) implements
> **create / edit / delete + persistence** against `AIRepository` (`getAllSkills` / `saveSkill` /
> `deleteSkill`). The DAO carries only `name` / `description` / `content` (the instructions),
> stored as a plain `String` — so **markdown skills are just the string** (no file reference; if
> you want `.md` import/export, parse frontmatter→name/description, body→content at the edge and
> keep the model a `String`). **Not yet built:** the `data access` scope (no DAO field), the
> global-vs-per-message **activation**, and the pipeline that assembles active skills into
> `AIRequest.skillsPrompt`.

---

## 6. Providers page

Lists the keys the subject has **added to the assistant** (a subset of what the source offers). Per row:
name, provider badge (Anthropic / OpenAI / Ollama / …), the discovery endpoint
(`baseUrl + /v1/models` or `/api/tags`), a status chip, the discovered models, and last sync.

- `Refresh` (per row) re-runs model discovery. A rejected key shows `401, key rejected` and stays
  visible.
- The row's remove control is an **✕, not a trash can** — removing **unlinks** the key from the
  assistant only. Confirm copy: "The key stays in your NoSneak credentials."

Each key carries its own auth metadata from NoSneak — `provider`, `base-url`, a free-text **auth
scheme** (`auth-type`, e.g. `Bearer`), and an optional **header name** (`header-name`, e.g.
`x-api-key`) — read straight off the credential's property bag (via the `Session.APIKeyInfo` keys
`provider` / `base-url` / `auth-type` / `header-name`), so the Providers page never re-asks for them.

### Add key = pick, not type

`Add key` opens a **picker** sub-page (back-arrow header) listing the credentials the source offers
that aren't already added. There is **no form** — provider, name, base URL, and secret already live on
the credential. Selecting a row adds it and runs discovery immediately. When everything is already
added, the picker says so and points back to NoSneak credential management.

Footer note on the list: keys come from NoSneak credentials; adding one here lets the assistant use it
and discover its models; it is never stored separately.

---

## 7. New prompt

Reached from `New prompt` (Prompt header or History toolbar). Fields:

- **Name**
- **Models** — a **multi-select** list of the *added* keys. Each selected key expands to a model
  dropdown populated from **that key's discovered models** (never hardcoded). One key selected →
  normal conversation; two or more → comparison. A count line reads "N models selected, answers
  compared."
- **Skills** — chips to toggle which skills start active for this prompt.

**Key + model are locked for the life of the prompt.** Changing them means starting a new one, so a
transcript always reflects exactly one model configuration per answer. A key that never synced or
errored offers an inline `Query models` or a jump to Providers, and blocks `Start` until resolved.

---

## 8. Invariants

1. The assistant owns no keys — it reads an `AICredentialSource` and stores only the chosen subset
   (key GUIDs) plus per-key discovery state.
2. Removing a key from the assistant never deletes the underlying credential.
3. Model lists are **discovered**, never hardcoded.
4. Key + model are immutable for a prompt's lifetime.
5. Skills have no global default — activation is per prompt or per message.
6. Every model in a run gets identical prompt text, skills, and attachments.
7. Nothing leaves the machine that the subject didn't attach.
8. Multi-model answers use the strip + full-width pattern, never N cramped columns.
9. Icons come from the standardized NoSneak SVG set, stroked with the theme foreground so they adapt
   to light/dark.

---

## 9. House style

Console design tokens throughout: `--surface-*`, `--text-*`, `--border*`, `--bg-accent` /
`--fill-accent`, `--bg-success` / `--border-success` / `--fill-success`, `--bg-danger` /
`--fill-danger`, `--fill-control`, `--radius`, `--font-mono`. Dense lists are bordered rows with no
card wrapper. One accent-filled button per view. Sentence case; no em dashes in UI strings. Mono for
identifiers (key names, model IDs, endpoints, filenames).

---

## 10. Backend it binds to (the `ai-model` module)

The value DAOs (`io.xlogistx.nosneak.ai.model`) and the service interfaces
(`io.xlogistx.nosneak.ai`) live in the separate **`ai-model`** module — this module depends on it.
**`ai-model/CLAUDE.md` is the authoritative contract**: the pair-based conversation model
(`AIChat` → `AIMessage` → `{AIRequest, AIResponse}`, plus `AISkill` / `AIModel`), the service
interfaces (`AIProvider`, `AIRunner`, `AICallback`, `AICallbackCollection`, `AICredentialSource`,
`AIModelCatalog`, `AIRepository`, `AIException`), the `correlationID` / `providerSessionID`
id scoping, and the interface-shape gaps the compare UI will force. Read it before touching the
send path. What follows is only how *this* module binds to those types.

### State holder (`io.xlogistx.nosneak.ai.assistant.AssistantContext`)

Swing-free. Bundles the injected services (`AICredentialSource`, `AIRepository`) and an internally
built `AIProviderRegistrar`, plus the current selection (`currentChat`, `currentCredential`,
`currentModel`) and two `referenceID`-keyed **canonical caches** (`chatCache`, `skillCache`) that
dedupe DAOs so the same chat/skill is one object across list refreshes. Chat API:
`getAllChats()` / `saveChat(AIChat)` / `deleteChat(AIChat)`; skills mirror it
(`getAllSkills` / `saveSkill` / `deleteSkill`). `setCurrentChat(AIChat)` swaps the in-memory
selection and fires `"currentChat"`; `deleteChat` fires it **only** when the deleted chat is the
current one (nulling first, then firing); `resetContext()` clears the selection + both caches and
fires `"currentChat"` so the transcript blanks. Panels subscribe via `onChange(prop, listener)`
and re-render, so the Chat page never decides *which* chat to load — it renders whatever
`currentChat()` is. The app supplies the concrete services (`SessionAICredentialSource`,
`AssistantStorage`); the registrar is populated on login by `AssistantPanel.reloadProviders()` and
cleared on logout by `clearProviders()`.

### Binding notes

- **Providers.** `AssistantPanel.reloadProviders()` builds an `AIAPIProvider` per key on login
  (off the EDT), discovers its models, and `put`s it in the `AIProviderRegistrar`; `clearProviders()`
  empties the registrar on logout. `AssistantContext.addProvider(APIKey)` also exists (build +
  register, **no** discovery) but is currently unused. Every key is still auto-added — the "pick a
  subset" picker (§6) is only scaffolded (`providerCards` / `buildAddProvider` / empty
  `onAddProvider` / `onRemoveProvider`), not wired.
- **Credentials.** `no-sneak-app`'s `SessionAICredentialSource` implements `AICredentialSource`; its
  `APIKeys()` feeds `reloadProviders` (every API key auto-added).
- **Persistence.** `no-sneak-app`'s `AssistantStorage` implements `AIRepository` against the app's
  H2P `APIDataStore`, owner-scoped by subjectGUID. **Chats and skills both persist** — create,
  edit, and delete all round-trip through the store (`saveChat` inserts when there's no
  `referenceID`, else updates; same for `saveSkill`). `getAllChats` / `getAllSkills` return empty
  when signed out.
- **Send path.** `onSend` builds an `AIRequest`, attaches an `AIMessage` to `currentChat`, and
  calls `AIProvider.send(...)` on a `BackgroundTask` for the single bound provider
  (`getProviders().lookup(chat.getProvider())`); on success it sets the response on the message and
  `saveChat`s the chat. It does **not** use `asyncSend` or the compare fan-out. See the
  interface-shape gaps in `ai-model/CLAUDE.md` before extending it.

---

## 11. Not built yet (deliberately deferred)

- **Redaction preview** — a pre-send panel showing exactly what leaves the machine, with
  hostname/IP pseudonymization toggles. Needs a per-message mapping table kept local so pseudonyms in
  the reply can be expanded back for display.
- **Cite the finding** — clickable finding IDs in answers that expand to the scanner finding and
  offer `Open in Scanner` / `Apply fix in PQC Firewall`.

Both were prototyped and pulled for now. Design the message and finding models so they can return
without a rewrite.
