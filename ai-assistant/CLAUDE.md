# NoSneak AI Assistant — UI Orientation

A top-level Swing window (`View > AI Assistant`) that lets the subject send their own network
data to third-party AI models and compare answers across them.

The assistant owns **no** API keys and adds **no** AI connections of its own. It reads keys from an
external `AICredentialSource` (the NoSneak credential store) and keeps a list of the ones the subject
has chosen to use.

> **Implementation status.** This document is the UI design spec. Today the module ships
> `io.xlogistx.nosneak.ai.assistant.AssistantPanel` with `ListSection`-based **History**, **Skills**, and **Providers** lists (History
> over `AIChatRepository.getAllChats()` with new/open/delete wired, Providers over the
> `AIProviderRegistrar`, Skills over `AssistantContext.getSkills()`) and a basic **Chat** page — a
> scrolling transcript of message bubbles plus a multiline composer (Enter to send, Shift+Enter for a
> newline) with a title + model-selector header. The Chat page is still **visual only** on send: Send
> appends a local bubble and does not yet call a provider or write to the chat model. The backend
> **interfaces** (`io.xlogistx.nosneak.ai`) and the **value DAOs** (`io.xlogistx.nosneak.ai.model`:
> `AIChat`, `AIMessage`, `AIRequest`, `AIResponse`, `AISkill`, `AIModel`) now live in the separate
> **`ai-model`** module (this module depends on it) — see `ai-model/CLAUDE.md`. Per-panel state lives in
> **`io.xlogistx.nosneak.ai.assistant.AssistantContext`** — a Swing-free holder for the credential source, the
> `AIChatRepository`, an `AIProviderRegistrar`, and the current chat/credential/model, exposing
> `newChat` / `openChat` / `deleteChat` and `PropertyChangeSupport` (`onChange`) so panels observe
> selection changes. Chat persistence is now real: `AssistantStorage` is a datastore-backed
> `AIChatRepository` over the app's H2P `APIDataStore`. Still target-only: the Job queue page, the Chat
> send path, and every provider implementation — the Providers list stays empty until a provider registers
> (`AssistantContext.addProvider` is a stub), and Skills has no store behind it. `no-sneak-app` builds an
> `AssistantContext(SessionAICredentialSource, AssistantStorage(dataStore))` and passes it to
> `AssistantPanel` on its `ASSISTANT` screen. The dependency is one-way (`no-sneak-app → ai-assistant`).

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
`AIModelCatalog`, `AIChatRepository`, `AIException`), the `correlationID` / `providerSessionID`
id scoping, and the interface-shape gaps the compare UI will force. Read it before touching the
send path. What follows is only how *this* module binds to those types.

### State holder (`io.xlogistx.nosneak.ai.assistant.AssistantContext`)

Swing-free. Bundles the injected services (`AICredentialSource`, `AIChatRepository`) and an internally
built `AIProviderRegistrar`, plus the current selection (`currentChat`, `currentCredential`,
`currentModel`). `newChat()` persists a fresh `AIChat` via `chats.save(...)`, `openChat(refID)` loads one,
and `deleteChat(AIChat)` removes it; the chat mutators fire a `"currentChat"`
`PropertyChangeEvent`; panels subscribe via `onChange(prop, listener)` and re-render, so the Chat page
never decides *which* chat to load — it renders whatever `currentChat()` is. The app supplies the
concrete services (`SessionAICredentialSource`, `AssistantStorage`); the registrar has no providers
registered yet.

### Binding notes

- **Providers.** `AssistantContext.addProvider(APIKey)` is the intended registration hook (still an
  empty stub); the Providers page reads the `AIProviderRegistrar`, so it stays empty until a concrete
  `AIProvider` exists and registers.
- **Credentials.** `no-sneak-app`'s `SessionAICredentialSource` implements `AICredentialSource`; its
  `APIKeys()` feeds the Providers picker.
- **Persistence.** `no-sneak-app`'s `AssistantStorage` implements `AIChatRepository` against the app's
  H2P `APIDataStore` — so History and chat save/load are real.
- **Send path (not wired).** The Chat composer's `onSend` is visual-only today — it does not build an
  `AIRequest`, attach an `AIMessage` to `currentChat`, call `AIProvider.asyncSend`, or persist. See
  the interface-shape gaps in `ai-model/CLAUDE.md` before wiring it.

---

## 11. Not built yet (deliberately deferred)

- **Redaction preview** — a pre-send panel showing exactly what leaves the machine, with
  hostname/IP pseudonymization toggles. Needs a per-message mapping table kept local so pseudonyms in
  the reply can be expanded back for display.
- **Cite the finding** — clickable finding IDs in answers that expand to the scanner finding and
  offer `Open in Scanner` / `Apply fix in PQC Firewall`.

Both were prototyped and pulled for now. Design the message and finding models so they can return
without a rewrite.
