# NoSneak AI Assistant — UI Orientation

A top-level Swing window (`View > AI Assistant`) that lets the subject send their own network
data to third-party AI models and compare answers across them.

The assistant owns **no** API keys and adds **no** AI connections of its own. It reads keys from an
external `AICredentialSource` (the NoSneak credential store) and keeps a list of the ones the subject
has chosen to use.

> **Implementation status.** This document is the UI design spec. Today the module ships only
> `gui.AssistantPanel` (a minimal Providers list fed by `AICredentialSource.APIKeys()`) plus the
> `agent` backend **interfaces** — everything below is the target, and the Prompt / Job queue /
> History / Skills pages and every provider implementation are not built yet. `no-sneak-app` mounts
> `AssistantPanel` on its `ASSISTANT` screen via a `SessionAICredentialSource`; the dependency is
> one-way (`no-sneak-app → ai-assistant`).

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

## 10. Backend it binds to (`agent` package — interfaces only, no implementations yet)

Value types live in the **`agent.model`** subpackage; the interfaces in **`agent`**.

- `AIProvider` (per credential, `extends GetName, GetDescription`) — `send(AIRequest)`,
  `asyncSend(AIRequest, AICallback)`, `getModelCatalog()`, plus `setAPIKey` / `getAPIKey` and
  `setHTTPAPICaller` / `getHTTPAPICaller` (the request goes out through zoxweb's `HTTPAPICaller`).
  Concrete providers are meant to register into `agent.model.AIProviderRegistrar`
  (`RegistrarMapDefault<String, AIProvider>`, keyed by `AIProvider::getName`) — nothing registers yet.
- `AIRunner.send(AIRequest, AIProvider...)` → returns an **`AICallbackCollection`** for the fan-out
  (compare). The collection exposes `size()`, `completed()` / `isComplete()`, `responses()`,
  `errors()`, and `onComplete(Runnable)` — one request across N providers, results aggregated per
  provider.
- `AICallback extends org.zoxweb.shared.task.ConsumerCallback<AIResponse>` — a single callback that
  carries both the success (response) and the error path.
- `AICredentialSource.APIKeys()` (returns `List<APIKey<String>>`) supplies the keys the Providers
  picker lists. `no-sneak-app`'s `SessionAICredentialSource` implements it.
- `AIModelCatalog` backs each key's discovered models (`models()`), `refresh()` (the Refresh button),
  and `lastSynced()` (the "Last sync" line).
- `agent.model` value types: `AIRequest` / `AIResponse` / `AIMessage` / `AIModel`.

UI notes that affect these: the compare view needs each answer paired with its provider (so a
per-provider result, not two flat lists) — `AICallbackCollection` already keeps responses/errors
aligned to the run. `asyncSend` currently returns `void`; for the Stop button (and for aborting the
other columns) it needs a cancel handle/identifier — flagged in the interface's own TODO. Attachments
(job queue) imply `AIMessage` content must eventually carry non-text parts, or attachments get
pre-extracted to text before the request is built.

---

## 11. Not built yet (deliberately deferred)

- **Redaction preview** — a pre-send panel showing exactly what leaves the machine, with
  hostname/IP pseudonymization toggles. Needs a per-message mapping table kept local so pseudonyms in
  the reply can be expanded back for display.
- **Cite the finding** — clickable finding IDs in answers that expand to the scanner finding and
  offer `Open in Scanner` / `Apply fix in PQC Firewall`.

Both were prototyped and pulled for now. Design the message and finding models so they can return
without a rewrite.
