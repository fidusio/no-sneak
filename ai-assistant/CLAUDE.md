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
> - **A provider is its own persisted record, not a key.** The unit is
>   **`AIProviderConfig`** (an `ai-model` DAO: `keyGUID` / `providerType` / `baseURL` /
>   `defaultModel` / `enabled`, plus the inherited `name`), so **one credential can back several
>   providers** — the same OpenAI key pointed at two base URLs, or relabelled per use.
>   `AIAPIProvider` (this module) is the concrete `AIProvider` over `io.xlogistx.api.ai.AIAPI`
>   (built by `AIAPIBuilder`), created by `AIAPIProvider.create(config, key)` and resolving its
>   type from the **config's** `providerType` (`openai` / `gemini`+`google` /
>   `anthropic`+`claude` / `grok`+`xai`), no longer from the credential's property bag. Its
>   **`getID()` is the config GUID**, which is also the registrar key — a label can be edited
>   without orphaning the chats bound to it.
> - **`reloadProviders()` builds from configs.** It runs on login (from `no-sneak-app`'s
>   `onAuthChange`) off the EDT, reads `getAllProviderConfigs()`, skips the disabled ones,
>   resolves each `keyGUID` against the credential source, builds an `AIAPIProvider` and
>   discovers its models via `AIModelCatalog.refresh()`. `adoptEnabledKeys()` is a **one-time
>   migration** that runs only when the subject has zero configs: every `assistant-enabled`
>   credential gets a config minted from its `provider` / `base-url` properties, so keys linked
>   before this change survive it.
> - **The Providers page is a four-card `CardStack`** (`list` / `add` / `create` / `form`).
>   The list rows carry **edit** (`onEditProvider` → the form, pre-filled) and **remove**
>   (`onRemoveProvider`), which deletes the *config* and only calls `setEnabled(key,false)` when
>   `context.configsUsing(keyGUID) == 0` — `assistant-enabled` is **derived** now, so a stale
>   flag cannot resurrect a provider at the next login. **+ Add Provider** opens the `add`
>   picker, which lists **every** credential the source offers, unfiltered on purpose (a key
>   stays pickable because it can back more than one provider). Selecting a row opens the same
>   `form` on a new config seeded from the key's metadata; **+ New Key** (`create`) makes a
>   credential first via `AICredentialSource.addAPIKey`, then lands on the form. Saving
>   (`onSaveProviderConfig`) persists the config, enables the key, builds the provider, runs
>   discovery, and registers it. There is no separate provider-type prompt any more — the type
>   is a required field on the form.
> - **Model discovery drives the pickers.** A provider→model helper pair (`fillProviders` /
>   `fillModels` / `bindProviderModels`) populates provider combos from the registrar and model
>   combos from the selected provider's cached catalog (`models()`, never hardcoded). Used by the
>   Chat header and the History create/edit forms. Provider combos carry the provider **id**, not
>   the label — two providers can share a name — and render through `providerRenderer()`;
>   `selectProvider` resolves a legacy provider *name* on an older chat back to an id.
>   `fillModels` filters the catalog through `isChatModel` (a `NON_CHAT_MODEL_MARKERS` substring
>   list: whisper / tts / embedding / moderation / dall-e / …), with a live `@TODO` to match with
>   `TokenMatcher` instead.
> - **List rows are label + sublabel, and search covers both.** The shared `ListSection` grew
>   `.description(...)` (a wrapping blurb under the panel title) and `.sublabel(...)` (a muted
>   second line per row). The rule here: the **label is the searchable identity**, the sublabel
>   carries the metadata. Chat History = title / `provider · model · N messages · created ·
>   updated`; Skills = `name · <skill type>` / description; Providers = config label /
>   `type · baseURL · default model · N models · last sync`; the key picker = key name /
>   `provider · baseURL · used by N providers`. `ListSection.filter()` matches label **or**
>   sublabel, so moving metadata off the label does not drop it out of search.
> - **History has create / edit / delete + persistence.** `buildHistoryCards` is a nested
>   `CardStack` (`list` / `editor` / `creator`). `+ New Prompt` opens a Create form
>   (name + provider + model), a row's edit opens a pre-filled Edit form (both persist via
>   `context.saveChat`), and remove calls `context.deleteChat`. The list source is
>   `context.getAllChats()` (→ `AIRepository.getAllChats()`), refreshed by the public EDT-safe
>   `refreshHistory()`, which `no-sneak-app` calls on both login and logout.
> - **Skills have create / edit / delete + persistence, and are typed.** `buildSkillCards` is a
>   nested `CardStack` of exactly two cards (`list` / `editor`). The list source is
>   `context.getAllSkills()` (→ `AIRepository.getAllSkills()`), refreshed by `refreshSkills()`.
>   **The editor card *is* an `MDFileViewer`** — one instance reused for both create and edit,
>   carrying name / description / **type** (`AISkill.SkillType`) / instructions in a single form;
>   remove calls `context.deleteSkill`; all saves run off the EDT via `BackgroundTask.runCatching`.
>   `AISkill.content` is the instruction text — a plain `String`, so a skill authored in markdown
>   is stored verbatim. There is no separate page form and no modal dialog any more: the viewer's
>   own Save is the single persistence point. See §5 and §5.1. The editor also takes a
>   `setValidator(Predicate<MDDocument>)` — `validateSkill` rejects a blank name **before**
>   `onSaveSkill` runs — and `onSaveSkill` snapshots the old field values so a failed store write
>   rolls the cached `AISkill` back and re-marks the editor dirty.
> - **An assistant reply can become a skill.** `AssistantUtil.chatBubble(...)` takes an optional
>   `onSaveAsSkill` `Runnable`, rendered as a borderless "Save as skill" button beside the
>   latency/token line (assistant bubbles only, never the user's). It routes to
>   `onSaveSkillFromResponse`, which confirms first if the editor holds unsaved edits, then opens
>   the skill editor seeded with that response. Guarded by `ChatBubbleSaveAsSkillTest`.
> - **Chat send is wired for a single provider, async, and persists.** `onSend` validates
>   (chat / model / provider — each missing piece gets a dialog, no more silent returns), builds
>   an `AIRequest` (raw user text, maxTokens), attaches an `AIMessage` to `currentChat`, flattens
>   the whole transcript into a `Human:/Assistant:` wire request, and calls
>   `AIProvider.asyncSend(wire, skillText, AssistantCallback)`. The callback (on the API
>   executor thread) decodes the payload via `AssistantMDDecoder`, sets content + model + tokens
>   + latency on a fresh `AIResponse`, `saveChat`s, then marshals UI work to the EDT; its error
>   path removes the unanswered message (on the EDT), re-enables Send, restores the typed text
>   into the composer, and shows the failure dialog. The `currentChat` `PropertyChangeEvent`
>   drives `refreshPrompt()`, which resets the title, model combo, and transcript.
> - **Response decoding is this module's job, and it is the biggest thing here.**
>   `asyncSend` hands back the provider's **raw** `NVGenericMap` (`ai-model` deleted the typed
>   `AICallback`), so `AssistantMDDecoder` — a `DataDecoder<NVGenericMap, String>` singleton —
>   owns the whole extract-and-repair pipeline. See *§10.1 Markdown decoding* below; it is
>   provider-protocol work living in a UI module, which `ai-model/CLAUDE.md` flags as a gap.
> - **Markdown rendering comes from the shared GUI toolkit.** The module's own
>   `MarkDownViewerPanel` was **deleted** and `AssistantUtil.chatBubble` now renders through
>   `io.xlogistx.gui.MDViewerPanel` (xlogistx-gui-audio). The explicit `org.commonmark`
>   dependency was dropped from `ai-assistant/pom.xml` — commonmark and its GFM extensions
>   (tables / strikethrough / task-list-items) now arrive **transitively** through
>   `xlogistx-gui-audio`, which is why the tests can still parse markdown without a declared
>   dependency. If the GUI toolkit ever drops commonmark, `AssistantMDDecoderTest` breaks first.
> - **Per-message skills go through the composer `+` popup** (`showAttachPopup`): a
>   `JPopupMenu` anchored above the button with a "Skills for this message" section, **grouped by
>   skill type** (`groupByType`). An **md skill** is a checkbox — check attaches, uncheck removes,
>   popup stays open while toggling; a **prompt skill** is a borderless button that closes the
>   popup and inserts its content into the composer at the caret (`insertIntoComposer`), and is
>   deliberately *not* added to `pendingSkills`. Checkbox selections live in the
>   transient `pendingSkills` list (the `+` button's tooltip names them), are flattened into
>   `<skill>…</skill>` blocks and passed as `asyncSend`'s **`String skill`** argument (there is
>   no `AIRequest.skillsPrompt` field — the skill text is never persisted with the turn), and
>   clear once `asyncSend` has been dispatched, plus on logout. They survive only a
>   **synchronous** `asyncSend` throw (`onSend` returns before the clear); an async failure
>   arrives after the clear has already run, so a retry does **not** re-send them. Future attachment kinds (photos,
>   files, job-queue items) are meant to be added as further sections of this popup. The chat
>   header also carries the **`Send history`** checkbox (default on; reset to on at logout) —
>   unchecked sends only the new message with no conversation context.
> - **Session reset is wired.** On logout `no-sneak-app` calls `clearProviders()` (wipes the
>   registrar) + `resetPanel()` → `context.resetContext()` (nulls `currentChat` / credential /
>   model, clears the chat + skill caches, fires `currentChat` so the transcript clears) and
>   blanks the composer / resets the card stacks. On app close, `Main` closes the datastore in a
>   `windowClosing` handler.
>
> **Still target-only / stubbed:** the multi-model **compare** path (no `AIRunner`; single-provider
> `asyncSend` is wired); **chat-scoped skill activation** (per-*message* attachment works, but
> nothing marks a skill active for a whole conversation — `AIChat`'s skills list was removed from
> the DAO, so there is nowhere to persist it); the **Job queue** and **Screen capture** pages
> (`onAddJob` / `onEditJob` / `onRemoveJob` / `onAddCapture` / `onSelectArea` /
> `onEditCaptureLocation` / `onEditCaptureDetails` are all empty bodies, and both lists bind to
> `ArrayList::new` with a `_ -> ""` label — there is nothing there to test); per-row provider
> **Refresh**; and a skill's **data-access scope** (no DAO field).
> `AICredentialSource` and `AIRepository` come from `no-sneak-app` (`SessionAICredentialSource`,
> `AssistantStorage` over the H2P `APIDataStore`); the DAOs and interfaces live in **`ai-model`**
> — see its CLAUDE.md. `no-sneak-app` builds
> `AssistantContext(SessionAICredentialSource, AssistantStorage(session))` and passes it to
> `AssistantPanel` on its `ASSISTANT` screen. The dependency is one-way
> (`no-sneak-app → ai-assistant → ai-model`).
>
> **Known rough edges** (see the code, not yet fixed):
> - **No send timeout or cancel.** If the provider never invokes the callback, the Send button
>   stays disabled for the life of the app. `AIProvider.asyncSend` returns `void`, so there is no
>   handle to cancel or time out against — the fix belongs in `ai-model`.
> - **The persisted response is the *display*-processed markdown.** `AssistantCallback` stores
>   what `AssistantMDDecoder` produced — outer fence unwrapped, wrapper fences widened, images
>   neutralized, and the truncation note appended — not the provider's original text. The
>   flattened `Human:/Assistant:` history then feeds that processed text back to the model
>   verbatim, so a truncated turn re-sends the `_Answer cut off…_` line as if the model had
>   written it. Round-tripping through the decoder is idempotent (`repairIsIdempotent`), so it
>   does not compound, but the original is unrecoverable.
> - **`providerSessionID` is sent but never captured.** Nothing calls `chat.setProviderSessionID`,
>   so every turn re-sends the full flattened history even against a stateful provider.
> - **`maxTokens` is hardcoded to 1024** in `onSend` — the single most likely cause of a
>   truncated answer, and not surfaced anywhere in the UI.
> - **Latency is measured from callback construction**, i.e. it includes queueing in the API
>   executor, not just the wire time. `tokens` *is* populated now (from the payload's usage
>   block), but reads `0` for any provider that omits one.
> - **The transcript re-renders in full on every `currentChat` change** (`refreshPrompt` clears
>   and rebuilds every bubble). Fine at current lengths; it is an `MDViewerPanel` per message.
> - **Discovery failures are swallowed.** Both `reloadProviders` and `onSaveProviderConfig` catch
>   and ignore every `getModelCatalog().refresh()` exception, so a rejected or expired key still
>   registers — just with an empty model list and no message. §6's "401, key rejected" status
>   chip is design intent, not built; the closest thing today is the row sublabel reading
>   `0 models · never synced`, plus a model combo that will not populate.
> - **A sublabel lambda runs per row, on the EDT, on every refresh and every keystroke in the
>   search box.** Keep them to fields already in memory. `providersUsing` (walks the registrar)
>   is safe; `AssistantContext.configsUsing` (a store query) is not — the two exist separately on
>   purpose, don't collapse them.
> - **The shared-endpoint race is still open.** `AIAPIProvider.bound()` re-asserts this
>   provider's URL and models-auth encoder before every call, but two providers hitting the wire
>   concurrently can still cross wires — in practice only a provider-form save (which runs
>   discovery) racing an in-flight send. The real fix is per-caller endpoint copies in
>   zoxweb-core's `HTTPAPIManager.buildAPICaller`.

## Source map

Seven classes, all in `io.xlogistx.nosneak.ai.assistant`:

| Class | What it is |
|---|---|
| `AssistantPanel` | The whole UI — the six pages, their nested `CardStack`s, and `onSend` |
| `AssistantContext` | Swing-free state holder: injected services + current selection + caches |
| `AIAPIProvider` | The `AIProvider` implementation over `io.xlogistx.api.ai.AIAPI` (+ inner `ModelCatalog`) |
| `AssistantCallback` | `ConsumerCallback<NVGenericMap>` — payload → `AIResponse`, persist, hop to the EDT |
| `AssistantMDDecoder` | Provider payload → renderable markdown (see §10.1) |
| `AssistantUtil` | `chatBubble(...)` — a rounded bubble around an `io.xlogistx.gui.MDViewerPanel` |
| `MDFileViewer` | Split markdown editor: editor left, live `MDViewerPanel` preview right (see §5.1) |

`MarkDownViewerPanel` used to live here and is **gone** — markdown rendering is
`io.xlogistx.gui.MDViewerPanel` from `xlogistx-gui-audio`, which is also where commonmark now
comes from.

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

> **Implementation status.** The sidebar is a `ButtonGroup` of `JToggleButton`s built by
> `PanelBuilder.buildDefaultSplitPanel`, ordered **Chat / Chat History / Providers —
> separator — Skills / Job Queue / Capture**: the daily loop first, the configuration below the
> line. The separator is why `buildDefaultSplitPanel` takes `JComponent...` rather than
> `JToggleButton...` — toggle buttons join the group, anything else is laid out but ungrouped.
> The History / Skills / Providers buttons **refresh their list on the way in**
> (`refreshHistory()` / `refreshSkills()` / `providerList.refresh()`): a `ListSection` only
> rebuilds from its supplier on `refresh()`, so a page that was merely switched back to used to
> show whatever it held at the last mutation — a message count frozen until the next login.
> Providers deliberately refreshes the **list only**, not `refreshProviderViews()`, which would
> repopulate the chat editor's provider combo and reset a selection that card is still holding.

---

## 2. Prompt page

The conversation view. Bottom composer with:

- A `+` button that opens a **popup** (icon flips plus↔x, click-outside dismisses) with two sections:
  **Job queue** (attach ready items) and **Skills for this message** (per-message skill override).
- Selected items and skills appear as **removable chips** above the input.
- Send button.

The skills section is **grouped by `SkillType`**, and the two types are different interactions,
not a cosmetic split: **md skills** are checkboxes that attach (system prompt), **prompt skills**
are buttons that paste their text into the composer for the subject to edit before sending. See
§5's implementation status for the mechanics and why a prompt skill is not also attached.

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

> **Implementation status.** The row is a **two-line** `ListSection` row: the label is the chat
> title alone (blank → `Untitled chat`), and `chatSublabel` supplies
> `provider · model · N messages · created <ts> · updated <ts>` (`timestamp(...)`,
> `yyyy-MM-dd HH:mm` local, `n/a` for an unset stamp). The provider half resolves through
> `context.lookupProvider(...)` because `AIChat.provider` holds a **config GUID** now — a raw
> ref would render as a GUID. Keeping the timestamps off the label is what makes the search box
> filter on titles; they stay findable because `filter()` also matches the sublabel. Note
> `ListSection.Builder.label(...)` is a **setter, not an accumulator** — calling it twice
> silently discards the first lambda. The "updated" half is only meaningful because
> `AssistantStorage` stamps `lastTimeUpdated` on the update branch; the store itself never bumps
> it (see `ai-model/CLAUDE.md`). The list is `.scrollable()` + `.search(...)`, filtering
> client-side over its supplier.

---

## 5. Skills page

A skill is: `name`, `description`, `instructions`, `data access` scope. No global on/off flag.
Its instructions are prepended to the system prompt for **every model in the run** when active.

- List rows show name, description, and the data-access scope; each row has edit + delete.
- The **editor** is the markdown editor itself (§5.1) with its name / description / type fields
  turned on: one `Save` (relabelled `Create` for a new skill) and one `Cancel` that reverts and
  returns to the list. No delete inside it — delete lives on the list rows.
- Activation is decided in exactly two places: per prompt (New prompt form) and per message (`+` popup).

Data-access options: `Scan data`, `Scan data and host inventory`, `Findings only`,
`Queue items only`, `No app data`.

> **Implementation status.** `buildSkillCards` (`list` / `editor`) implements
> **create / edit / delete + persistence** against `AIRepository` (`getAllSkills` / `saveSkill` /
> `deleteSkill`). Rows are two-line: `skillLabel` puts **name and type on the first line**
> (`network-recon · md skill`) because the type is what decides whether the composer attaches
> the skill or pastes it — it belongs with the identity, not buried in the description — and the
> description is the sublabel (run through `SUS.trimOrNull`, so a whitespace-only one collapses
> the row back to a single line). The DAO carries `name` / `description` / `content` (the
> instructions) / `skillType`, with the content a plain `String` — so **markdown skills are just
> the string**
> (no file reference; `MDFileViewer`'s *Open file* loads a `.md` off disk **into the editor
> buffer**, it does not create a link to it, and there is no export. If you want frontmatter
> import, parse it →name/description, body→content at the edge and keep the model a `String`).
>
> **There is one skill form, and it is the markdown editor.** `buildSkillEditor()` builds a
> single `MDFileViewer` (field `skillEditor`), enables its optional name / description / type
> rows (`withName` / `withDescription` / `withTypes(...)`, the type combo rendered through
> `SkillType.getName()` — "md skill" / "prompt skill" — rather than `toString()`), and hands it
> `setOnCommit(this::onSaveSkill)` plus a `setOnCancel` that clears `selectedSkill` and returns
> to the list. Both entry points route through `showSkillEditor(skill, saveText)`:
> `onAddSkill` passes `null` + "Create", `onEditSkill` passes the row + "Save". Reusing **one**
> instance is why the old creator/editor pair had to go — a Swing component cannot sit on two
> cards, and the duplicated combos silently read each other's selection.
>
> `onSaveSkill(MDDocument)` is the only persistence point: it rejects a blank name with a dialog,
> then writes name + description + type (`document.typeAs()`) + instructions onto
> `selectedSkill` (or a fresh `AISkill` when creating) and saves off the EDT via
> `BackgroundTask.runCatching(..., skillEditor.getSaveButton(), ...)`. Cancel calls the viewer's
> `revert()` before the handler, so backing out leaves the cached `AISkill` unmutated — the same
> guarantee the old per-page buffer gave, now enforced inside the editor. Note the skills page is
> **not** wrapped in an outer `JScrollPane` (unlike the other pages) — the editor's `JSplitPane`
> needs a real viewport height, and the list card already scrolls itself.
>
> **Per-message activation is built, and the two types behave differently** (see §2). The
> composer `+` popup groups skills by type (`groupByType`, enum order, name-sorted within a
> group, untyped last under `other`, headers only when more than one group exists). An **md
> skill** is a checkbox that toggles `pendingSkills`, flattened into `<skill>…</skill>` blocks
> as `asyncSend`'s `skill` argument. A **prompt skill** is a borderless button that closes the
> popup and inserts its content into the composer at the caret — it is deliberately **not**
> added to `pendingSkills`, or the same text would go out twice (once as the message, once as a
> system-prompt block). A consequence worth knowing: prompt-skill text is persisted with the
> turn as ordinary message content, while attached md skills are still recorded nowhere.
>
> **Not yet built:** the `data access` scope (no DAO field) and **per-prompt** activation. The
> latter regressed rather than stalled: `AIChat` used to carry a `skills` list and it was
> **removed** from the DAO, so a chat cannot remember which skills it runs with. Note also that
> nothing records *which* skills went out with a given turn — `AIRequest` has no `skillsPrompt`
> field, so the stored transcript cannot tell you what the model was actually instructed with.

### 5.1 The markdown editor (`MDFileViewer`)

A standalone `JPanel`, deliberately **not** to the house spec in §9 — it is its own thing, and it
*is* the skill editor page today (§5), reusable anywhere a markdown string needs editing.

- **Split view.** Mono `JTextArea` in a scroll pane on the left, `io.xlogistx.gui.MDViewerPanel`
  on the right, 50/50 one-touch-expandable `JSplitPane`. The preview re-renders on a 250 ms
  non-repeating `Timer` restarted per keystroke, so typing does not reparse per character;
  `Save` / `Cancel` / `setMarkdown` stop the pending timer and render immediately.
- **Save and Cancel are both callback-driven and always visible.** `setOnSave(Consumer<String>)`
  hands over the current markdown; `setOnCommit(Consumer<MDDocument>)` hands over the metadata
  fields with it and both fire on Save; `setOnCancel(Runnable)` reverts the editor to the last
  committed text **first**, then runs the handler — so a host that only wants "go back" does not
  have to re-load the source to undo edits. `revert()` is public for a host that prefers its own
  back arrow. `⌘S`/`Ctrl+S` saves, `Esc` cancels.
- **Optional metadata fields, off by default.** A `GridBagLayout` form sits between the toolbar
  and the split, invisible until a host asks for a row: `withName(...)`, `withDescription(...)`,
  and a **generic** `withTypes(...)` (`T[]` or `Collection<? extends T>`, an optional
  `Function<? super T,String>` renderer, and an overload taking the row label) that holds any
  object, not just `AISkill.SkillType`. Each `withX` adds its row once and updates the value
  afterwards. Read back with `getDocumentName()` / `getDescription()` / `<T> getSelectedType()`
  / `getDocument()`, or write with `setDocumentName` / `setDescription` / `setSelectedType`
  (`setName` was taken by `Component`). `MDDocument` is a plain value class (name, description,
  type, markdown) with a typed `typeAs()`. `commit()` snapshots the fields alongside the
  markdown and `revert()` restores them, so `isDirty()` — and therefore the status line and the
  Open-file overwrite confirm — reacts to a name edit too.
- **Open file** loads a `.md` / `.markdown` / `.txt` from disk (UTF-8, remembers the last
  directory, confirms first when the buffer is dirty). The load counts as an **edit, not a
  commit** — it never touches the committed baseline, so Cancel still returns to the original
  text and nothing reaches the caller until Save. There is no write-to-disk path; the status
  line shows provenance (`loaded readme.md · unsaved changes`).
- Host hooks: `setTitle` (renames the editor pane's border), `setSaveText` ("Create" / "Save" on
  the skills page), `getSaveButton()` / `getCancelButton()` for driving an async save through
  `BackgroundTask.runCatching`, plus `isDirty` / `markDirty` / `markSaved`.
- `JPanelTest` (test sources) is a `main`-method visual harness for it, in the same spirit as
  `ChatBubbleTest`.

---

## 6. Providers page

Lists the **providers** the subject has configured — not the keys. Per row: the provider's label,
provider badge (Anthropic / OpenAI / Ollama / …), the discovery endpoint
(`baseUrl + /v1/models` or `/api/tags`), a status chip, the discovered models, and last sync.

- `Refresh` (per row) re-runs model discovery. A rejected key shows `401, key rejected` and stays
  visible.
- The row's remove control is an **✕, not a trash can** — removing deletes the *provider config*
  and unlinks the credential only when nothing else uses it. Confirm copy: "The key stays in your
  NoSneak credentials."

> **Implementation status.** A provider is an `AIProviderConfig` row (see the status block at the
> top), so **one credential can back several providers** and the row's identity is the config's
> editable label. `providerSublabel` renders
> `providerType · baseURL · default <model> · N models · <last sync>` — that model count and
> `never synced` are currently the *only* signal that a key was rejected, because discovery
> failures are swallowed (see the rough edges). A per-row **Refresh** is still **not built**:
> re-discovery happens on login, and as a side effect of saving the provider form.
> The `✕` runs `onRemoveProvider` → `deleteProviderConfig` + `getProviders().unregister(id)`,
> and calls `setEnabled(key,false)` only when `configsUsing(keyGUID)` hits zero.
> `AIProviderConfig.enabled` exists but is effectively **write-only `true`** — the form always
> sets it, and nothing in the UI can disable a provider without deleting its config.

Each key carries its own auth metadata from NoSneak — `provider`, `base-url`, a free-text **auth
scheme** (`auth-type`, e.g. `Bearer`), and an optional **header name** (`header-name`, e.g.
`x-api-key`) — read straight off the credential's property bag (via the `Session.APIKeyInfo` keys
`provider` / `base-url` / `auth-type` / `header-name`), so the Providers page never re-asks for them.

### Add provider = pick a key, or create one through the source

`+ Add Provider` opens a **picker** sub-page (back-arrow header) listing the credentials the source
offers — **unfiltered**, because a key that already backs one provider can back another. Rows read
key name over `provider · baseURL · used by N providers`; that count comes from `providersUsing`,
which walks the **registrar** rather than the store, since the sublabel renders per row on the EDT.
Selecting a row opens the provider **form** (`buildProviderForm`) on a new config seeded from the
key's `provider` / `base-url` properties: Key (read-only) / Label / Provider type / Base URL /
Default model. Below the picker, **New Key** opens a `create` card (`buildCreateProviderKey`) for a
key NoSneak doesn't have yet: Label / Provider (the known types) / API Key / optional Base URL — no
domain/app-id scope fields, that's Credentials vocabulary. It creates through
`AICredentialSource.addAPIKey` (→ `Session.storeAPIKey` with `external = true` +
`setAssistantEnabled`), then lands on the same form. The key is a full NoSneak credential —
visible, editable, and deletable in Credentials.

> **Known gap.** On the add path the form's **Default model** combo is empty: `showProviderForm`
> only calls `fillModels` for an existing config, and discovery has not run yet. You save, reopen
> the provider via edit, and only then can you pick from the discovered list.

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

1. The assistant stores no keys — it reads an `AICredentialSource` and stores only
   `AIProviderConfig` rows (each holding a key **GUID**, never a secret) plus in-memory discovery
   state. It may *create* a key through `AICredentialSource.addAPIKey` (the Providers page's
   **New Key** form), but the key materializes as an ordinary NoSneak credential owned by the
   source, external-flagged and assistant-enabled on creation.
2. Removing a provider from the assistant never deletes the underlying credential.
3. Model lists are **discovered**, never hardcoded.
4. Key + model are immutable for a prompt's lifetime. **Not enforced today** — the chat header's
   model combo is editable and `onSend` writes the selection back to the chat, and the Edit Chat
   form rewrites both provider and model. Either lock the controls or drop the invariant.
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
interfaces (`AIProvider`, `AIRunner`, `AICallbackCollection`, `AICredentialSource`,
`AIModelCatalog`, `AIRepository`, `AIException`), the `correlationID` / `providerSessionID`
id scoping, and the interface-shape gaps the compare UI will force. Read it before touching the
send path. What follows is only how *this* module binds to those types.

> The typed **`AICallback`** is gone. `AIProvider.asyncSend(AIRequest, String skill,
> ConsumerCallback<NVGenericMap>)` delivers the provider's raw payload, so decoding it into an
> `AIResponse` happens **here** — `AssistantCallback` + `AssistantMDDecoder`.

### State holder (`io.xlogistx.nosneak.ai.assistant.AssistantContext`)

Swing-free. Bundles the injected services (`AICredentialSource`, `AIRepository`) and an internally
built `AIProviderRegistrar`, plus the current selection (`currentChat`, `currentCredential`,
`currentModel`) and three **GUID**-keyed **canonical caches** (`chatCache`, `skillCache`,
`configCache`) that dedupe DAOs so the same chat/skill/config is one object across list refreshes
(`referenceID` is always null on the H2P store — see the identity note in `ai-model/CLAUDE.md`).
Chat API: `getAllChats()` / `saveChat(AIChat)` / `deleteChat(AIChat)`; skills mirror it
(`getAllSkills` / `saveSkill` / `deleteSkill`), as do provider configs
(`getAllProviderConfigs` / `saveProviderConfig` / `deleteProviderConfig`), plus
`configsUsing(keyGUID)` (counts stored configs borrowing a credential — it queries the **store**,
so never call it per row) and `lookupProvider(ref)` (registrar lookup by id, falling back to a
name match so a chat saved before providers had ids still resolves). `setCurrentChat(AIChat)` swaps the in-memory
selection and fires `"currentChat"`; `deleteChat` fires it **only** when the deleted chat is the
current one (matched by instance **or GUID**, nulling first, then firing — instance identity
alone misses, because History refreshes hand out fresh instances whenever the cache hasn't seen
the GUID yet); `resetContext()` clears the selection + both caches and
fires `"currentChat"` so the transcript blanks. Panels subscribe via `onChange(prop, listener)`
and re-render, so the Chat page never decides *which* chat to load — it renders whatever
`currentChat()` is. The app supplies the concrete services (`SessionAICredentialSource`,
`AssistantStorage`); the registrar is populated on login by `AssistantPanel.reloadProviders()` and
cleared on logout by `clearProviders()`.

### Binding notes

- **Shared-endpoint hazard (`AIAPIProvider.bound()`).** zoxweb's
  `HTTPAPIManager.buildAPICaller` hands every `AIAPI` the **same shared endpoint instances**
  for the `ai-api` domain, and both `HTTPAPICaller.updateURL` and `AIAPIBuilder.createAIAPI`'s
  Anthropic models-authorization special case **mutate those shared objects** — so creating a
  provider rebinds every other provider's base URL (symptom: add a Gemini key mid-session and
  the existing OpenAI provider's sends start failing — its requests now go to Gemini's URL).
  `AIAPIProvider.bound()` re-asserts this provider's URL and models-auth encoder before
  **every** call (`send`, `asyncSend`, catalog `refresh`). This is a workaround: a tiny race
  remains if two providers hit the wire concurrently (panel sends are serialized, so in
  practice only a per-row Refresh racing an in-flight send). The real fix is per-caller
  endpoint copies in `buildAPICaller` (zoxweb-core).
- **Providers.** `AssistantPanel.reloadProviders()` builds an `AIAPIProvider` per **enabled
  `AIProviderConfig`** on login (off the EDT), resolving each config's `keyGUID` against the
  credential source, discovering its models, and `put`ting it in the `AIProviderRegistrar` —
  which is keyed by **`AIProvider::getID`** (the config GUID), not by name. `clearProviders()`
  empties the registrar on logout. `adoptEnabledKeys()` mints configs for `assistant-enabled`
  credentials the first time a subject has none.
- **Credentials.** `no-sneak-app`'s `SessionAICredentialSource` implements `AICredentialSource`;
  `APIKeys()` feeds the picker and the `keyGUID` resolution, `enabledAPIKeys()` feeds only the
  one-time `adoptEnabledKeys` migration, and `setEnabled(key,on)` persists the flag on the
  credential's `assistant-enabled` property (via `Session`). Key identity goes through the
  interface's own `AICredentialSource.guidOf(key)` static (and the `getKey(guid)` default) —
  never the name, which is editable.
- **Persistence.** `no-sneak-app`'s `AssistantStorage` implements `AIRepository` against the app's
  H2P `APIDataStore`, owner-scoped by subjectGUID. **Chats, skills, and provider configs all
  persist** — create, edit, and delete round-trip through the store (`saveChat` inserts when
  there's no `GUID`, else updates; `saveSkill` and `saveProviderConfig` mirror it — the store
  assigns the GUID on insert and every path upserts by GUID underneath). `getAllChats` /
  `getAllSkills` / `getAllProviderConfigs` return empty when signed out.
- **Send path.** `onSend` validates chat / model / provider with user-visible dialogs, then calls
  `AIProvider.asyncSend(wire, skillText, callback)` for the single bound provider
  (`getProviders().lookup(chat.getProvider())`), where `wire` is a **second, throwaway**
  `AIRequest` carrying the flattened `Human:/Assistant:` transcript — the `AIRequest` stored on
  the `AIMessage` keeps the raw user text, so the transcript shows what was typed while the model
  sees the whole conversation. `AssistantCallback` decodes the payload (`AssistantMDDecoder`),
  persists via `saveChat`, and marshals UI updates (and the error-path message removal) to the
  EDT. Both the synchronous throw (`asyncSend` itself failing) and the async error path undo the
  optimistic message and restore the composer text. The compare fan-out (`AIRunner`) is still
  unbuilt. See the interface-shape gaps in `ai-model/CLAUDE.md` before extending it.

### 10.1 Markdown decoding (`AssistantMDDecoder`)

A `DataDecoder<NVGenericMap, String>` singleton, and the only place that understands provider
wire formats. `decode(payload)` runs, in order:

1. **Extract the text.** `AIAPI.AIMDDecoder` first; on empty, `fromContentBlocks` walks
   `choices[0].message.content` (and a top-level `content`) as an `NVGenericMapList`, keeping
   `text` / `output_text` blocks — the Anthropic/Responses shape. If both come back empty it
   falls back to **rendering the raw JSON in a ```json fence** rather than showing nothing, so a
   shape it does not know still surfaces something debuggable in the bubble.
2. **`toMarkdown`** = `unwrapOuterFence` → `repairWrapperFences` → `neutralizeImages`.
   - `unwrapOuterFence` strips a whole-response ```` ```md ```` / ```` ```markdown ```` wrapper
     (a model asked for "a markdown file" answers with the document inside a fence, which would
     otherwise render as one grey box).
   - `repairWrapperFences` **widens** a wrapper whose inner blocks use a backtick run at least as
     long as its own — the collision that makes a document render as a code box followed by
     orphaned prose. Idempotent; leaves well-formed and unbalanced input alone.
   - `neutralizeImages` rewrites `![alt](url)` → `[image: alt](url)` and `<img` → `&lt;img`
     **outside** code spans and fences. Net effect: a model's answer can never make the viewer
     issue an outbound image fetch — it degrades to a plain link. Inline code stays literal, so a
     markdown tutorial that *talks about* `![alt](url)` still shows it verbatim.
3. **Truncation.** `truncated(payload)` checks `choices[0].finish_reason`, `stop_reason`, and
   `candidates[0].finishReason` for `length` / `max_tokens`; when set it closes any dangling
   fence and appends the `_Answer cut off…_ ` note.

`tokens(payload)` reads `usage` **or** `usageMetadata`, preferring `total_tokens` /
`totalTokenCount`, else summing the prompt/input/completion/output/candidates spellings; `0`
when absent.

**Tests.** The module runs **45 green tests**: `AssistantMDDecoderTest` (29) renders through
commonmark and asserts on the resulting HTML rather than on strings, so it checks the fix actually
renders — plus fence fixtures in `src/test/resources/fence/`; `MDFileViewerTest` (7) covers the
editor's commit/revert/dirty contract; `AssistantContextTest` (5) guards the canonical caches, the
delete-fires-only-for-the-current-chat rule, and `resetContext`, against an in-memory
`AIRepository` that hands out a fresh instance per read like the real store does; and
`ChatBubbleSaveAsSkillTest` (4) covers the "Save as skill" affordance.

Three files in test sources are **not** JUnit tests but `main`-method visual harnesses:
`ChatBubbleTest` (renders `AssistantUtil.chatBubble` over the real transcript layout under both
FlatLaf themes — paste a provider answer into its `RESPONSE` constant to eyeball a rendering bug),
`JPanelTest` (the `MDFileViewer`), and `AssistantPanelTest` (the whole panel against fake
credentials and an in-memory repository — layout only; its keys are not real, so anything touching
a wire will fail). Run the suite with
`mvn -pl ai-assistant test -DskipTests=false -Dmaven.test.skip=false` (surefire is skipped by the
parent pom).

---

## 11. Not built yet (deliberately deferred)

- **Redaction preview** — a pre-send panel showing exactly what leaves the machine, with
  hostname/IP pseudonymization toggles. Needs a per-message mapping table kept local so pseudonyms in
  the reply can be expanded back for display.
- **Cite the finding** — clickable finding IDs in answers that expand to the scanner finding and
  offer `Open in Scanner` / `Apply fix in PQC Firewall`.

Both were prototyped and pulled for now. Design the message and finding models so they can return
without a rewrite.
