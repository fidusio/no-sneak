# NoSneak AI Model (`ai-model`)

The backend **contract** the AI assistant binds to: the value DAOs plus the service
interfaces, with **no provider or store implementations**. `ai-assistant` (the Swing UI) and
`no-sneak-app` (the concrete `AICredentialSource` / `AIRepository`) depend on this module;
it depends on neither. The dependency is one-way: `no-sneak-app → ai-assistant → ai-model`.

Two packages:

- **`io.xlogistx.nosneak.ai.model`** — concrete, JSON-serializable `PropertyDAO`s (the
  conversation model), plus `AIProviderRegistrar`.
- **`io.xlogistx.nosneak.ai`** — the service interfaces (no implementations) and `AIException`.

> **Status.** Interfaces + DAOs only in *this* module. JSON round-trip tests
> (`AIChatRoundTripTest` 9 + `AISkillRoundTripTest` 3, **12 green**) guard the DAO
> (de)serialization invariants. The concrete implementations all live **outside** this module:
> `ai-assistant`'s **`AIAPIProvider`** (an `AIProvider` + inner `AIModelCatalog`, wrapping
> `io.xlogistx.api.ai.AIAPI` built by `AIAPIBuilder`, resolving provider type from its
> **`AIProviderConfig`**) and `no-sneak-app`'s **`AssistantStorage`** (an `AIRepository` over
> the app's H2P `APIDataStore`). There is still **no** `AIRunner` implementation (the compare
> fan-out). Providers register into an `AIProviderRegistrar` keyed by `AIProvider::getID` —
> the config GUID.
>
> **The async contract is untyped on purpose (for now).** `AICallback` — the old
> `ConsumerCallback<AIResponse>` — has been **deleted**. `asyncSend` now takes a
> `ConsumerCallback<NVGenericMap>` and hands back the provider's **raw** JSON payload; building
> an `AIResponse` out of it (markdown extraction, token counts, truncation detection) is the
> caller's job. `ai-assistant`'s `AssistantCallback` + `AssistantMDDecoder` are the one
> implementation — see the gap note at the bottom.

---

## Conversation model (`io.xlogistx.nosneak.ai.model`)

The transcript is **pair-based**, not role-tagged:

```
AIChat  ──has many──▶  AIMessage  ──is──▶  { AIRequest, AIResponse }
```

- **`AIChat`** — one conversation. Holds an ordered list of `AIMessage`, a default `model`, the
  bound `provider` (the provider/key name it is locked to), and a `providerSessionID` — that is
  the **whole** field set. There is no `systemPrompt` field, and the chat-scoped **`skills`
  list was removed** (with `addSkill` / `removeSkill`): skills are per-call only, passed as the
  `skill` argument to `send`/`asyncSend`. Its own identity is the inherited
  **`GUID`** — **not** a hand-rolled id, and **not** `referenceID`: that field is deprecated in
  zoxweb (commented out of the base DAO) and the H2P store never sets it, so `getReferenceID()`
  is always null on persisted entities. Anything keying chats/skills (caches, save branches,
  same-chat checks) must use `getGUID()`. Helpers:
  `startTurn(userInput, maxTokens)` (appends a request-only message), `addMessage(AIMessage)`,
  and `toRequest(userInput, maxTokens)`.
- **`AIMessage`** — one exchange = one provider round-trip: an `AIRequest` plus the
  `AIResponse` it produced. **Roles are implicit in the pair** (request = user side, response =
  assistant side); there is no role field. The response half is null until the provider
  replies. A multi-step/tool turn is several `AIMessage`s in a row, and the "request" side is
  "model input this round" (user text *or* a tool result), not strictly what a human typed.
- **`AIRequest`** — a single outgoing turn: `model`, `content`, `maxTokens`, `correlationID`,
  `providerSessionID`. There is **no `skillsPrompt` field** — the skill text travels as the
  separate `String skill` argument on `AIProvider.send`/`asyncSend`, so it is never persisted
  with the request. Per-call tuning can ride the inherited `properties` bag.
- **`AIResponse`** — `model`, `content`, `correlationID`, `providerSessionID`, `tokens`,
  `latency`. `getTokens()` / `getLatency()` are **null-safe**: an unset field reads `0` rather
  than throwing on unbox, which is what makes a response persisted before those were populated
  still readable.
- **`AISkill`** — `content` (the instruction text) plus **`skillType`**; `name` and
  `description` are the inherited `NVEntity` fields. `SkillType` is a `GetName` enum —
  `MD_SKILL` ("md skill") / `PROMPT_SKILL` ("prompt skill") — and the two mean different things
  to the composer: an md skill is **attached** (flattened into the `skill` argument), a prompt
  skill's content is **inserted into the message box** for the subject to edit before sending
  (see `ai-assistant/CLAUDE.md` §2). The enum-typed `NVConfig` follows the zoxweb pattern
  (`CreditCardType`, `FileType`); H2P persists it by `name()` and rebuilds it via
  `SharedUtil.enumValue`. Verified round-trip against a real encrypted H2 store, both
  directions.
- **`AIModel`** — `provider` + model id (`getModelID()` / `getName()`), cached by
  `AIModelCatalog`.
- **`AIProviderConfig`** — *a configured provider*, and the newest DAO here. `keyGUID` (the
  credential it borrows its secret from — a **GUID**, never a name, because labels are editable)
  / `providerType` (canonical: `openai`, `anthropic`, `gemini`, `grok`) / `baseURL` (blank = the
  type's default) / `defaultModel` / `enabled`, plus the inherited `name` as its editable label.
  It exists so a provider stops being *the same thing as* a key: **one credential can back
  several providers** (two base URLs, two labels), and a provider's identity survives being
  relabelled. Its **GUID is `AIProvider.getID()`**, which is what `AIChat.provider` stores and
  what the registrar is keyed by. The assistant never persists a secret — only this row.
- **`AICapture`** (`NVC_AI_CAPTURE`) — a saved screenshot: `fromArea` / `width` / `height` /
  `numBytes` / `thumbnail` / `image` (png bytes), plus the inherited `name` and
  `creationTime`. The two byte fields are **not the same format**: `image` is the full-size png
  (and `numBytes` counts *it*), while `thumbnail` is a **jpeg** — `GUIUtil.compressImage(image,
  200, DEFAULT_JPG_QUALITY)`, which also flattens alpha to `TYPE_INT_RGB`. Nothing reads either
  by extension (`CaptureSupport.toImage` goes through `ImageIO.read`), so the mismatch is
  harmless, but do not assume "png bytes" when exporting. It sits **outside** the conversation
  model — a capture is not attached to an
  `AIChat` or an `AIMessage`, so sending one to a chat copies the pixels onto the wire and
  leaves no record on the turn. `fromArea` is a **copied string label**, not a reference, so the
  session `io.xlogistx.gui.CaptureArea` it came from can be renamed or deleted without touching
  the row.
  **`image` is the reason reads are projected:** `AssistantStorage.getAllCaptures()` selects
  `thumbnail` but not `image`, so any code that saves a row it got from a list read must
  re-fetch the full row first or `ds.update` writes a null png over the stored one.

Two ids, two scopes: **`correlationID`** joins one request to its response(s) (only meaningful
once sends go async / fan out); **`providerSessionID`** is a *stateful provider's* resume
handle — null for a fresh or stateless chat, minted by the provider on the first response, then
saved on the chat and replayed by `toRequest`. Stateless providers ignore it and get the
flattened history instead. (Nothing captures it off a response yet, so today every chat is
effectively stateless.) The skill text is composed by the provider adapter into the provider's
system field — it rides the `skill` argument, not the DAO.

DAO serialization invariant (guarded by `AIChatRoundTripTest`): `AIMessage` embeds
`AIRequest`/`AIResponse` with `createNVConfigEntity` — a scalar `createNVConfig` compiles but
drops the nested entity on JSON round-trip.

### Two things to know before adding a field or reading a timestamp

- **Adding a param breaks existing stores.** H2P's `ensureTable` is `CREATE TABLE IF NOT
  EXISTS` with no `ALTER TABLE … ADD COLUMN` anywhere, so a table created before a param
  existed never gains its column, while the generated INSERT/UPDATE names it — saves fail
  against the old store. `AISkill.skillType` hit exactly this. Adding a param means deleting
  the dev store (or adding the column by hand); a fresh `@TempDir` store hides the problem in
  tests. A whole **new entity** is fine — `AIProviderConfig` got its own table, which
  `CREATE TABLE IF NOT EXISTS` creates on first use against an existing store. It is only
  *new params on an existing entity* that break.
  > **This is a property of the H2P store, not of this module**, so it governs every
  > `PropertyDAO` the app persists — including `no-sneak-core`'s `ProbeContent` / `ReportContent`
  > (`io.xlogistx.nosneak.v2.data`), which `no-sneak-app`'s `Session` writes to the same store.
  > `ProbeContent` currently has a single `content` param and wants several more; that is cheap
  > only until a `probe_content` table exists somewhere. See `no-sneak-app/CLAUDE.md` → *Scan
  > panel*.
- **None of these DAOs collide with the inherited `PropertyDAO` chain**, and new params must
  keep it that way. The reserved attribute names are `guid` / `subject_guid`
  (`ReferenceIDDAO`), `name` (`SetNameDAO`), `description` (`SetNameDescriptionDAO`),
  `creation_ts` / `last_update_ts` / `last_read_ts` (`TimeStampDAO`), and `canonical_id` /
  `properties` (`PropertyDAO`). `AIChat.getTitle`/`setTitle` and `AIModel.getModelID`
  **delegate** to the inherited `name` rather than declaring a field — keep that pattern.
- **`last_update_ts` does not advance by itself.** The store calls
  `MetaUtil.initTimeStamp(nve)` on both insert and update, but it only writes a value when the
  current one is `0` — so it stamps creation once and never bumps "last updated". Anything that
  wants a real modified time must set it: `AIChat.addMessage` does, and `no-sneak-app`'s
  `AssistantStorage` stamps it on the update branch of `saveChat`/`saveSkill` (the insert branch
  leaves it to the store so creation and update don't land a millisecond apart). `last_read_ts`
  is never set by anything — treat it as unused, not as data.

## Service interfaces (`io.xlogistx.nosneak.ai`)

- **`AIProvider`** (per credential, `extends GetName, GetDescription`) — three send methods, all
  taking the skill text as a **second `String` argument**:

  ```java
  AIResponse send(AIRequest req, String skill) throws AIException;
  void asyncSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback) throws AIException;
  void asyncImageSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback, UByteArrayInputStream... images) throws AIException;
  ```

  `asyncImageSend` is **varargs**, so one message can carry several images. It takes
  **already-encoded bytes**, not `BufferedImage`s: the caller encodes (the assistant does it off
  the EDT inside a `BackgroundTask`, via `SnapShot.exportAsInputStream`), and `AIAPIProvider`
  only forwards the array to `AIAPI.asyncVisionCompletion`, which emits one `image_url` content
  block per image. The media subtype it declares is `AIAPIProvider.IMAGE_TYPE` — a **constant**,
  so every stream handed in must actually be that format (png today); there is no per-image type
  argument. Two consequences of the earlier `BufferedImage` shape are now gone (encoding no
  longer happens on the caller's thread, and an image can be encoded once and re-sent), but the
  rest still holds: there is no image counterpart to the sync `send`, and the images are **not**
  part of the `AIRequest`, so nothing about them is persisted with the turn — the same gap
  `skill` has.

  plus `getModelCatalog()`, `setAPIKey` / `getAPIKey`, `setHTTPAPICaller` /
  `getHTTPAPICaller` (the request goes out through `io.xlogistx.api.ai.AIAPI`, built by
  `AIAPIBuilder`), and **`getID()`**. Note the **asymmetry**: the sync path returns a typed
  `AIResponse`, the async path returns the untyped provider payload. Concrete providers register
  into `io.xlogistx.nosneak.ai.model.AIProviderRegistrar` (`RegistrarMapDefault<String,
  AIProvider>`), now keyed by **`AIProvider::getID`** — the backing `AIProviderConfig`'s GUID,
  **not** `getName()`, since two providers may share a label and a label can be edited after a
  chat is bound to it. The one implementation is `ai-assistant`'s `AIAPIProvider`; both are wired
  there (`asyncSend` delegates straight to `AIAPI.asyncCompletion`). The single-provider path is
  real; only the multi-provider compare (`AIRunner`) remains unimplemented.
- **`AIRunner`** — `send(AIRequest, AIProvider...)` → an `AICallbackCollection` for the
  fan-out (compare). No implementation; note it has **no** skill parameter, unlike `AIProvider`.
- **`AICallbackCollection`** — aggregates a multi-provider run: `size()`, `completed()` /
  `isComplete()`, `responses()`, `errors()`, and `onComplete(Runnable)`. Still typed on
  `AIResponse`, so a fan-out built today would have to decode payloads before aggregating.
- ~~`AICallback`~~ — **deleted.** Callers pass an `org.zoxweb.shared.task.ConsumerCallback<NVGenericMap>`
  directly; it carries both the success (`accept`) and the error (`exception`) path.
- **`AICredentialSource`** — `APIKeys()` (returns `List<APIKey<String>>`, what the Providers
  picker lists), `enabledAPIKeys()`, `setEnabled(key, on)`, and `addAPIKey(...)`, which **returns
  the created key** so the caller can configure a provider against it. It also owns the one
  definition of a key's identity: the **`guidOf(APIKey<?>)` static** (casts to `ReferenceIDDAO`,
  null for an unpersisted key) and the **`getKey(String guid)` default** that resolves the
  credential an `AIProviderConfig` borrows from. Match on GUID, never on name.
  `no-sneak-app`'s `SessionAICredentialSource` implements it.
- **`AIModelCatalog`** — each provider's discovered models (`models()`), `refresh()` (the Refresh
  button), and `lastSynced()` (the "Last sync" line).
- **`AIRepository`** — persistence for chats, skills, provider configs, **and captures**, keyed by
  **GUID** (the `getChat(refID)` / `getSkill(refID)` / `getProviderConfig(guid)` /
  `getCapture(guid)` parameters all take the
  GUID; see the `AIChat` identity note above): `saveChat` / `deleteChat` / `getChat` /
  `getAllChats`, `saveSkill` / `deleteSkill` / `getSkill` / `getAllSkills`,
  `saveProviderConfig` / `deleteProviderConfig` / `getProviderConfig` / `getAllProviderConfigs`,
  and `saveCapture` / `deleteCapture` / `getCapture` / `getAllCaptures`.
  `no-sneak-app`'s `AssistantStorage` implements it against the H2P `APIDataStore` (owner-scoped
  by subjectGUID), branching insert-vs-update on `getGUID()`. **`getAllCaptures` is the one
  projected read** — it omits the `image` column (see `AICapture` above), so it is `getCapture`
  that returns a saveable row.
- **`AIException`** — checked, with a `Kind` (`AUTH`, `RATE_LIMIT`, `CONTEXT_OVERFLOW`,
  `TIMEOUT`, `NETWORK`, `PROVIDER`).

> Skill persistence is now part of `AIRepository` (the earlier standalone `AISkillStore` idea was
> folded in). The `AISkill` DAO carries `name` / `description` / `content` / `skillType` — the
> instruction text is a plain `String`, so markdown is stored as-is; there is still no
> skill-scope/data-access field. Skills are **attached per message, never persisted with the
> chat** (the `AIChat.skills` list was removed) — the UI flattens the selected md skills into
> the `skill` argument at send time, and inserts a prompt skill's text into the composer
> instead.
>
> The UI-side state holder `AssistantContext` lives in the **`ai-assistant`** module
> (`io.xlogistx.nosneak.ai.assistant`), not here — it bundles these injected services plus the
> current chat/credential/model selection. See `ai-assistant/CLAUDE.md`.

## Known gaps the interfaces will force (not yet resolved)

These are shape problems that surface the moment a real provider and the compare UI are built.
Because no implementation exists yet, they are the cheapest to fix now.

- **`asyncSend` leaks the provider wire format into the UI module.** It delivers a raw
  `NVGenericMap`, so every provider's response shape (`choices[].message.content`,
  Anthropic content blocks, Gemini `candidates`, three spellings of the token-usage block,
  three spellings of the truncation reason) has to be parsed by the **caller** — today that is
  `ai-assistant`'s `AssistantMDDecoder`, a UI-module class doing provider-protocol work. The
  sync `send` returns an `AIResponse`, so the two paths disagree about who owns decoding. If
  another `AIProvider` implementation ever appears, that decoder has to move down here (or into
  the provider) or be duplicated. Load-bearing for the compare feature, which needs typed
  responses to aggregate.
- **Compare needs per-provider results.** `AICallbackCollection.responses()` / `errors()` are
  flat `List`s with no provider/model key — the compare view must pair each answer with the
  provider that produced it, so this needs an `agentID`/provider key or a
  `Map<AIProvider, …>` shape. Load-bearing for the compare feature.
- **Fan-out vs. a single `model`.** `AIRunner.send(AIRequest, AIProvider...)` sends one request
  (which carries one `model`) to N providers, but each provider needs its own model id — the
  request-per-provider model still has to be resolved (provider default, or a per-provider
  mapping). `AIRunner` also has no `skill` parameter, so it cannot yet express what
  `AIProvider` already accepts.
- **No cancel handle.** `asyncSend` returns `void`; the Stop button (and aborting the other
  columns) needs a cancel handle/identifier. It is also why there is no timeout — nothing can
  be cancelled once dispatched. Additive, can wait.
- **Skill activation is per-message only.** The per-message path is wired (the assistant's `+`
  popup flattens the checked skills into the `skill` argument), but there is no *chat*-scoped
  activation any more and no place to persist one — `AIChat.skills` was removed and
  `AIRequest` has no `skillsPrompt`, so what was sent with a given turn is not recoverable from
  the stored transcript.
- **Attachments imply rich content.** Job-queue attachments mean `AIRequest.content` (a plain
  `String` today) must eventually carry non-text parts, or attachments get pre-extracted to
  text before the request is built.

---

## Build

- `mvn -q -T1C test` from the repo root builds the whole reactor. Surefire is skipped by the
  parent POM — run tests with `-DskipTests=false -Dmaven.test.skip=false`.
- The test (`AIChatRoundTripTest`) lives in `io.xlogistx.nosneak.ai.model`, the same package as
  the DAOs it exercises.
