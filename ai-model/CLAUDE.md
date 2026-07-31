# NoSneak AI Model (`ai-model`)

The backend **contract** the AI assistant binds to: the value DAOs plus the service
interfaces, with **no provider or store implementations**. `ai-assistant` (the Swing UI) and
`no-sneak-app` (the concrete `AICredentialSource` / `AIRepository`) depend on this module;
it depends on neither. The dependency is one-way: `no-sneak-app → ai-assistant → ai-model`.

Two packages:

- **`io.xlogistx.nosneak.ai.model`** — concrete, JSON-serializable `PropertyDAO`s (the
  conversation model), plus `AIProviderRegistrar`.
- **`io.xlogistx.nosneak.ai`** — the service interfaces (no implementations) and `AIException`.

> **Status.** Interfaces + DAOs only in *this* module. A JSON round-trip test
> (`io.xlogistx.nosneak.ai.model.AIChatRoundTripTest`, 8 tests, green) guards the DAO
> (de)serialization invariants. The concrete implementations all live **outside** this module:
> `ai-assistant`'s **`AIAPIProvider`** (an `AIProvider` + inner `AIModelCatalog`, wrapping
> `io.xlogistx.api.ai.AIAPI` built by `AIAPIBuilder`, resolving provider type from the key's
> `provider` property) and `no-sneak-app`'s **`AssistantStorage`** (an `AIRepository` over
> the app's H2P `APIDataStore`). There is still **no** `AIRunner` implementation (the compare
> fan-out). Providers register into an `AIProviderRegistrar` keyed by `AIProvider::getName`
> (which returns the credential's name).
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
- **`AISkill`** — `content` (the instruction text) is its only declared param; `name` and
  `description` are the inherited `NVEntity` fields.
- **`AIModel`** — `provider` + model id (`getModelID()` / `getName()`), cached by
  `AIModelCatalog`.

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

## Service interfaces (`io.xlogistx.nosneak.ai`)

- **`AIProvider`** (per credential, `extends GetName, GetDescription`) — two send methods, both
  taking the skill text as a **second `String` argument**:

  ```java
  AIResponse send(AIRequest req, String skill) throws AIException;
  void asyncSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback) throws AIException;
  ```

  plus `getModelCatalog()`, `setAPIKey` / `getAPIKey`, and `setHTTPAPICaller` /
  `getHTTPAPICaller` (the request goes out through `io.xlogistx.api.ai.AIAPI`, built by
  `AIAPIBuilder`). Note the **asymmetry**: the sync path returns a typed `AIResponse`, the async
  path returns the untyped provider payload. Concrete providers register into
  `io.xlogistx.nosneak.ai.model.AIProviderRegistrar` (`RegistrarMapDefault<String, AIProvider>`,
  keyed by `AIProvider::getName`). The one implementation is `ai-assistant`'s `AIAPIProvider`;
  both are wired there (`asyncSend` delegates straight to `AIAPI.asyncCompletion`). The
  single-provider path is real; only the multi-provider compare (`AIRunner`) remains
  unimplemented.
- **`AIRunner`** — `send(AIRequest, AIProvider...)` → an `AICallbackCollection` for the
  fan-out (compare). No implementation; note it has **no** skill parameter, unlike `AIProvider`.
- **`AICallbackCollection`** — aggregates a multi-provider run: `size()`, `completed()` /
  `isComplete()`, `responses()`, `errors()`, and `onComplete(Runnable)`. Still typed on
  `AIResponse`, so a fan-out built today would have to decode payloads before aggregating.
- ~~`AICallback`~~ — **deleted.** Callers pass an `org.zoxweb.shared.task.ConsumerCallback<NVGenericMap>`
  directly; it carries both the success (`accept`) and the error (`exception`) path.
- **`AICredentialSource.APIKeys()`** (returns `List<APIKey<String>>`) — the keys the Providers
  picker lists. `no-sneak-app`'s `SessionAICredentialSource` implements it.
- **`AIModelCatalog`** — each key's discovered models (`models()`), `refresh()` (the Refresh
  button), and `lastSynced()` (the "Last sync" line).
- **`AIRepository`** — persistence for **both** chats and skills, keyed by **GUID** (the
  `getChat(refID)` / `getSkill(refID)` parameters take the GUID; see the `AIChat` identity note
  above): `saveChat` / `deleteChat` / `getChat` / `getAllChats`, and
  `saveSkill` / `deleteSkill` / `getSkill` / `getAllSkills`. `no-sneak-app`'s
  `AssistantStorage` implements it against the H2P `APIDataStore` (owner-scoped by subjectGUID),
  branching insert-vs-update on `getGUID()`.
- **`AIException`** — checked, with a `Kind` (`AUTH`, `RATE_LIMIT`, `CONTEXT_OVERFLOW`,
  `TIMEOUT`, `NETWORK`, `PROVIDER`).

> Skill persistence is now part of `AIRepository` (the earlier standalone `AISkillStore` idea was
> folded in). The `AISkill` DAO carries `name` / `description` / `content` — the instruction text
> is a plain `String`, so markdown is stored as-is; there is no skill-scope/data-access field yet.
> Skills are **attached per message, never persisted with the chat** (the `AIChat.skills` list was
> removed) — the UI flattens the selected skills into the `skill` argument at send time.
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
