# NoSneak AI Model (`ai-model`)

The backend **contract** the AI assistant binds to: the value DAOs plus the service
interfaces, with **no provider or store implementations**. `ai-assistant` (the Swing UI) and
`no-sneak-app` (the concrete `AICredentialSource` / `AIChatRepository`) depend on this module;
it depends on neither. The dependency is one-way: `no-sneak-app → ai-assistant → ai-model`.

Two packages:

- **`io.xlogistx.nosneak.ai.model`** — concrete, JSON-serializable `PropertyDAO`s (the
  conversation model), plus `AIProviderRegistrar`.
- **`io.xlogistx.nosneak.ai`** — the service interfaces (no implementations) and `AIException`.

> **Status.** Interfaces + DAOs only. A JSON round-trip test
> (`io.xlogistx.nosneak.ai.model.AIChatRoundTripTest`) guards the DAO (de)serialization
> invariants. There is **no** concrete `AIProvider`, `AIModelCatalog`, or `AIRunner` yet. The
> one real implementation of any interface lives outside this module: `no-sneak-app`'s
> `AssistantStorage` (an `AIChatRepository` over the app's H2P `APIDataStore`). Concrete
> providers are expected to register into an `AIProviderRegistrar` keyed by
> `AIProvider::getName`.

---

## Conversation model (`io.xlogistx.nosneak.ai.model`)

The transcript is **pair-based**, not role-tagged:

```
AIChat  ──has many──▶  AIMessage  ──is──▶  { AIRequest, AIResponse }
```

- **`AIChat`** — one conversation. Holds an ordered list of `AIMessage`, a default `model`, a
  `systemPrompt` (the assistant's persistent identity), and a `providerSessionID`. Its own
  identity is the inherited `referenceID` (what `AIChatRepository` keys on) — **not** a
  hand-rolled id. Helpers: `startTurn(userInput, maxTokens)` (appends a request-only message)
  and `toRequest(userInput, maxTokens)`.
- **`AIMessage`** — one exchange = one provider round-trip: an `AIRequest` plus the
  `AIResponse` it produced. **Roles are implicit in the pair** (request = user side, response =
  assistant side); there is no role field. The response half is null until the provider
  replies. A multi-step/tool turn is several `AIMessage`s in a row, and the "request" side is
  "model input this round" (user text *or* a tool result), not strictly what a human typed.
- **`AIRequest`** — a single outgoing turn: `model`, `skillsPrompt` (skills for *this* call),
  `content`, `maxTokens`, `correlationID`, `providerSessionID`. Per-call tuning can ride the
  inherited `properties` bag.
- **`AIResponse`** — `model`, `content`, `correlationID`, `providerSessionID`, `tokens`,
  `latency`.
- **`AISkill`** — `name` / `description` / `content` (the instruction text prepended for the
  run).
- **`AIModel`** — `provider` + model id (`getModelID()` / `getName()`), cached by
  `AIModelCatalog`.

Two ids, two scopes: **`correlationID`** joins one request to its response(s) (only meaningful
once sends go async / fan out); **`providerSessionID`** is a *stateful provider's* resume
handle — null for a fresh or stateless chat, minted by the provider on the first response, then
saved on the chat and replayed by `toRequest`. Stateless providers ignore it and get the
flattened history instead. System prompt (chat-scoped identity) and `skillsPrompt` (per-request)
are composed by the provider adapter into the provider's system field, not concatenated in the
model.

DAO serialization invariant (guarded by `AIChatRoundTripTest`): `AIMessage` embeds
`AIRequest`/`AIResponse` with `createNVConfigEntity` — a scalar `createNVConfig` compiles but
drops the nested entity on JSON round-trip.

## Service interfaces (`io.xlogistx.nosneak.ai`)

- **`AIProvider`** (per credential, `extends GetName, GetDescription`) — `send(AIRequest)`,
  `asyncSend(AIRequest, AICallback)`, `getModelCatalog()`, plus `setAPIKey` / `getAPIKey` and
  `setHTTPAPICaller` / `getHTTPAPICaller` (the request goes out through zoxweb's
  `HTTPAPICaller`). Concrete providers register into `io.xlogistx.nosneak.ai.model.AIProviderRegistrar`
  (`RegistrarMapDefault<String, AIProvider>`, keyed by `AIProvider::getName`).
- **`AIRunner`** — `send(AIRequest, AIProvider...)` → an `AICallbackCollection` for the
  fan-out (compare).
- **`AICallbackCollection`** — aggregates a multi-provider run: `size()`, `completed()` /
  `isComplete()`, `responses()`, `errors()`, and `onComplete(Runnable)`.
- **`AICallback extends org.zoxweb.shared.task.ConsumerCallback<AIResponse>`** — a single
  callback carrying both the success (response) and the error path.
- **`AICredentialSource.APIKeys()`** (returns `List<APIKey<String>>`) — the keys the Providers
  picker lists. `no-sneak-app`'s `SessionAICredentialSource` implements it.
- **`AIModelCatalog`** — each key's discovered models (`models()`), `refresh()` (the Refresh
  button), and `lastSynced()` (the "Last sync" line).
- **`AIChatRepository`** — chat persistence (`save`, `getChat(refID)`, `getAllChats`,
  `delete(AIChat)`), keyed by the chat's `referenceID`. `no-sneak-app`'s `AssistantStorage`
  implements it against the H2P `APIDataStore`.
- **`AIException`** — checked, with a `Kind` (`AUTH`, `RATE_LIMIT`, `CONTEXT_OVERFLOW`,
  `TIMEOUT`, `NETWORK`, `PROVIDER`).

> Skills persistence (`AISkillStore`) has been **removed for now** — the `AISkill` DAO remains,
> but there is no store interface. It returns when the Skills page is built.
>
> The UI-side state holder `AssistantContext` lives in the **`ai-assistant`** module
> (`io.xlogistx.nosneak.ai.assistant`), not here — it bundles these injected services plus the
> current chat/credential/model selection. See `ai-assistant/CLAUDE.md`.

## Known gaps the interfaces will force (not yet resolved)

These are shape problems that surface the moment a real provider and the compare UI are built.
Because no implementation exists yet, they are the cheapest to fix now.

- **Compare needs per-provider results.** `AICallbackCollection.responses()` / `errors()` are
  flat `List`s with no provider/model key — the compare view must pair each answer with the
  provider that produced it, so this needs an `agentID`/provider key or a
  `Map<AIProvider, …>` shape. Load-bearing for the compare feature.
- **Fan-out vs. a single `model`.** `AIRunner.send(AIRequest, AIProvider...)` sends one request
  (which carries one `model`) to N providers, but each provider needs its own model id — the
  request-per-provider model still has to be resolved (provider default, or a per-provider
  mapping).
- **No cancel handle.** `asyncSend` returns `void`; the Stop button (and aborting the other
  columns) needs a cancel handle/identifier — flagged in the interface's own TODO. Additive,
  can wait.
- **Skills pipeline is unwired.** Nothing yet selects which `AISkill`s a chat uses or assembles
  them into `AIRequest.skillsPrompt`.
- **Attachments imply rich content.** Job-queue attachments mean `AIRequest.content` (a plain
  `String` today) must eventually carry non-text parts, or attachments get pre-extracted to
  text before the request is built.

---

## Build

- `mvn -q -T1C test` from the repo root builds the whole reactor. Surefire is skipped by the
  parent POM — run tests with `-DskipTests=false -Dmaven.test.skip=false`.
- The test (`AIChatRoundTripTest`) lives in `io.xlogistx.nosneak.ai.model`, the same package as
  the DAOs it exercises.
