# AI Assistant

A reusable Swing AI-assistant module: a headless, vendor-neutral **engine** (`agent`) plus its
**Swing UI** (`gui`). It lets a subject send their own data to a third-party AI and compare answers
across models, using **API keys the host supplies** — it ships **no built-in AI connections**.

It is built to run in two contexts:

- **Inside NoSneak** — keys come from credentials the subject stored under
  `Subject account → Credentials` and flagged **"Use for AI assistant"**. NoSneak adapts those keys
  into the module through a narrow port; see [Wiring a host](#wiring-a-host).
- **Standalone / other zoxweb-ecosystem projects** — any project that can produce a list of zoxweb
  `APIKey<String>` can mount the same panel.

The module depends only on `xlogistx-gui-audio` (shared widget kit — `PanelBuilder`, `CardStack`)
and `zoxweb-core`; it must **never** depend on `no-sneak-app`. Keys reach the panel through a narrow
port the host implements, so the module graph stays one-directional:
`no-sneak-app → ai-assistant`, never the reverse.

> **Status: interfaces first.** The `agent` layer is currently interfaces + vendor-neutral DTOs with
> **no provider implementations yet**. It compiles and the Providers UI is wired; the actual AI calls,
> async runner, and catalog impls are still to come (see [Not built yet](#not-built-yet)).

> The `agent` engine is written to be headless and testable without a screen. Today the module is a
> single Maven artifact, so depending on the engine still pulls in the Swing widget kit transitively.
> Splitting `agent` and `gui` into separate `-core` / `-ui` artifacts is a planned follow-up.

---

## Standardization approach

The module standardizes on **zoxweb's existing types** rather than inventing parallel ones, so any
ecosystem project's keys drop in without a bespoke adapter:

- **`APIKey<String>`** (zoxweb `org.zoxweb.shared.security.APIKey`, impl `SubjectAPIKey`) is the
  credential currency — it carries the secret (`getAPIKey()`), a name/description, and a properties
  bag (`getProperties()`) that holds the AI metadata (`provider`, `base_url`).
- **`AIException extends org.zoxweb.shared.api.APIException`** — errors are zoxweb `APIException`s.
- **`AIModel extends org.zoxweb.shared.data.SetNameDescriptionDAO`** — a model is a zoxweb meta-DAO
  (typed `Param`/`NVConfig`), not a hand-rolled bean.
- **`AIProviderRegistrar extends org.zoxweb.shared.util.RegistrarMapDefault`** — provider lookup uses
  the house registrar, self-keyed by `AIProvider.getName()`.
- **`NVGenericMap`** is the option/property bag on `AIRequest` — the same bag used across zoxweb.

When provider implementations are written, they will **delegate to the existing xlogistx AI clients**
(`io.xlogistx.api.anthropic.AnthropicAPI`, `io.xlogistx.api.ai.AIAPI` in `xlogistx-apis`) — both are
`org.zoxweb.server.http.HTTPAPICaller`s that already handle the wire format, auth, and rate limiting.
Vendor JSON stays in those clients; everything in `agent` above the provider adapter is vendor-neutral.

---

## Code layout

```
ai-assistant/src/main/java/
├── agent/                          # engine — vendor-neutral, headless
│   ├── AIProvider.java             # SPI: one impl per vendor; send / asyncSend / getModelCatalog
│   ├── AICredentialSource.java     # host-supplied source of the APIKey list (APIKeys())
│   ├── AIModelCatalog.java         # per-provider model cache: models() / refresh() / lastSynced()
│   ├── AIRunner.java               # fan-out ABOVE the SPI: send(req, AIProvider...) → AICallbackCollection
│   ├── AICallback.java             # async result for one call: onResponse / onError
│   ├── AICallbackCollection.java   # aggregate of a fan-out: size / completed / responses / errors / onComplete
│   ├── AIException.java            # extends zoxweb APIException; carries a Kind
│   └── model/                      # vendor-neutral DTOs
│       ├── AIRequest.java          #   model, systemPrompt, messages, correlationID, topicID, maxTokens, options
│       ├── AIResponse.java         #   model, content, correlationID, topicID, tokens, latencyMillis, stopReason
│       ├── AIMessage.java          #   Role (USER / ASSISTANT) + String content
│       ├── AIModel.java            #   SetNameDescriptionDAO; name = model id, Param.MODEL_ID
│       └── AIProviderRegistrar.java#   RegistrarMapDefault<String, AIProvider>, self-keyed by getName()
│
└── gui/                            # Swing UI — reuses the io.xlogistx.gui widget kit
    └── AssistantPanel.java         # toggle nav (Chat / History / Skills / Providers) → CardStack detail
                                    #   Providers page lists the keys from the source
```

There is **no `agent/impl/` package yet** — provider adapters land there (or delegate out to
`xlogistx-apis`) when implementation starts.

---

## Engine contracts

### Credential port
The host supplies keys; the engine never knows where they came from.
```java
public interface AICredentialSource {
    List<APIKey<String>> APIKeys();
}
```
Each `APIKey<String>` carries its secret via `getAPIKey()` and its AI metadata in `getProperties()`
(`"provider"` selects the `AIProvider`; `"base_url"` is the endpoint).

### Provider SPI
One implementation per vendor, resolved by name via `AIProviderRegistrar`:
```java
public interface AIProvider extends GetName, GetDescription {
    AIModelCatalog getModelCatalog() throws AIException;

    void setAPIKey(APIKey<String> key);
    APIKey<String> getAPIKey();

    void setHTTPAPICaller(HTTPAPICaller caller);
    HTTPAPICaller getHTTPAPICaller();

    AIResponse send(AIRequest req) throws AIException;             // sync
    void asyncSend(AIRequest req, AICallback callback) throws AIException;   // async
}
```
- **`AIRequest`** — `model`, `systemPrompt` (active skills, concatenated), `messages`,
  `correlationID` + `topicID` (chat/topic threading), `maxTokens`, `options` (`NVGenericMap` for
  temperature and vendor extras).
- **`AIResponse`** — `model`, `content`, `correlationID` + `topicID` (echoed back), `tokens`,
  `latencyMillis`, `stopReason` — usage and latency are first-class so compare columns can show them.
- **`AIMessage`** — a `Role` (`USER` / `ASSISTANT`) plus `String content` (text-only today).

### Async delivery
```java
public interface AICallback {
    void onResponse(AIResponse response);
    void onError(AIException error);
}
```

### Fan-out
The multimodel run is an orchestrator **above** the SPI, not a provider concern:
```java
public interface AIRunner {
    AICallbackCollection send(AIRequest req, AIProvider... providers);
}
public interface AICallbackCollection {
    int size();
    int completed();
    default boolean isComplete() { return completed() >= size(); }
    List<AIResponse> responses();
    List<AIException> errors();
    void onComplete(Runnable action);
}
```
Results are matched back to the request by `correlationID`; `AIResponse.getModel()` identifies which
provider/model produced each column. One provider failing lands in `errors()`, not the whole run.

### Model catalog
```java
public interface AIModelCatalog {
    List<AIModel> models();               // cached
    List<AIModel> refresh() throws AIException;   // the Refresh button
    Instant lastSynced();
}
```
Per-provider (obtained via `AIProvider.getModelCatalog()`), so it inherits the provider's key.

### Errors
`AIException extends APIException` and carries a `Kind`
(`AUTH`, `RATE_LIMIT`, `CONTEXT_OVERFLOW`, `TIMEOUT`, `NETWORK`, `PROVIDER`) via `kind()`, so callers
can react (retry a transient failure, surface an auth error) without parsing messages.

---

## GUI — `AssistantPanel`

Constructed with an `AICredentialSource`. A toggle-button sidebar switches a `CardStack` between
**Chat / History / Skills / Providers** (a job-queue card exists but isn't navigable yet).

- **Providers** — lists the keys from the source as `name — provider @ base_url`
  (provider/base_url read from each key's `getProperties()`). It never renders the secret. Empty
  state points the user at `Subject → Credentials` to add and flag a key.
- **Chat / History / Skills** — placeholders today (see [Not built yet](#not-built-yet)).
- `refresh()` (EDT-safe) rebuilds the provider list; `cleanup()` calls it too, so logout clears it.
  The source returns an empty list when the host is signed out, so the host calls `refresh()` on
  login and `cleanup()` on logout.

---

## Wiring a host

A host mounts the panel in two steps:

1. **Implement `AICredentialSource`** over its own key store. In NoSneak this is
   `SessionAICredentialSource` (in `no-sneak-app`), which walks the signed-in subject's API-key
   credentials, keeps the ones flagged for AI use (`Session.isAIKey`), and returns them as
   `APIKey<String>` (the `provider` / `base_url` live in each key's properties).
2. **Construct and refresh the panel:**
   ```java
   AssistantPanel panel = new AssistantPanel(new SessionAICredentialSource(session));
   // on login:  panel.refresh();
   // on logout: panel.cleanup();
   ```

NoSneak reaches the panel via **View → AI Chat**, and stores the extra per-key metadata
(`provider`, `base_url`, `ai_provider`) from the *Add / Edit API key* form — see `no-sneak-app`.

---

## Invariants

1. No AI endpoint is reachable except through a host-supplied `APIKey<String>`.
2. Model lists are **discovered**, never hardcoded.
3. Every model in a run gets identical prompt text and skills.
4. The API secret (`getAPIKey()`) is never displayed by the UI.
5. Vendor JSON lives only in the provider adapters (delegating to `xlogistx-apis`); everything above
   is vendor-neutral.
6. Nothing leaves the machine that the subject didn't attach.

---

## Not built yet (deliberately deferred)

- **Provider implementations** — no class implements `AIProvider` yet. The plan: thin adapters that
  delegate to `AnthropicAPI` / `AIAPI` from `xlogistx-apis`, built from the key via
  `HTTPAuthScheme` + `HTTPAPIBuilder`.
- **`AIRunner` / `AICallbackCollection` implementations** — fan-out on zoxweb's `TaskProcessor`.
- **`AIModelCatalog` implementation** — refresh via the provider's MODELS endpoint + cache + `lastSynced`.
- **Registrar population + UI resolution** — nothing registers providers or resolves one from a key yet.
- **Chat / History / Skills pages and the job queue** — the Providers page is the only wired one today.
- **Streaming** — intentionally dropped for now (sync `send` + async `asyncSend` only).
- **`-core` / `-ui` module split** — for headless reuse without the Swing dependency.

Reuse notes for when implementation starts (what to lean on instead of hand-rolling) are captured in
the planning notes for this module.
