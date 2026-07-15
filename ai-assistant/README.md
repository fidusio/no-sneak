# AI Assistant

A reusable Swing AI-assistant module: a headless, vendor-neutral **engine** (`agent`) plus its
**Swing UI** (`gui`). It lets a subject send their own data to a third-party AI and compare answers
across models, using **API keys the host supplies** — it ships **no built-in AI connections**.

It is built to run in two contexts:

- **Inside NoSneak** — models come from API keys the subject stored under
  `Subject account → Credentials` and flagged **"Use for AI assistant"**. NoSneak adapts those keys
  into the module through a narrow port; see [Wiring a host](#wiring-a-host).
- **Standalone / other zoxweb-ecosystem projects** — any project that can produce a list of
  `AICredential` (directly, or by adapting a zoxweb `APIConfigInfo`) can mount the same panel.

The engine depends only on `xlogistx-gui-audio` (shared widget kit — `PanelBuilder`, `CardStack`)
and `zoxweb-core`; it must **never** depend on `no-sneak-app`. Credentials reach the panel through a
narrow port the host implements, so the module graph stays one-directional:
`no-sneak-app → ai-assistant`, never the reverse.

> The `agent` engine is written to be headless and testable without a screen. Today the module is a
> single Maven artifact, so depending on the engine still pulls in the Swing widget kit transitively.
> Splitting `agent` and `gui` into separate `-core` / `-ui` artifacts is a planned follow-up for
> truly headless reuse.

---

## Standardization approach

The module standardizes on **zoxweb's existing SPIs** rather than inventing parallel types, so any
ecosystem project's keys and config drop in without a bespoke adapter:

- **`AICredential extends GetName`** — the narrow read port for one connection
  (`getName()` / `providerType()` / `baseUrl()` / `secret()`).
- **`APIConfigCredential`** — adapts any zoxweb `APIConfigInfo` (+ its secret) to `AICredential`:
  `getName` ↔ `getName`, `providerType` ↔ `getAPITypeName`, `baseUrl` ↔ `getDefaultLocation`.
- **`AICredentialSource`** — the "where do the keys come from" seam. The host implements it; the
  panel only sees `AICredential`s.
- **`NVGenericMap`** is the option/property bag on `AIRequest` — the same bag zoxweb's
  `APIConfigInfo` exposes, not a custom map.

Vendor JSON lives **only** in `agent/impl/*`. Everything above it — the runner, the catalog, the UI —
is vendor-neutral.

---

## Code layout

```
ai-assistant/src/main/java/
├── agent/                         # engine — vendor-neutral, headless
│   ├── AIProvider.java            # SPI: one impl per vendor, resolved by providerType
│   ├── AIProviderRegistry.java    # resolve AIProvider by providerType string
│   ├── AICredential.java          # read port to one endpoint; extends zoxweb GetName; secret() → char[]
│   ├── APIConfigCredential.java   # adapter: zoxweb APIConfigInfo (+secret) → AICredential
│   ├── AICredentialSource.java    # host-supplied source of the AICredential list
│   ├── AIModelCatalog.java        # cached model discovery + refresh + lastSynced, keyed by AICredential
│   ├── AIRunner.java              # fan-out orchestrator ABOVE the SPI (nests RunTarget / Run / RunResult)
│   ├── AIStreamListener.java      # streaming callback for AIProvider.stream
│   ├── AICancelToken.java         # cooperative cancel for streaming runs
│   ├── AIException.java           # carried (not thrown) inside RunResult.Failure
│   ├── model/                     # vendor-neutral DTOs
│   │   ├── AIRequest.java         #   model, systemPrompt, messages, maxTokens, options (NVGenericMap)
│   │   ├── AIResponse.java        #   model, text, AIUsage, latencyMillis, stopReason
│   │   ├── AIMessage.java         #   nests Role + Content (Text / Image / Document)
│   │   ├── AIModel.java           #   id, displayName
│   │   └── AIUsage.java           #   inputTokens, outputTokens
│   └── impl/   (planned)          # AnthropicProvider, OpenAIProvider, OllamaProvider, GeminiProvider
│
└── gui/                           # Swing UI — reuses the io.xlogistx.gui widget kit
    └── AssistantPanel.java        # toggle nav (Chat / History / Skills / Providers) → CardStack detail
                                   #   Providers page lists the AICredentials from the source
```

---

## Engine contracts

### Credential port
```java
public interface AICredential extends GetName {   // getName() from zoxweb GetName
    String providerType();   // anthropic | openai | ollama | gemini — selects the SPI impl
    String baseUrl();
    char[] secret();         // never String
}

public interface AICredentialSource {
    List<AICredential> credentials();
}
```
`APIConfigCredential` is the ready-made adapter from a zoxweb `APIConfigInfo`.

### Provider SPI
One implementation per vendor, resolved by `providerType` via `AIProviderRegistry`:
```java
public interface AIProvider {
    String providerType();
    List<AIModel> listModels(AICredential cred) throws AIException;
    AIResponse send(AICredential cred, AIRequest req) throws AIException;
    void stream(AICredential cred, AIRequest req, AIStreamListener listener, AICancelToken token) throws AIException;
}
```
- `AIRequest` — `model`, `systemPrompt` (skills), `messages`, `maxTokens`, `options` (`NVGenericMap`);
  `withModel(m)` clones it for fan-out so every model gets identical prompt/skills/messages.
- `AIResponse` — `text`, `AIUsage` (in/out tokens), `latencyMillis`, `stopReason` (usage and latency
  are first-class so the compare columns can display them).
- Attachments stay vendor-neutral (`AIMessage.Content`: `Text` / `Image` / `Document`, bytes + MIME +
  name). Each provider adapts them to its own wire format — the queue never knows vendor JSON.

### Fan-out
The multimodel run is an orchestrator **above** the SPI (`AIRunner`), not a provider concern. Its
nested `RunTarget` / `Run` / `RunResult` feed and return from `run`; `RunResult` is a **sealed**
`Success | Failure`, so one model returning 429 can't sink the other columns.

### Model catalog
```java
public interface AIModelCatalog {
    List<AIModel> models(AICredential cred);              // cached
    List<AIModel> refresh(AICredential cred) throws AIException;   // the Refresh button
    Instant lastSynced(AICredential cred);
}
```
Keyed by `AICredential` (not a host-specific GUID string) so it works for any host.

---

## GUI — `AssistantPanel`

Constructed with an `AICredentialSource`. A toggle-button sidebar switches a `CardStack` between
**Chat / History / Skills / Providers**.

- **Providers** — lists the `AICredential`s from the source as `name — provider @ baseUrl`. It never
  renders `secret()`. Empty state points the user at `Subject → Credentials` to add and flag a key.
- **Chat / History / Skills** — placeholders today (see [Not built yet](#not-built-yet)).
- `refresh()` (EDT-safe) rebuilds the provider list; `cleanup()` calls it too so logout clears it.
  The source returns an empty list when the host is signed out, so the host calls `refresh()` on
  login and `cleanup()` on logout.

---

## Wiring a host

A host mounts the panel in two steps:

1. **Implement `AICredentialSource`** over its own key store. In NoSneak this is
   `SessionAICredentialSource` (in `no-sneak-app`), which walks the signed-in subject's API-key
   credentials, keeps the ones flagged for AI use, and adapts each to an `AICredential`
   (`providerType` / `baseUrl` / `secret` read back from the key's properties). Ecosystem projects
   that store `APIConfigInfo` can wrap each in `APIConfigCredential` instead.
2. **Construct and refresh the panel:**
   ```java
   AssistantPanel panel = new AssistantPanel(new SessionAICredentialSource(session));
   // on login:  panel.refresh();
   // on logout: panel.cleanup();
   ```

NoSneak reaches the panel via **View → AI Chat** (the `ASSISTANT` screen), and stores the extra
per-key metadata (`provider`, `base_url`, `ai_provider`) from the *Add / Edit API key* form — see
`no-sneak-app`'s `NOSNEAK-APP.md`.

---

## Invariants

1. No AI endpoint is reachable except through a host-supplied `AICredential`.
2. Model lists are **discovered**, never hardcoded.
3. Every model in a run gets identical prompt text, skills, and attachments.
4. `secret()` is `char[]`, and the UI never displays it.
5. Vendor JSON lives only in `agent/impl/*`; everything above it is vendor-neutral.
6. Nothing leaves the machine that the subject didn't attach.

---

## Not built yet (deliberately deferred)

- **Provider SPI impls** (`agent/impl/*`) — the actual Anthropic/OpenAI/Ollama/Gemini calls.
- **Chat / History / Skills pages** — the Providers page is the only wired one today.
- **Job queue, multimodel compare columns, skills** — designed for but not yet built.
- **Redaction preview** and **cite-the-finding** — prototyped and pulled; `AIMessage` stays a typed
  content list so a redaction step and a `finding-ref` content variant can return additively, above
  the SPI, without touching any vendor impl.
- **`-core` / `-ui` module split** — for headless reuse without the Swing dependency.
