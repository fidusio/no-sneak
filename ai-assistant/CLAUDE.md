# NoSneak AI Assistant — UI Orientation

A top-level Swing window (`View > AI Assistant`) that lets the subject send their own network
data to third-party AI models and compare answers across them.

The assistant owns **no** API keys and adds **no** AI connections of its own. It reads keys from an
external `AICredentialSource` (the NoSneak credential store) and keeps a list of the ones the subject
has chosen to use.

> **What crosses the trust boundary.** This window is the only outbound path in the product, and
> it is deliberately narrow: the subject picks the provider, the subject supplies the credential
> (the assistant owns none), and **only what the subject attaches** — a message, a capture, a scan
> report — is sent. Scan reports describe the subject's own network, so an accidental attachment or
> a chat left visible across a logout is a data leak, not a UI glitch; session reset
> (`clearProviders` / `resetPanel`) is a data-isolation control. Nothing here sends telemetry, and no code
> path may attach stored data the subject did not choose.

> **Implementation status.** This document is the UI design spec; the pages have drifted from
> it (`AssistantPanel` has **Chat / Capture / Job Queue / Skills / Providers** behind the host's
> sidebar rather than the nav table in §1; Chat History merged into Chat on 2026-10-26, §2 / §4).
> What is wired today:
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
> - **The Providers page is a four-card `CardStack`** (`list` / `add` / `create` / `form`),
>   each card a page in the house list look since 2026-10-26 (§6). The list's toolbar carries
>   **Edit** (`onEditProvider` → the form, pre-filled) and **Remove**
>   (`onRemoveProvider`), which deletes the *config* and only calls `setEnabled(key,false)` when
>   `context.configsUsing(keyGUID) == 0` — `assistant-enabled` is **derived** now, so a stale
>   flag cannot resurrect a provider at the next login. **Add provider** opens the `add`
>   picker, a table of **every** credential the source offers, unfiltered on purpose (a key
>   stays pickable because it can back more than one provider). **Use this key** (or a
>   double-click) opens the same `form` on a new config seeded from the key's metadata;
>   **New key** (`create`) makes a credential first via `AICredentialSource.addAPIKey`, then
>   lands on the form. Saving
>   (`onSaveProviderConfig`) persists the config, enables the key, builds the provider, runs
>   discovery, and registers it. There is no separate provider-type prompt any more — the type
>   is a required field on the form.
> - **Model discovery drives the pickers.** A provider→model helper pair (`fillProviders` /
>   `fillModels` / `bindProviderModels`) populates provider combos from the registrar and model
>   combos from the selected provider's cached catalog (`models()`, never hardcoded). Used by the
>   Chat header and the History create/edit forms. Provider combos carry the provider **id**, not
>   the label — two providers can share a name — and render through `providerRenderer()`;
>   `selectProvider` resolves a legacy provider *name* on an older chat back to an id.
>   `fillModels` filters the catalog through **`ModelFilter`** (root package, Swing-free), which
>   is where the old `PanelSupport.isChatModel` marker list moved.
> - **Model ids are stored and sent as bare names (2026-09-22).** Gemini's OpenAI-compatible
>   `/models` listing returns `models/gemini-2.0-flash` while its chat calls take
>   `gemini-2.0-flash`, so a catalog entry picked in any combo went to the wire with the prefix
>   and failed — the maintainer saw it as "the first selection works, every other one is null".
>   `AIAPIProvider.MODEL_NAME` is a zoxweb `ReplacementFilter("models/", "")`, applied by
>   `modelName(id)` in **two** places: `ModelCatalog.refresh()` strips every discovered id (so
>   combos, the row's model count and the provider's default model all see bare names), and the
>   three send paths (`send` / `asyncSend` / `asyncImageSend`) strip `req.getModel()` again so a
>   chat saved with a prefixed model before the fix still sends. Every other provider's ids carry
>   no prefix and pass through untouched. Pinned by `ModelNameTest` (4).
> - **The conversation's model combo is its own filter (2026-10-28).** The maintainer asked for
>   the model widget and the filter widget to be "one widget like a combo" in the gui-audio
>   package: `ChatPanel.modelSelector` is an `io.xlogistx.gui.FilterComboBox<String>` — an
>   editable combo whose drop-down narrows to what is typed in its editor (the widget's contract
>   is in gui-audio's `CLAUDE.md`). Its `Matcher` is the chat's **`ModelFilter`** grammar: two
>   zoxweb `TokenMatcher`s (case-insensitive) — includes and excludes — over the typed text.
>   Patterns split on comma / semicolon / whitespace; a bare word with no `*` or `?` is expanded
>   to `*word*` so `mini` matches anywhere; a leading `!` sends the rest to the exclude matcher.
>   **Blank means the built-in `NON_CHAT_MODEL_MARKERS` list** (whisper / tts / embedding /
>   moderation / dall-e / …); as soon as one pattern is set the markers **step aside entirely**,
>   which is the only way to reach an audio or embedding model on purpose (`*` lists everything
>   the provider discovered). Excludes win over includes; an exclude-only filter keeps everything
>   else. The filter has **no state of its own**: it is the editor text while the popup is open,
>   gone once an item is picked, Escape is pressed or the list is refilled, so there is nothing on
>   `AssistantContext` any more (`getModelFilter` / `setModelFilter` and the `"modelFilter"`
>   event were removed the same day). The combo holds **every** discovered model
>   (`fillModels(ctx, box, ref, m -> true)`, `ChatPanel.ALL_MODELS`) and the matcher decides what
>   shows; `setFreeText(true)` keeps a typed name the list does not offer, so a bound chat never
>   has its model silently rewritten. The three-arg `fillModels(ctx, box, ref)` is the chat
>   models only (`ModelFilter.isChatModel`) and is what the History forms' and the Providers
>   form's plain editable combos use. Before this the filter was a separate `Filter models`
>   search field beside a plain combo, session-scoped on the context.
> - **List rows are label + sublabel, and search covers both.** The shared `ListSection` grew
>   `.description(...)` (a wrapping blurb under the panel title) and `.sublabel(...)` (a muted
>   second line per row). The rule here: the **label is the searchable identity**, the sublabel
>   carries the metadata. (Chat History, Skills and Providers left `ListSection` for tables on
>   2026-10-26, §4 / §5 / §6; the Providers table's columns are what its sublabel used to say —
>   `type · baseURL · default model · N models · last sync` — and the key picker's are
>   `provider · baseURL · used by N providers`.) `ListSection.filter()` matches label **or**
>   sublabel, so moving metadata off the label does not drop it out of search.
> - **The list of chats has create / edit / delete + persistence** (the Chat page's list since
>   the merge of 2026-10-26; the Chat History page before). `ChatHistoryPanel.buildHistoryCards`
>   is a nested `CardStack` (`list` / `editor` / `creator`). **New chat** opens the Create form
>   (name + provider + model), the toolbar's Edit opens a pre-filled Edit form (both persist via
>   `context.saveChat`), and Delete calls `context.deleteChat` after a confirm. The list is a
>   table on `ChatHistoryModel` over `context.getAllChats()` (→ `AIRepository.getAllChats()`),
>   refreshed by the public EDT-safe `refreshHistory()`, which `no-sneak-app` calls on both login
>   and logout (§4, since 2026-10-26).
> - **Skills have create / edit / delete + persistence, and are typed.** `buildSkillCards` is a
> nested `CardStack` of exactly two cards (`list` / `editor`). The list source is
> `context.getAllSkills()` (→ `AIRepository.getAllSkills()`), refreshed by `refreshSkills()`.
> **The editor card *is* an `MDEditorPanel`** — one instance reused for both create and edit,
> carrying name / description / **type** (`AISkill.SkillType`) / instructions in a single form;
> remove calls `context.deleteSkill`; all saves run off the EDT via `BackgroundTask.runCatching`.
> `AISkill.content` is the instruction text — a plain `String`, so a skill authored in markdown
> is stored verbatim. There is no separate page form and no modal dialog any more: the viewer's
> own Save is the single persistence point. See §5 and §5.1. The editor also takes a
> `setValidator(Predicate<MDDocument>)` — `validateSkill` rejects a blank name **before**
> `onSaveSkill` runs, but only when the selected type is a `SkillType`: a registered save target
> (the app's "probe") validates its own content, so the skill-worded name check no longer blocks
> it (finding 10) — and `onSaveSkill` snapshots the old field values so a failed store write
> rolls the cached `AISkill` back and re-marks the editor dirty. The editor itself now re-marks
> dirty when a commit handler *throws* (finding 8), so a target that refuses the document can
> never leave a rejected draft reading as saved.
> - **An assistant reply can become a skill.** `AssistantUtil.chatBubble(...)` takes an optional
>   `onSaveAsSkill` `Runnable`, rendered as a borderless "Save as skill" button beside the
>   latency/token line (assistant bubbles only, never the user's). It routes to
>   `onSaveSkillFromResponse`, which confirms first if the editor holds unsaved edits, then opens
>   the skill editor seeded with that response. Guarded by `ChatBubbleSaveAsSkillTest`.
> - **A past prompt can be sent again (2026-10-27).** Every user bubble on the conversation page
>   carries one white copy icon at its bottom-right (`IconUtil.CopyIcon(16, Color.WHITE)`,
>   component name `AssistantUtil.REUSE_PROMPT`, tooltip *Put this prompt back in the composer
>   to send it again*). The nine-argument `chatBubble` takes the `onReuse` `Runnable`;
>   `ChatPanel.addMessage` passes `() -> insertIntoComposer(text)` for user bubbles and null for
>   replies, so the prompt lands in the composer the same way a skill or another screen's
>   `setComposerText` does: replacing a blank composer, otherwise appended at the caret, caret at
>   the end, focus on the composer. Nothing is sent until the subject presses Send. The action
>   row is the only one a user bubble gets (right-aligned, no detail line, no Copy / PDF
>   buttons, which stay assistant-only). Guarded by `ChatBubbleReuseTest`.
>   **Or a host record, in one click (2026-10-26):** the seven-argument `chatBubble` also takes a
>   `Map<String, Runnable>` of the host's save targets and renders one borderless
>   "Save as <label>" button per entry after *Save as skill*. `ChatPanel.addSaveTarget(label,
>   handler)` keeps the targets and `addMessage` builds the runnables: `handler.accept("",
>   markdown)`, with a `RuntimeException` from the handler shown under "Not a valid <label>" and
>   nothing else done. The app registers "probe", so a reply that is a probe definition goes
>   straight into the probe library (the skill editor's "Save as" combo still offers it too).
> - **An assistant reply can be shown as a PDF (2026-09-23).** The PDF-icon button (`IconUtil.PDFIcon`, 2026-10-07; a plain file icon before) beside
>   *Copy* on every assistant bubble runs `AssistantUtil.showAsPDF`: the bubble's markdown goes
>   through the toolkit's `io.xlogistx.gui.MDToPDF` (commonmark with the same GFM extensions as
>   the viewer, OpenHTMLtoPDF over PDFBox, Roboto embedded) **off the EDT** via `BackgroundTask`
>   — the button is disabled while it renders and a failure lands in `BackgroundTask`'s own error
>   dialog — and the bytes open in an `io.xlogistx.gui.pdf.PDFViewerPanel` (the `pdf` package since the 2026-10-28 gui-audio move) inside a modeless
>   `JDialog` (900 × 940, toolbar on; closing asks the viewer's `confirmDiscard()` when it has
>   unsaved edits, disposal → `viewer.close()`). The viewer's **Aa text size spinner is scoped
>   to the viewer** (gui-audio 2026-10-23, `FontSizeWidget(Component scope)` — the default for
>   a `PDFViewerPanel`): turning it resizes the dialog's controls only, never no-sneak's, and a
>   no-sneak text size change does not reach the dialog; it used to drive the whole application.
>   **Page editing is the toolkit's, not ours:** the
>   viewer's toolbar carries *Insert* and *Delete* (pages: current, list or range; added to
>   `PDFViewerPanel` in `io-xlogistx/gui-audio` on 2026-09-23 — a first cut of the deletion
>   lived here as `ResponsePDFDialog` for an hour and was moved), plus *Save* and *Print*, so
>   the trimmed document is the export; nothing is written unless the subject asks.
>   The PDF libraries arrive transitively through `xlogistx-gui-audio`
>   (`openhtmltopdf-pdfbox`, `pdfbox` 3.0.x, `graphics2d`, `xmpbox`, `jsoup`); a hand-built test
>   classpath must pin **one** pdfbox version or `fontbox` throws `NoSuchMethodError`. And when the toolkit jar is reinstalled with new transitives, **reload the Maven projects in IntelliJ** — its imported module libraries do not follow the local repository on their own, and the app then dies with `NoClassDefFoundError: com/openhtmltopdf/pdfboxout/PdfRendererBuilder` while `mvn` resolves everything (seen 2026-09-23).
> - **The whole chat can be shown as a PDF (2026-10-07).** A red `IconUtil.PDFIcon` button at the
>   end of the chat header (after *New Chat*) runs `ChatPanel.showChatAsPDF`: `chatToMarkdown`
>   folds every stored turn into one markdown document — `# title`, an italic provider · model
>   line, then per message a `---` rule, `### You` with the request text, every image attachment
>   inline (the capture's PNG read back from the store, embedded as a `data:` URI; MDToPDF scales it
>   to the text width — this is why the markdown is built on the background worker, through the
>   `Callable` overload of `showAsPDF`) and, for every text source, **its content** under a
>   bold `Attached: <name>` line with the muted `type · origin · size` (a JSON report in a
>   ```` ```json ```` fence via `sourceMarkdown`; until 2026-10-23 only the names were listed —
>   a sent attachment is part of the chat, so the PDF carries it), and `### Assistant · model`
>   with the response —
>   and hands it to the same `AssistantUtil.showAsPDF(owner, title, markdown)` the bubble button
>   uses (now public, with the dialog title as a parameter; the dialog carries PDF window icons).
>   No chat or an empty chat gets an information dialog instead.
> - **The code in a reply can be auto-copied (2026-10-07).** The chat header carries an
>   **`Auto-copy code`** checkbox (after *Send history*, default off, reset to off at logout like
>   the rest of the session view state). While it is ticked, every reply that lands in the
>   transcript has its **fenced code blocks** put on the system clipboard — `ChatPanel.copyCode`
>   runs from the send callback's EDT half, right after `addMessage`, and sets a `StringSelection`
>   of `codeToCopy(response)`: the blocks from `AssistantMDDecoder.codeBlocks(markdown)` joined by
>   a blank line, fence lines dropped and the fence's indentation stripped. A reply with no fenced
>   block leaves the clipboard untouched (so the last copied code survives a prose answer), and a
>   clipboard held by another application (`IllegalStateException`) is swallowed — the bubble's
>   own *Copy* button is still there. `codeBlocks` uses the decoder's `Fence` grammar: backtick
>   fences of three or more, closed by a bare fence at least as long as the opener (so a ````md`
>   wrapper's inner ```` ```java ```` block stays inside it), an unclosed block runs to the end,
>   inline code spans are not blocks. Pinned by `CodeBlocksTest` (5). Re-rendering an old chat
>   (`refreshPrompt`) does **not** copy — only a reply arriving from the wire does.
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
>   arrives after the clear has already run, so a retry does **not** re-send them. The popup has
>   two further sections below the skills — **Images for this message** and **Capture** (both
>   below); job-queue items are meant to join them. The chat
>   header also carries the **`Send history`** checkbox (default on; reset to on at logout) —
>   unchecked sends only the new message with no conversation context. Checked, every earlier
>   turn's **text attachments go with its `Human:` line** as `SourceSupport.block(textSourcesOf(req))`
>   (2026-10-23): a scan report sent two turns ago is still in front of the model. The current
>   turn's sources are not repeated there — they travel in the source block appended to the
>   skill text, as before.
> - **A message can carry several images, and the popup is where they live.** `ChatPanel` holds
>   two index-parallel lists — `pendingImages` (`BufferedImage`) and `pendingImageNames` — and
>   every attach path funnels through the public **`attachImage(image, name)`**, which
>   **appends** (it used to replace). The popup's *Images for this message* section renders one
>   **checkbox per pending image** (`imageRow(image, name)`, checked, tooltip = pixel
>   dimensions); unchecking removes it from both lists by `indexOf(image)` — **never by a
>   captured index**, or every row below the one you untick points at the wrong slot. Below the
>   rows sits `attachImageRow`, the file picker (`chooseImage`, multi-select on). The three
>   attach paths are the picker, the popup's *Capture* section, and `CapturePanel`'s
>   send-to-chat arrow (→ `AssistantPanel` → `attachImage`). On send, `onSend` **snapshots**
>   (`new ArrayList<>(pendingImages)` — the field is cleared before the callback returns) and,
>   when the snapshot or the ticked areas are non-empty, encodes everything **off the EDT** and
>   dispatches `asyncImageSend(wire, skill, callback, UByteArrayInputStream...)`, falling back to
>   plain `asyncSend` only when both are empty. The wire supports this end to end:
>   `AIProvider.asyncImageSend` is varargs over **already-encoded** streams (encoding moved out
>   of `AIAPIProvider`, which now only forwards them with the constant `IMAGE_TYPE` = `png`), and
>   `AIAPIBuilder.toVisionParams` emits a plural `images` array that the COMPLETION encoder turns
>   into one `image_url` content block per image. All four `AIAPIType` base URLs are
>   OpenAI-compatible surfaces (Gemini via `/v1beta/openai`, Anthropic via its compat layer), so
>   the single unbranched encoder is portable — a **custom base URL pointing at a native
>   `/v1/messages` would not be**.
> - **Capture areas are ticked in the composer and shot at send time.** The popup's *Capture*
>   section carries `defineAreaRow` ("Capture area...", a fresh drag that **adds** a
>   `CaptureArea` to the shared `CaptureAreaSet` — auto-named `Area N`, description = display,
>   ticked on creation — nothing is shot at that point) and `areaSection`: an **All areas**
>   check-all above one row per area in a bounded scroll pane (`AREA_LIST_MAX_HEIGHT`), each
>   row a tick box (tooltip = `areaSublabel`) plus an ✕ that removes the area from the set.
>   Ticks live in `ChatPanel.tickedAreas` (an identity set — view state, not on the area) and
>   **survive the send**: the same areas go out with every message until unticked; `reset()`
>   clears them. Nothing captures before Send: `onSend` intersects the ticks with the live set
>   (`areasToSend()`) and, when areas or pending images exist, moves dispatch into a
>   `BackgroundTask` — `CaptureSupport.shootAndSave` does one hide/sweep
>   (`CaptureAreaSet.takeSnapShots(areas)`)/save-each/restore cycle, the pending images and
>   snapshots are PNG-encoded **off the EDT** into `UByteArrayInputStream`s, and
>   `asyncImageSend` fires from the background thread; the success callback adds the shots to
>   the transcript, the failure path funnels through `failSend` (same undo as a sync throw).
>   Every shot still lands in the store via `ctx.saveCapture`, so it is recoverable on the
>   Capture page. The old instant-capture path (`capture`/`shootArea`/`onCaptureButton`/
>   `defaultArea`, the commented-out composer camera button, `CaptureSupport.shoot`) is
>   **deleted**.
> - **The Capture page is built** (`panels/CapturePanel`; re-laid out 2026-10-26 in the house
>   list look, after Chat History): a `PagePanel` head (title from `Page.CAPTURE`, the two
>   actions **Define area** and the primary **Capture (N)**; N = all defined areas, disabled at
>   0) over two columns split 38/62. *Areas* (left) is a toolbar (count, **Rename / Redraw /
>   Remove** on the selected row) over a `Tables.style`d table on **`CaptureAreaModel`** —
>   Area · Display · Region — of the **session-scoped** `io.xlogistx.gui.CaptureArea`s (held in
>   `AssistantContext`'s `CaptureAreaSet`, never persisted, cleared by `resetContext()`); the
>   name is edited **in place** in the Area column (`setValueAt`, a blank keeps the old name;
>   Define area lands in that editor with the default name selected), Redraw re-runs the overlay
>   keeping name/identity. *Captures* (right) is a toolbar (count, **Open / Send to chat /
>   Rename / Delete** on the selected row, **Delete all**) over a table on
>   **`CaptureTableModel`** — thumbnail (62 px rows, the camera glyph when a row has none) ·
>   Capture · Area · Size · Bytes · Taken, newest first; double-click opens. Open replaces the
>   whole page with a **preview page** (`PagePanel`: the name, `area · WxH · KB · taken <ts>`,
>   **Back** and the primary **Send to chat**, the image in the card). Both models are pure
>   (`CaptureModelsTest`). `fromArea` is a **copied string label**, so deleting the area leaves
>   captures intact. Capture (N) runs `CaptureSupport.shootAndSave` — the same sweep the chat
>   send path uses: one hide/settle/restore cycle around a single
>   `CaptureAreaSet.takeSnapShots` sweep (one cached `Robot`; unset or empty rectangles are
>   silently skipped per the library contract, and the panel warns "N of M areas could not be
>   captured" when the snapshot count comes up short), saves each via `ctx.saveCapture`, and
>   reloads the Captures table; there is **no job queue integration by
>   design** (deferred with the queue itself). Selection runs through
>   `panels/RegionOverlay.select()` — **multi-monitor**: one undecorated always-on-top `JWindow`
>   per `GraphicsDevice` (translucency with per-pixel → opacity → solid fallback), rubber-band
>   drag in virtual-screen coordinates spanning monitors, Esc cancels via a global
>   `KeyEventDispatcher`, teardown in a `finally`. It **blocks and must not run on the EDT**
>   (guarded; all call sites go through `BackgroundTask`), replacing the primary-display-only
>   `GUIUtil.captureSelectedArea()` drag. **The projected-read invariant is load-bearing:**
>   `AssistantStorage.getAllCaptures()` selects thumbnail but **not** `image`, so rows render
>   thumbnails cheaply, and any send/view/rename must re-fetch via `full()`
>   (`ctx.getCapture(guid)`) first — saving a row instance would null the stored png. **`full()`
>   itself is not yet safe for that:** when `ctx.getCapture` misses it falls back to the
>   projected row, so `onRenameCapture` can write an image-less row straight back over the
>   stored one (see the rough edges). The
>   panel is **not** wrapped in an outer `JScrollPane` (the two tables scroll themselves and
>   need a bounded viewport). There is no search box on either table: the areas are
>   session-sized and the captures toolbar has no room for one at 1280 px wide. Note macOS
>   needs Screen Recording permission for
>   `Robot.createScreenCapture` — without it captures come back blank with no exception.
> - **The module has two outward hooks, and they are the whole coupling to the scanner.**
>   **`AssistantPanel.sendToChat(text, name)`** attaches plain text as a pending `AISource`
>   (rendered in full as the last transcript entry, with a Delete button until it is sent, 2026-10-22) and
>   flips to the Chat card — `no-sneak-app` hands it to `ScanPanel` so a scan report can be sent
>   into a conversation. It throws a `SecurityException` (message shown by the caller) when there
>   is no current chat, since an attachment with nowhere to land is silently lost otherwise.
>   **`sendToChat(text, name, composerText)`** (2026-10-26) does the same and types
>   `composerText` into the composer (`ChatPanel.setComposerText`, the public face of
>   `insertIntoComposer`: appended at the caret when something is already typed) so the subject
>   only has to press Send; the Probe library attaches `PROBE-DEFINITION.md` and asks for a
>   probe this way.
>   **`AssistantPanel.addSaveTarget(label, BiConsumer<String,String>)`** registers an extra
>   destination in the skill editor's **"Save as"** combo **and** a "Save as <label>" button on
>   every assistant reply (2026-10-26, above); the app registers `"probe"` there, so a
>   response can be saved into the probe store instead of the skill store (§5). The handler takes
>   `(name, content)` rather than an `MDDocument` deliberately: the host never references this
>   module's editor types, and this module never learns what a probe is — it has no view of
>   `no-sneak-core` and could not validate one anyway.
> - **A message is persisted before dispatch.** `onSend` saves the chat right after
>   `chat.addMessage(msg)`, not only from the response callback, so a turn that is never answered
>   (provider down, logout while in flight) survives. `failSend` still *removes* the message on a
>   provider error and re-saves — see the rough edges.
> - **Session reset is wired.** On logout `no-sneak-app` calls `clearProviders()` (wipes the
> registrar) + `resetPanel()` → `context.resetContext()` (nulls `currentChat` / credential /
> model, clears the chat + skill caches, fires `currentChat` so the transcript clears) and
> blanks the composer / resets the card stacks. On app close, `NoSneakMain` closes the datastore in a
> `windowClosing` handler.
>
> **Still target-only / stubbed:** the multi-model **compare** path (no `AIRunner`; single-provider
> `asyncSend` is wired); **chat-scoped skill activation** (per-*message* attachment works, but
> nothing marks a skill active for a whole conversation — `AIChat`'s skills list was removed from
> the DAO, so there is nowhere to persist it); the **Job queue** page (`onAddJob` / `onEditJob` /
> `onRemoveJob` are all empty bodies and the list binds to `ArrayList::new` with a `_ -> ""`
> label — there is nothing there to test); per-row provider **Refresh**; and a skill's
> **data-access scope** (no DAO field).
> `AICredentialSource` and `AIRepository` come from `no-sneak-app` (`SessionAICredentialSource`,
> `AssistantStorage` over the H2P `APIDataStore`); the DAOs and interfaces live in **`ai-model`**
> — see its CLAUDE.md. `no-sneak-app` builds
> `AssistantContext(SessionAICredentialSource, AssistantStorage(session))` and passes it to
> `AssistantPanel` on its `ASSISTANT` screen. The dependency is one-way
> (`no-sneak-app → ai-assistant → ai-model`).
>
> **Every row added to the transcript must be width-capped.** The transcript is a `MigLayout`
> panel inside a `JScrollPane` with `HORIZONTAL_SCROLLBAR_NEVER`. Bubbles carry
> `wmin 0, wmax 60%` (user, trailing) or `growx, wmin 0, wmax 92%` (assistant, leading); the
> attachment rows — image thumbnails through the shared `ATTACHMENT_CONSTRAINT`, text sources
> (`sourceView`, 2026-10-22) through `SOURCE_VIEW_CONSTRAINT` — are capped for the same reason. An **uncapped** row sizes to its content, which
> sets the panel's preferred width past the viewport; because chips and user bubbles are
> `alignx trailing`, they are then positioned off-screen with no horizontal scrollbar to reach
> them, and the only way to see them is to widen the window. Measured: a 1400px chip against a
> 597px viewport pushed the user's bubble 817px out of view. The `wmin 0` matters too — MigLayout
> will not shrink a component below its reported minimum, and a `JEditorPane` reports the width of
> its widest unbreakable content. A source view's header shows the name in bold, no icon (the
> chips it replaced carried a PDF icon; dropped by request 2026-10-22); the name is ellipsized at 48 chars with
> the full name in the tooltip, since `wmax` alone clips mid-word with no indication anything
> was cut, and the body is a `JScrollPane` around the viewer's editor pane, which reports a small
> minimum width however wide the JSON inside is.
> Callers should keep attachment names short for the same reason — `ScanPanel` sends a scan's
> targets, not its full command line.
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
> - **`maxTokens` is hardcoded to 1024** in `onSend`, is not surfaced anywhere in the UI, and
>   **never reaches the wire anyway**: the `max_tokens` build is commented out of `xlog-api-ai`'s
>   COMPLETION encoder (`AIAPIBuilder.buildCompletionEndPoint`, ~line 293 of the 1.0.0 sources —
>   the only live one is in the text-to-speech endpoint), so text and vision sends both run at
>   the provider's default. Do not reach for the 1024 to explain a truncated answer until that
>   is fixed upstream.
> - ~~**`CaptureSupport.shootAndSave` can leave the window hidden.**~~ **Fixed** (verified
>   2026-10-26): the sweep runs inside `try { takeSnapShots } finally { restoreWindow }` and the
>   encode + save loop comes after it, so the window is back before anything is written and a
>   failed save cannot hide the assistant. A failed save still aborts the rest of the batch.
> - **A failed send loses the attached images — now on every path.** `clearPendingImages()` runs
>   right after dispatch and `failSend` restores only the composer text, so a capture that cost a
>   drag-select is gone and the retry sends text alone. This used to be async-only; the image
>   path is now entirely inside a `BackgroundTask`, so its synchronous-throw escape hatch is
>   gone too. (Ticked **areas** survive, because the ticks are not cleared on send — only the
>   already-shot pixels are lost.) Same hole as `pendingSkills`.
> - **Wire images are full-resolution png.** `CaptureSupport.toStream` / `IMAGE_FORMAT` pin
>   `"png"`, so a 4K area goes out at 4K — several MB per image, and providers downscale it
>   anyway. `SnapShot.exportAsInputStream("jpg")` would cap the long edge at
>   `GUIUtil.AI_IMAGE_MAX_DIMENSION` (1536) at `DEFAULT_JPG_QUALITY`; switching means changing
>   `AIAPIProvider.IMAGE_TYPE` with it, since the media subtype it declares is a constant.
> - **Auto-named areas collide.** Both `defineAreaRow` (chat) and `onDefineArea` (capture page)
>   name a new area `Area <count + 1>`, so removing an area and adding another reuses a name.
>   The name is the `SnapShot.sourceID` and therefore the `AICapture.fromArea` label, so two
>   different rectangles can produce indistinguishable capture rows.
> - **An all-skipped sweep still sends a vision request.** `takeSnapShots` silently drops areas
>   whose rectangle is unset or empty; if every ticked area drops and no images are attached,
>   `onSend` still calls `asyncImageSend` with a zero-length array instead of falling back to
>   `asyncSend`. Not reachable today (`select()` only returns usable rectangles), but the guard
>   is one `streams.length == 0` check.
> - **Send-time capture thumbnails can land after the reply.** The shots are appended to the
>   transcript from `BackgroundTask`'s done-callback while `asyncImageSend` is already in flight,
>   so a fast provider's answer can be rendered first and the images appear below it.
> - **The popup's *All areas* box reads ticked when the list is empty.** Removing the last row
>   re-evaluates it as `rowBoxes.stream().allMatch(...)` over an empty list, which is `true`.
>   Cosmetic only — the popup is rebuilt on each open.
> - **`CapturePanel.full()` falls back to the projected row.** When `ctx.getCapture(guid)` misses
>   — signed out, or the row was deleted elsewhere — `full()` returns the image-less projected
>   instance, and `onRenameCapture` saves it, so `ds.update` writes a null `image` over the
>   stored png. Exactly what the method's own javadoc says must never happen. The read paths
>   (view, send-to-chat) are safe; only the save path needs to bail instead.
> - ~~**`previewed == capture` breaks across a refresh.**~~ **Moot since 2026-10-26:** the
>   preview is a page of its own and the list's Rename / Delete are not reachable while it is
>   open; the panel keeps no `previewed` field. (`getAllCaptures()` still hands out fresh
>   instances per read; `refreshCaptures()` keeps the selection by GUID.)
> - **Multi-file attach order is nondeterministic.** `chooseImage` fires one `BackgroundTask` per
>   selected file and `SwingWorker.done()` order is not submission order, so "compare the first
>   with the second" depends on which decode finished first. Read them in one task.
> - **Latency is measured from callback construction**, i.e. it includes queueing in the API
>   executor, not just the wire time. `tokens` *is* populated now (from the payload's usage
>   block), but reads `0` for any provider that omits one.
> - **The transcript re-renders in full on every `currentChat` change** (`refreshPrompt` clears
>   and rebuilds every bubble). Fine at current lengths; it is an `MDViewerPanel` per message.
> - **`addMessage` always scrolls to the bottom** (`v.setValue(v.getMaximum())`). When a reply is
>   taller than the viewport — routine once a scan report is attached — that lands past the end of
>   the answer with the request scrolled off the top. Scrolling to the *top* of the new bubble
>   would show where the answer begins with the request just above it.
> - ~~**`AssistantUtil`'s convert-to-PDF button has no action listener**~~ — wired 2026-09-23,
>   see the *response as PDF* bullet in the status block above.
> - **A provider whose discovery failed still registers**, with an empty catalog — so sends
>   against it fail, and `failSend` then removes the message (below). `reloadProviders` no longer
>   swallows the reason: it collects a line per failure — a refresh exception, a `keyGUID` that no
>   longer resolves, an unrecognized provider type — into a list **local to that pass** and shows
>   them **once from the done-callback**, on the EDT. Building the dialog inside the `Callable`
>   would put Swing on the worker thread and block discovery mid-loop behind a modal.
>   `reloadProviders` hops to the EDT if called elsewhere (login fires it from the login worker)
>   and stamps each pass with a generation number; a pass that finishes after a newer one started
>   applies nothing, so overlapping reloads can no longer wipe each other's issues, show the wrong
>   pass's dialog, or race a shared list into an exception that left the subject with zero
>   providers (finding 7). `onSaveProviderConfig` still
>   swallows its own refresh exception. §6's per-row "401, key rejected" chip is still design
>   intent; dropping a provider on a failed refresh is deliberately *not* done, because a
>   transient blip at login would unlink a working key until the next reload.
> - **`failSend` removes the user's message.** Any provider error pulls the unanswered `AIMessage`
>   back out of the chat, re-saves, and re-renders — so a broken key reads to the subject as
>   "my messages disappear". It restores the composer text only if the composer is still blank, so
>   typing while a send is in flight loses the original. Arguably correct (it undoes a failed
>   turn), but it is the visible half of the bullet above.
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

The root package `io.xlogistx.nosneak.ai.assistant` plus a `panels` sub-package — the pages were
split out of `AssistantPanel`, which is now just wiring:

| Class | What it is |
|---|---|
| `AssistantPanel` | Wiring only: builds the six page panels, the sidebar, and the top-level `CardStack` |
| `AssistantContext` | Swing-free state holder: injected services + current selection + caches + the session `CaptureAreaSet` |
| `ModelFilter` | The model-filter grammar: two `TokenMatcher`s (include / `!`exclude) over a typed pattern list, falling back to the built-in non-chat markers; the conversation combo's `Matcher` since 2026-10-28, no session state |
| `AIAPIProvider` | The `AIProvider` implementation over `io.xlogistx.api.ai.AIAPI` (+ inner `ModelCatalog`) |
| `AssistantCallback` | `ConsumerCallback<NVGenericMap>` — payload → `AIResponse` (stamped with the model and, since 2026-10-27, the provider id the request went to), persist, hop to the EDT |
| `AssistantMDDecoder` | Provider payload → renderable markdown (see §10.1) |
| `AssistantUtil` | `chatBubble(...)` — a rounded bubble around an `io.xlogistx.gui.MDViewerPanel` |
| `io.xlogistx.gui.MDEditorPanel` | Split markdown editor: editor left, live `MDViewerPanel` preview right (see §5.1). **Lives in `io-xlogistx/gui-audio` since 2026-10-22**; only its test stays here |
| `panels/ChatPanel` | The Chat page (merged with Chat History 2026-10-26): two cards — the list of chats (`ChatHistoryPanel`) and the conversation page (`PagePanel` titled by the chat, re-framed by `showConversation()`): head actions, options row (the provider combo — the provider switch of 2026-10-27 — and the filterable model combo, a gui-audio `FilterComboBox` since 2026-10-28, Send history, Auto-copy code), transcript over the composer; `+` popup (skills / images / capture), `onSend`, `attachText`; `showCurrent()` is what the sidebar lands on |
| `panels/ChatHistoryPanel` | The list of chats, the Chat page's `list` card: `PagePanel` head (title from `Page.CHAT`, the primary New chat), toolbar, table on `ChatHistoryModel`, plus the New chat / Edit chat form cards (house list look since 2026-10-26); `editChat`, `startNewChat`, `setOnFormClosed` |
| `panels/ChatHistoryModel` | The chat list's rows (title, provider, model, messages, created, updated) and the conversation's `facts` line; pure, `ChatHistoryModelTest` |
| `panels/SkillsPanel` | The Skills page: `PagePanel` head (New skill), toolbar, table on `SkillsTableModel`, and the one `MDEditorPanel` framed as a New skill / Edit skill page (house list look since 2026-10-26) |
| `panels/SkillsTableModel` | The Skills table's rows (name, type, description, updated); pure, `SkillsTableModelTest` |
| `panels/ProvidersPanel` | The four-page Providers card stack: the table page, the key picker page, the new-key form, the provider form (house list look since 2026-10-26) |
| `panels/ProvidersTableModel` | The providers table's rows (`Row` computed once per refresh by `rowOf`: label, type, endpoint, default model, model count, last sync); pure, `ProviderTableModelsTest` |
| `panels/ProviderKeysTableModel` | The key picker's rows (`Row`: key, provider or *choose provider*, endpoint, used-by count); pure, `ProviderTableModelsTest` |
| `panels/JobQueuePanel` | Stub (see the status block) |
| `panels/CapturePanel` | The Capture page: `PagePanel` head (Define area, Capture (N)), the Areas and Captures toolbar-over-table columns, the preview page (house list look since 2026-10-26; see the status block) |
| `panels/CaptureAreaModel` | The Areas table's rows (name edited in place, display, region); pure, `CaptureModelsTest` |
| `panels/CaptureTableModel` | The Captures table's rows (thumbnail, name, area, size, bytes, taken); pure, `CaptureModelsTest` |
| `panels/CaptureSupport` | Capture helpers: select/shootAndSave, png encode + jpeg thumbnail, icon scaling, sublabel/byte/time formatting |
| `panels/RegionOverlay` | Blocking multi-monitor drag-select overlay; `select()` must run off the EDT |
| `panels/PanelSupport` | Shared row/format helpers (`timestamp`, `deleteConfirm`, provider combos, `showErrorDialog`) |

`MarkDownViewerPanel` used to live here and is **gone** — markdown rendering is
`io.xlogistx.gui.MDViewerPanel` from `xlogistx-gui-audio`, which is also where commonmark now
comes from.

The module's own **`CaptureArea` POJO is gone too**: capture areas are
`io.xlogistx.gui.CaptureArea` (name / description / `Rectangle`, no tick and no `lastUsed`) held
in an `io.xlogistx.gui.CaptureAreaSet`, and a shot is an `io.xlogistx.gui.SnapShot`
(image + `sourceID` = the area name + sequence + timestamp, plus `exportAsInputStream(format)`).
The set owns one lazily created, cached `Robot` and serializes sweeps on it; `takeSnapShots()`
with **no arguments captures the whole set**, so every call site must pass an explicit, non-empty
array or an intended "capture nothing" turns into "capture everything".

---

> **2026-10-24, Phase 4 of the UI redesign (plan: `no-sneak-app/UI-REDESIGN-PLAN.md`).** Three
> pages were re-laid out side by side and the composer gained chips; nothing in the wiring, the
> DAOs or the send path changed.
> - **Providers** (board 8): the provider list on the left, the picker / new-key / form cards on
>   the right. Re-laid out again on 2026-10-26 in the house list look (§6): the four cards are
>   four pages (table, key picker, new-key form, provider form) that replace one another;
>   `providerCards` keeps its card names, so every `providerCards.show("list")` still lands on
>   the table. The panel no longer implements `Scrollable` and the host mounts it without a
>   `JScrollPane` — the tables scroll themselves and the forms fit.
> - **Skills** (board 7): the list (320–420 px) on the left, the `MDEditorPanel` on the right.
>   Re-laid out again on 2026-10-26 in the house list look (§5): a full-width table page, and
>   the editor as a page of its own that replaces it; `skillsCards` keeps `"list"` / `"editor"`,
>   and the editor's `JSplitPane` still gets a real viewport height from the page card.
> - **Capture** (board 6): capture areas and captures **side by side** instead of two tabs.
>   Re-laid out again on 2026-10-26 in the house list look (the Capture status bullet above):
>   each half is a toolbar over a table card, the preview is a page of its own (Back / Send to
>   chat), and the old toggle buttons and `showAreas()` are gone. *Delete all* is always visible.
> - **Chat composer chips** (board 4): a `ChipPanel` **inside the composer bar**, above the input
>   box, lists what goes with the next message — md skills (*skill*), attached images (*image*),
>   capture areas ticked to shoot on send (*shot on send*) — each removable from its ×
>   (`dropPendingChip`: `pendingSkills` / `pendingSources` / `tickedAreas`, then
>   `refreshSkillTooltip`). Text sources are not repeated: they keep their full view at the end of
>   the transcript. The row is hidden while empty, and it lives in the composer bar, so the rule
>   that nothing sits between the transcript and the composer holds.
> - The *Chats* (history) page and the job-queue stub were untouched then; **Chat History
>   followed on 2026-10-26** (the maintainer: "it is still rendered with the old look and
>   feel") — see §4 — and **Capture, Skills and Providers the same day** ("do the same for
>   the Capture page", then "for the Skills page", "for the Providers page"; the Capture status
>   bullet below, §5 and §6). **Last, the Chat page itself, merged with Chat History** ("do the
>   same for the Chat page and make sure there is not overlapping with the Chat history or
>   maybe they should be merged" — merged, the maintainer's call): one sidebar item, the list of
>   chats is the page and the open conversation replaces it (§2, §4).

## 1. Window shape

The host application (`no-sneak-app`'s `AppShell`) owns the window: its one sidebar lists the
assistant's pages under an **Assistant** section — Chat, Capture, Skills, Providers (Chat History
merged into Chat on 2026-10-26) — and routes each to `AssistantPanel.showPage(Page)`.
`AssistantPanel` itself is **wiring only** since
2026-10-24: the five page panels behind one `CardStack`, no navigation column of its own
(`PanelBuilder.buildDefaultSplitPanel` and the `JToggleButton`s are gone). Since 2026-10-27 each
card is registered as a gui-audio `ComponentRef<Page>` over its constant (`page(Page, card)`: the
ref's name is the card key, so `showPage` and `resetPanel` flip by it); `page(Page)` / `pages()`
hand the refs to a host that wants a page's component, title or description. Since 2026-10-26
`Page implements GetDisplayName`: each page's title at the top of its panel (`ChatHistoryPanel`,
`CapturePanel`, `SkillsPanel`, `ProvidersPanel`, `JobQueuePanel`) reads `Page.X.getDisplayName()`,
and the host's `Navigator.Screen` carries the same words, pinned by the app's `ScreenLabelsTest`.
Since 2026-10-27 `Page` also implements `GetDescription` (one line per page, the same as the
screen's, pinned by the same test); the host shows it as the sidebar tooltip.

| `Page` | Panel | Refreshed on the way in |
|---|---|---|
| `CHAT` | `ChatPanel` | `showCurrent()`: the open conversation, or the list of chats refreshed (`refreshHistory()`) when none is open |
| `CAPTURE` | `CapturePanel` | `refreshAreas()` + `refreshCaptures()` |
| `SKILLS` | `SkillsPanel` | `refreshSkills()` |
| `PROVIDERS` | `ProvidersPanel` | `refreshList()` only — not `refreshProviderViews()`, which repopulates the chat editor's provider combo and would reset a selection that card is still holding |
| `QUEUE` | `JobQueuePanel` (stub) | not offered by the host's sidebar |

The refresh-on-the-way-in rule stands: a `ListSection` only rebuilds from its supplier on
`refresh()`, so a page merely switched back to used to show whatever it held at the last
mutation. When a page moves the assistant by itself — a chat opened from history, a capture sent
to the chat, `sendToChat` from the scanner, *Save as skill* from a bubble — it calls `showPage`
too, and the host hears it through `setOnPageShown(Consumer<Page>)` to move its sidebar
highlight (`Navigator.sync`). `getPage()` is the page showing now.

Page-level actions live in each page's own head or toolbar (`New chat`, `New skill`, `Add
provider`, `Define area`), never in the host's sidebar.

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

> **Implementation status.** The popup has four sections, not two, and the chips were never
> built. **What exists instead, since 2026-10-22, are conditional entries in the transcript**
> (`ChatPanel.pendingViews`): every pending **text** source — a scan report sent from the
> scanner, an attached file, a fetched URL — is rendered **in full as the last entry of the
> transcript** through `sourceView(source, onDelete)`: a header (bold name, muted
> `type · origin · size`, a Delete button) over an `MDViewerPanel` of the content, capped at
> `SOURCE_VIEW_MAX_HEIGHT` with its own scrollbar. The entries live in the transcript's own
> scroll — a separate panel between transcript and composer was tried the same day and read as
> covering the chat, so it is a design rule now: **nothing may sit between the transcript and
> the composer**. `sourceMarkdown` puts JSON (every scan report) in a ```` ```json ```` fence so
> it renders as code and passes anything else through as markdown. **Delete exists only while
> pending**: `onSend` calls `removePendingViews()` and renders the turn — the message bubble, then
> `addAttachments`, the same `sourceView` with no Delete (under `SOURCE_VIEW_CONSTRAINT`,
> `growx, wmin 0, wmax 92%`) — and the source is persisted on the request, so it comes back on
> every `refreshPrompt` as part of the chat. `refreshPendingPanel()` rebuilds the entries (and
> scrolls to the bottom) from `refreshSkillTooltip()`, which runs it **first** — its early return
> on "nothing pending" used to skip the rebuild, so deleting the last source left its view on
> screen — and from the end of `refreshPrompt`, whose `removeAll` takes the entries with it. The
> popup's *Sources for this message* checkboxes still drop a source too. Images stay in the
> popup and render as thumbnails once sent. `attachText` moves focus to the composer. The popup
> sections are **Skills for this message**, **Images for this message** (a checkbox per attached
> image, uncheck to drop it, plus an *Attach image* file picker), and **Capture** (a fresh drag
> that *defines* a new area, an *All areas* check-all, and one tick box + remove ✕ per session
> capture area — ticked areas are shot in one sweep **when Send is pressed**, and the ticks
> persist across sends). **Job queue** is absent because the queue page itself is a stub. A message can carry any
> number of images; the attached image is display-and-wire only, so it leaves the transcript on
> the next `refreshPrompt()` and never goes out with the flattened history. See the status block
> at the top for the mechanics.

> **Layout (2026-10-26, the house list look; merged with Chat History the same day).** `ChatPanel`
> is a two-card `CardStack`: **`list`** is the `ChatHistoryPanel` (§4 — the table of chats with
> its New chat / Edit chat forms; this is what the page shows with no chat open, and what the
> sidebar lands on then, refreshed), **`chat`** is the open conversation as a page that replaces
> the list. `showConversation()` re-frames the once-built pieces in a fresh `PagePanel` the way
> the Skills page re-frames its editor: the title is the chat's (`ChatHistoryModel.title`,
> *Untitled chat* when blank), the description its facts line (`ChatHistoryModel.facts`:
> `provider · model · N messages`), the head actions are plain toolbar buttons — **All chats**
> (back to the list, refreshed), **Edit** (the §4 Edit form, which returns here on Save or
> Cancel), **Chat as PDF** (`showChatAsPDF`), **New chat** (the §4 Create form; Cancel returns
> here, Create opens the new chat) — then a row with the **provider combo** (2026-10-27, the
> maintainer's "if I have 2 ai assistant can I switch between them": the assistant the next
> message goes to; picking another one rebinds the chat, refills the model combo with that
> provider's models and lands on its default model, saves the chat and re-frames the facts line;
> the transcript stays as it is and *Send history* alone decides whether the new provider sees
> it; a chat bound to a provider that is no longer linked shows no selection; `onProviderPicked`,
> `syncProviderSelector` under a `syncingProvider` guard so the sync never counts as a pick;
> **a filter cannot outlive the switch** (2026-10-28, first a maintainer's bug report — the
> old session filter typed for the old provider's names stayed in force and hid the new
> provider's whole list — then, the same day, the filter became the model combo's own typed
> text, which the refill drops) — `ChatPanelProviderSwitchTest` drives it with two fake
> providers), the model combo (an `io.xlogistx.gui.FilterComboBox`: type to narrow the list,
> see *The conversation's model combo is its own filter* above) and the
> *Send history* / *Auto-copy code* checkboxes, and the card: the transcript over the composer
> bar (a line above it; the one primary button of the page is **Send**; since 2026-10-27, at
> the maintainer's request, an **X icon** at the right end of the input box — `IconUtil.CancelIcon`,
> the + button's twin, named `ChatPanel.CLEAR_PROMPT` — empties the typed text only, chips and
> attachments stay, focus returns to the composer; it is shown only while the composer holds
> text (the svg icon has no dimmed state, so hidden beats disabled), through the same document
> listener that resizes the bar — `composerChanged` /
> `clearComposer`, guarded by `ChatPanelClearTest`). The old empty card ("No
> chat selected", New Chat, Open Chat History) and the Chat header's own New Chat are gone with
> the merge: `New chat` lives on the list's head and the conversation's head, nothing else. The
> `currentChat` event drives the cards: a chat (open from the list, Create) shows the
> conversation, null (reset, delete of the open chat) shows the list — `saveChat` does not fire
> it, so a reply landing while the subject is on the list does not move them. Forms opened from
> the conversation return to it through `ChatHistoryPanel.setOnFormClosed` and a
> `returnToConversation` flag; forms opened from the list return to the list.

Header shows the prompt title plus a compact binding:
- one model → `key · model` (mono chip)
- several → `N models` (and `· best <model>` once one is marked)
- an `Auto feed` chip when queue auto-feed is on.

### Single vs. multi-model answers

A prompt may be bound to one model or several (see New prompt). One question, one turn:

- **One model** → the answer renders inline under the assistant avatar, with `latency · in / out tokens` (2026-09-23: `120 ms · 57 in / 203 out tokens`)
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

> **Implementation status (re-laid out 2026-10-26 in the house list look, the shape of the
> app's scan history page; the same day the page merged into Chat — the list *is* the Chat page
> now, the open conversation replaces it, §2).** `ChatHistoryPanel.buildHistoryPanel` is a
> `PagePanel` (title from `Page.CHAT`, a one-line description, the primary **New chat** as the
> page action), a
> toolbar row (search over title / provider / model, the count — *No chats yet* / *N chats* /
> *shown of N chats* — and **Open / Edit / Delete** on the selected row, enabled for exactly one
> selection) and a white card holding a `Tables.style`d `JTable` on **`ChatHistoryModel`**:
> Chat · Provider · Model · Messages · Created · Updated, sorted newest update first, double-click
> opens. The model is pure (`ChatHistoryModelTest`): a blank title reads `Untitled chat`, the
> provider column resolves the config GUID through `context.lookupProvider(...)` and falls back
> to the raw reference (`no provider` when blank), the message count is `getMessages().size()`
> (still the full chat graph per row, see `no-sneak-app/LOADING.md`), and the two timestamp
> columns are `Long`s rendered `yyyy-MM-dd HH:mm` by a muted renderer so they sort as numbers.
> `refreshHistory()` (EDT-safe) re-reads `getAllChats()` and keeps the selected row by GUID. The
> **New chat** and **Edit chat** forms are the other two cards of the panel's `CardStack`, each a
> `PagePanel` with the three rows (Name, Provider, Model) and a primary Create / Save beside
> Cancel, which returns to the list (`closeForm`, which also tells `setOnFormClosed` — the Chat
> page uses it to return to the conversation a form was opened from); `editChat(chat)` and
> `startNewChat()` open the forms from outside, and opening a chat is just
> `context.setCurrentChat`, which `ChatPanel` listens to. The old `PanelBuilder.detail`
> back-arrow forms are gone. The panel is the `list` card of `ChatPanel`, mounted without a
> `JScrollPane`: the table scrolls itself.
> The "updated" column is only meaningful because `AssistantStorage` stamps `lastTimeUpdated` on
> the update branch; the store itself never bumps it (see `ai-model/CLAUDE.md`).

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

> **Implementation status (re-laid out 2026-10-26 in the house list look, after Chat History
> and Capture).** `buildSkillCards` (`list` / `editor`) implements **create / edit / delete +
> persistence** against `AIRepository` (`getAllSkills` / `saveSkill` / `deleteSkill`). The list
> is a `PagePanel` (title from `Page.SKILLS`, a one-line description, the primary **New skill**),
> a toolbar (search over name / type / description, the count, **Edit / Delete** on the selected
> row) and a `Tables.style`d table on **`SkillsTableModel`** — Skill · Type · Description ·
> Updated, by name, double-click edits. The model is pure (`SkillsTableModelTest`): a blank name
> reads `Untitled skill`, the Type column is the `SkillType`'s own name (`md skill` /
> `prompt skill` — what decides whether the composer attaches the skill or pastes it), and
> `refreshSkills()` (EDT-safe) keeps the selected row by GUID. The editor replaces the list as a
> page of its own (**New skill** / **Edit skill**; `showEditorPage` wraps the one `MDEditorPanel`
> in a fresh `PagePanel` on every open, and its Save / Create is styled as the page's primary
> button). The DAO carries `name` / `description` / `content` (the
> instructions) / `skillType`, with the content a plain `String` — so **markdown skills are just
> the string**
> (no file reference; `MDEditorPanel`'s *Open file* loads a `.md` off disk **into the editor
> buffer**, it does not create a link to it, and there is no export. If you want frontmatter
> import, parse it →name/description, body→content at the edge and keep the model a `String`).
>
> **There is one skill form, and it is the markdown editor.** `buildSkillEditor()` builds a
> single `MDEditorPanel` (field `skillEditor`), enables its optional name / description / type
> rows (`withName` / `withDescription` / `withTypes(...)`, the type combo rendered through
> `SkillType.getName()` — "md skill" / "prompt skill" — rather than `toString()`), and hands it
> `setOnCommit(this::onSaveSkill)` plus a `setOnCancel` that clears `selectedSkill` and returns
> to the list. Both entry points route through `showSkillEditor(skill, saveText)`:
> `onAddSkill` passes `null` + "Create", `onEditSkill` passes the row + "Save". Reusing **one**
> instance is why the old creator/editor pair had to go — a Swing component cannot sit on two
> cards, and the duplicated combos silently read each other's selection.
>
> **The type combo is a destination picker, not just a skill attribute.** It is populated from the
> `SkillType` values **plus** any labels registered through `addSaveTarget(label, BiConsumer)`, so
> it reads `md skill` / `prompt skill` / `probe` once `no-sneak-app` has registered the scanner.
> `targetLabel(...)` renders `GetName` values by name and anything else by `toString`, and the row
> is labelled **"Save as"**. The `withTypes(...)` call lives in `showSkillEditorFields` — i.e. it
> is rebuilt on **every open**, not once in `buildSkillEditor` — because a host registers its
> targets *after* this panel is constructed, so a combo built at construction would never show
> them. `MDEditorPanel` needs no changes for any of this: `withTypes` is already
> `Collection<? extends T>` and `MDDocument.getType()` already returns `Object`.
>
> `onSaveSkill(MDDocument)` is the only persistence point, and it **dispatches first**: a selected
> type that is not a `SkillType` routes to the registered handler with `(name, markdown)` and
> returns before touching the skill store — after a confirmation when an existing skill is open
> (its edits are not saved to the skill), and inside a `try`: a handler that throws has refused
> the content, so the editor is re-marked dirty and the handler's message is shown under a
> "Not a valid <target>" title. Otherwise it rejects a blank name with a dialog,
> then writes name + description + type (`document.typeAs()`) + instructions onto
> `selectedSkill` (or a fresh `AISkill` when creating) and saves off the EDT via
> `BackgroundTask.runCatching(..., skillEditor.getSaveButton(), ...)`. Note the validator still
> only checks for a blank name — an injected target validates its own content and reports its own
> failure, so a rejected probe leaves the editor open with the text intact. Cancel calls the viewer's
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

### 5.1 The markdown editor (`MDEditorPanel`)

> **2026-10-22 — moved out of this repo.** The class is `io.xlogistx.gui.MDEditorPanel` in
> `io-xlogistx/gui-audio`, next to `MDViewerPanel` and `IconUtil`, the only house classes it
> uses; it depends on nothing in no-sneak (`MDDocument.type` is an `Object`, `withTypes` is
> generic, the caller hands in the enum). It was `MDFileViewer` → `MDEditor` → `MDEditorPanel`
> on 2026-10-21. gui-audio compiles at Java 8, so three calls were lowered on the way
> (`getMenuShortcutKeyMask`, `Files.readAllBytes`, `sb.length() > 0`). **`MDEditorPanelTest`
> stays here** (it exercises the type combo with `AISkill.SkillType`), as does the `JPanelTest`
> window. Changing the editor means editing it in io-xlogistx, `mvn -o -pl gui-audio install`
> into `D:/dev/data/java/.m2`, then a Maven reload in IntelliJ.

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

> **Implementation status (re-laid out 2026-10-26 in the house list look, after Chat History,
> Capture and Skills).** A provider is an `AIProviderConfig` row (see the status block at the
> top), so **one credential can back several providers** and the row's identity is the config's
> editable label. The list is a `PagePanel` (title from `Page.PROVIDERS`, the footer note as its
> description, the primary **Add provider**), a toolbar (search over every column, the count,
> **Edit / Remove** on the selected row) and a `Tables.style`d table on
> **`ProvidersTableModel`** — Provider · Type · Endpoint · Default model · Models · Last sync, by
> name, double-click edits. Each row is a `ProvidersTableModel.Row` computed once by `rowOf`
> when `refreshList()` runs (EDT-safe, keeps the selection by provider ID), so the catalog is
> read per refresh, never per paint; the model count and *never synced* are currently the
> *only* signal that a key was rejected, because discovery failures are swallowed (see the rough
> edges). A per-row **Refresh** is still **not built**: re-discovery happens on login, and as a
> side effect of saving the provider form. **Remove** runs `onRemoveProvider` →
> `deleteProviderConfig` + `getProviders().unregister(id)`, and calls `setEnabled(key,false)`
> only when `configsUsing(keyGUID)` hits zero.
> `AIProviderConfig.enabled` exists but is effectively **write-only `true`** — the form always
> sets it, and nothing in the UI can disable a provider without deleting its config.

Each key carries its own auth metadata from NoSneak — `provider`, `base-url`, a free-text **auth
scheme** (`auth-type`, e.g. `Bearer`), and an optional **header name** (`header-name`, e.g.
`x-api-key`) — read straight off the credential's property bag (via the `Session.APIKeyInfo` keys
`provider` / `base-url` / `auth-type` / `header-name`), so the Providers page never re-asks for them.

### Add provider = pick a key, or create one through the source

**Add provider** opens the **picker** page (*Add a provider*: Back and the primary **New key**
in its head, a count and **Use this key** in its toolbar) — a table on `ProviderKeysTableModel`
of the credentials the source offers, **unfiltered**, because a key that already backs one
provider can back another. Columns: Key · Provider (or *choose provider* when the stored type is
not one the assistant knows) · Endpoint · Used by; that count comes from `providersUsing`, which
walks the **registrar** rather than the store, once per key when `refreshKeys()` builds the rows
on the page's open. **Use this key** (or a double-click) opens the provider **form**
(`buildProviderForm`, framed by `showProviderForm` as an *Add provider* or *Edit provider* page)
on a new config seeded from the key's `provider` / `base-url` properties: Key (read-only) / Label
/ Provider type / Base URL / Default model, with the primary Save (*Add to assistant* on the add
path) beside Cancel — the **Default model row is hidden on the add path** (`hidemode 3`), because
discovery has not run yet and the combo would be empty; it appears once the provider is edited
after its first save. **New key** opens the `create` page (`buildCreateProviderKey`, *New
provider key*) for a key NoSneak doesn't have yet: Label / Provider (the known types) / API key /
optional Base URL, *Add to assistant* beside Cancel — no domain/app-id scope fields, that's
Credentials vocabulary. It creates through
`AICredentialSource.addAPIKey` (→ `Session.storeAPIKey` with `external = true` +
`setAssistantEnabled`), then lands on the same form. The key is a full NoSneak credential —
visible, editable, and deletable in Credentials, and key mutations made here reach that page
live: `Session` fires a `"credentials"` event that `SubjectPanel` refreshes on. The assistant
itself never deletes a credential — key deletion lives on the Credentials page's edit-API-key
card (and its list rows), deliberately outside this module.

The page's description (the footer note of the old list): keys come from NoSneak credentials;
adding one here lets the assistant use it and discover its models; it is never stored separately.

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
4. ~~Key + model are immutable for a prompt's lifetime.~~ **Dropped 2026-10-27** — the maintainer
   asked to switch assistants inside a chat. The conversation's provider and model combos rebind
   the chat for the next turn, the Edit chat form does the same, and every reply records the
   provider and model that answered it (`AIResponse.provider`, set by `AssistantCallback`; the
   bubble's detail line and the PDF's `### Assistant` heading read `provider · model` through
   `ChatHistoryModel.replyMeta`), so a transcript that changed hands stays readable.
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
the GUID yet); `resetContext()` clears the selection, **all three** caches and the session
`CaptureAreaSet` (`getCaptureAreaSet()` is the only accessor — the old
`getCaptureAreas`/`addCaptureArea`/`removeCaptureArea` trio is gone), then
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
  `AIProvider.asyncSend(wire, skillText, callback)` — or, when the message carries images or
  ticked capture areas, hops into a `BackgroundTask` that shoots, encodes, and calls
  `asyncImageSend(wire, skillText, callback, UByteArrayInputStream...)` from the worker thread —
  for the single bound provider
  (`getProviders().lookup(chat.getProvider())`), where `wire` is a **second, throwaway**
  `AIRequest` carrying the flattened `Human:/Assistant:` transcript — the `AIRequest` stored on
  the `AIMessage` keeps the raw user text, so the transcript shows what was typed while the model
  sees the whole conversation. The chat is saved **once before dispatch** (so an unanswered turn
  survives) and once more only when a capture-carrying send attaches its images; the former
  unconditional save after dispatch is gone — it ran on a second worker with no ordering and, for
  a chat with no GUID yet, could insert a duplicate row (finding 9). `AssistantCallback` decodes
  the payload (`AssistantMDDecoder`), persists via `saveChat`, and marshals UI updates (and the
  error-path message removal) to the EDT. Both the synchronous throw (`asyncSend` itself failing) and the async error path undo the
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

**Tests.** The module runs **73 green tests** (2026-10-07, through the hand-rolled launcher in
`.claude/tools/` with the toolkit jars added to its classpath — surefire's JUnit provider is not
cached on the Windows box, and the Swing tests need a display, so no `-Djava.awt.headless`):
`ModelNameTest` (4) pins the `models/` prefix strip; `DetailLineTest` (3) the bubble's `latency · in / out tokens` line; `AssistantMDDecoderTest` (29) renders through
commonmark and asserts on the resulting HTML rather than on strings, so it checks the fix actually
renders — plus fence fixtures in `src/test/resources/fence/`; `MDEditorPanelTest` (8) covers the
editor's commit/revert/dirty contract (the class itself lives in gui-audio since 2026-10-22); `AssistantContextTest` (7) guards the canonical caches, the
delete-fires-only-for-the-current-chat rule, `resetContext` (including session capture areas), and
the capture round-trip, against an in-memory `AIRepository` that hands out a fresh instance per
read like the real store does; `CaptureSupportTest` (6) pins the headless-safe capture helpers
(`toCapture` field mapping and png round-trip, thumbnail bounds, `bytes`, `shortTime`,
`region`/`usable`, `areaSublabel` — the `scale` case went with the helper, which
`GUIUtil.compressImage` replaced); `ModelFilterTest` (7) pins the model-filter grammar (blank →
built-in markers, bare word → contains, glob include, `!` exclude, exclude-only, `*`,
round-trip/clear, and a lone `!` being ignored rather than blocking everything); and
`ChatBubbleSaveAsSkillTest` (4) covers the "Save as skill"
affordance; `ChatBubbleReuseTest` (3, 2026-10-27) the user bubble's copy icon (present with a
handler, clickable, never on a reply); `ChatPanelClearTest` (1, 2026-10-27) drives a real
`ChatPanel` over `AssistantContextTest.MemoryRepository` (package-private for that) with a current
chat and checks the clear icon is hidden when empty, shown on text, and empties the composer;
`ChatPanelProviderSwitchTest` (2, 2026-10-28) registers two fake `AIProvider`s with fixed catalogs
on the context's registrar, binds a chat to one, types into the model combo's editor (the list
narrows), picks the other provider in the conversation's combo and checks the list is the new
provider's, the editor shows its model and the chat is rebound; the widget itself is pinned by
gui-audio's `FilterComboBoxTest` (6); `CodeBlocksTest` (5, 2026-10-07) pins the fenced-block extraction behind the chat
header's *Auto-copy code* box. `RegionOverlay` and the capture tab/toolbar/inline-rename behavior are **not**
headless-testable — they need real windows and a mouse; use the `AssistantPanelTest` harness.

Three files in test sources are **not** JUnit tests but `main`-method visual harnesses:
`ChatBubbleTest` (renders `AssistantUtil.chatBubble` over the real transcript layout under both
FlatLaf themes — paste a provider answer into its `RESPONSE` constant to eyeball a rendering bug),
`JPanelTest` (the `MDEditorPanel`), and `AssistantPanelTest` (the whole panel — including the
capture page; its in-memory repository's `saveCapture` is a passthrough, so captures "save"
without a store — against fake credentials, layout only; its keys are not real, so anything
touching a wire will fail). Run the suite with
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
