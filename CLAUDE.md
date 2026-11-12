# no-sneak

> **Picking this project up?** `PENDING-ISSUES.md` at the repo root is the open-work index: its
> *Open now (2026-10-27)* section is the whole open list, and everything under *History* is the
> dated record (kept because sources cite its finding numbers). Since 2026-10-21 the app's store
> follows the datastore's deployment model: a first run is `H2PSetup command=create` (vault with the operator as
> super-admin, encrypted H2 file, the no-sneak app, `shiro.ini`), every run opens the vault and
> attaches the Shiro manager to the INI realm, and sign-up grants the app's `app_user` role so the
> app login gate lets the subject in (`no-sneak-app/NoSneakStore`). It lists the decisions taken
> on the maintainer's behalf and what is still open (old installations are refused). The **Mongo
> path is deprecated** (2026-10-25): the store is the encrypted H2 file, PostgreSQL is the next
> datastore target. The Swing UI was redesigned on 2026-10-24/25 — `no-sneak-app/UI-REDESIGN-PLAN.md`
> and the *Status check (2026-10-24)* section of `PENDING-ISSUES.md` carry it; committed on
> 2026-10-25. **After it, uncommitted (2026-10-25/26, same section, dated blocks):** MAC vendor
> names in scan reports (the Wireshark manuf file kept in the store as a `DataContent`, loaded into
> `NSNetUtil.MAC_VENDORS` after login, *Account → Settings → Sync* to refresh it), Delete all and
> multi-select on the scan history, **no probe ticked = no probing**, a Network adapter block
> (MAC, vendor) in the host detail pane, and (2026-10-26) a **Probe library** that shows every
> bundled and stored probe read-only, explains how to add one, shows `PROBE-DEFINITION.md` in
> the app and asks the assistant for a probe (*Save as probe* on the reply); probes carry an
> optional one-line `description`. Same day: the two unbundled probe files were deleted as
> redundant and `postgres-tls` was fixed with a new `tls-upgrade` action (SSLRequest, then TLS
> in place, then the version over it). **2026-10-27** (same section, dated block): Chat and Chat
> History merged into one Chat page, a MAC column on the Hosts tab, Help and About rewritten, a
> status bar that shows the MAC vendor list's state, the Profile, API Keys and Settings pages
> re-laid out, and gui-audio's **`ComponentRef`** under every enum-driven control (sidebar, View
> menu, segmented controls, assistant pages, navigator routes, tabs, list rows, chips) with
> descriptions on the UI enums as tooltips. **Later that day** the app's five *Hardening* items
> closed: one signed-in guard in `Session`, identifier rules left to the manager, chat delete
> cascade, a blank provider removes the entry, a copied API key wiped from the clipboard after 60 s.
> Same evening: a **Provider combo** on the conversation page switches the assistant inside a
> chat, and every reply says which provider · model answered it (`AIResponse.provider`); later,
> a **copy icon on every past prompt** puts its text back in the composer to send it again, and
> an **X icon** inside the input box empties the prompt. **2026-10-28:** the Model box and the
> model filter are one gui-audio **`FilterComboBox`** (type to narrow the drop-down), so a filter
> can no longer hide the new provider's models after a provider switch. **2026-10-29:** step-1
> tooltips and the NOT RECOVERABLE warning under the vault password on the unlock screen, and a
> **Hide window** box beside Capture (N) on the Capture page (ticked by default; clear, the
> application stays on screen while an area is drawn or shot, so it can capture itself).
> **2026-10-31:** an **Assistant block on the Settings page** with the **reply timeout** (seconds a
> provider may take to answer one request, 10 to 600, default 40, kept per installation in
> `AppPrefs`). The usual 40 s is right for a responsive endpoint; the setting is there to
> stretch it for a congested one, which zoxweb's shared http client gave no way to do.
> `AssistantContext` holds the value and **one shared
> `OkHttpClient`** built from it, rebuilt when the setting changes and pushed to every
> registered provider's endpoints (`applyHttpClient`); a provider built later gets it when it is
> registered, and a timed-out send names the setting in its error. **Same day, the scanner:**
> with no ports typed and probes ticked, the scan covers **the ticked probes' declared ports**
> (ssh + https-pqc = 22, 2222, 443, 8443; `NMapScanner.resolvePorts`, the Ports placeholder says
> which) instead of 1-1024; typed ports still win; and **`--probe-match first|all`** (a *Match*
> segment on the form) picks the checker's sweep on an open port — first, the default, stops the
> other probes once one has identified it, all keeps every identification (`PortReport.probes`,
> the JSON's `probes` list, an *Identifications* block in the host detail). **2026-11-01:** the
> Scan page is titled *Scan* like its sidebar item, and a **New scan** button on that page clears
> the form, the chips and the result (`ScanPanel.newScan`); the history page's button is unchanged.
> **Same day, probe groups** (`PLAN-probe-groups.md`): a subject saves named sets of probes
> (`ProbeGroup` in core, a set of probe *names*, an `NVStringSet`), ticks one in the Add probe popup's
> **GROUPS** section or keeps the chips as one with *Save ticked as group…*, and manages them on
> a **Probe groups** page behind the library bar's *Probe groups manager* button (table, member badges,
> an editor with a checklist). A group never reaches the engine: ticking it ticks its probes,
> the report records the probes; a deleted member is reported as missing, not lost
> (`ProbeGroupModel`, `no-sneak-app/CLAUDE.md` → *ScanPanel* → *Probe groups*). **Same evening,
> UI descriptors:** every component the app builds now has a constant in `no-sneak-app`'s
> `NSAppUtil` (36 enums implementing zoxweb's `GetNameDescriptionDisplay`: the page list `Screen`,
> the tabs, filters and table columns that lived beside their panels, and one enum per panel) and
> is rendered through gui-audio's `GUIUtil.applyProp` — no literal label, tooltip, placeholder or
> dialog title is left in a panel (`no-sneak-app/CLAUDE.md` → *ScanPanel* → *Probe groups*, last
> paragraph); `ai-assistant` has its twin, `AIAssistantUtil` (20 enums, the assistant's `Page`
> among them), so the whole Swing surface follows the one rule. **2026-11-02, one probe
> source** (`PLAN-single-probe-source.md`): the 18 bundled probes are copied into a subject's
> own `ProbeType` rows once, at their first login (`Session.seedBundledProbes`; the marker
> `probes-seeded` on the subject's property bag, `origin=bundled` on each copy — no new entity,
> no new param). From then on every probe is theirs to tick, edit, delete and group: the Add
> probe popup and the library have one section, *Restore bundled probes* on the library bar
> re-adds the missing ones and never overwrites, a probe's name is unique among the subject's
> rows and a rename follows into the groups. The engine takes exactly the ticked definitions
> with its bundled catalog switched off (`NMapConfig.bundledCatalog`, set in code, never on the
> command line, so the CLI is unchanged). No upgrade path, by decision: a bundled probe fixed in
> a later version reaches a seeded subject only through Restore, and only if they deleted theirs.
> **Later that day** the maintainer renamed the entity `ProbeContent` → **`ProbeType`** (param
> `content` → `definition`, table `probe_type`, `setName` lower-cases and trims); the app refuses
> a definition whose name is not already in that form (`ProbeSelection.nameForm`). A store from
> before the rename keeps its old `probe_content` table unread: its subjects, already marked as
> seeded, see an empty library until *Restore bundled probes*. **Same day, Appearance**
> (`PLAN-appearance.md`): an **Appearance** block on the Settings page — the **theme** (FlatLaf
> Light or Dark, `NSAppUtil.Theme`; Dark is FlatLaf's macOS Dark palette — the grey FlatDark and
> Darcula were tried first and dropped the same evening, one dark look being wanted) and the **control text size** (gui-audio's
> `FontSizeWidget` over `UIFontSize`, 8 to 32 points, Reset to 13), both per installation in
> `AppPrefs`, installed before the unlock screen. A theme choice applies at once by rebuilding the
> pages on the same session (`AppFrame.applyTheme`; refused while a scan runs), since panels keep
> the token colours they read when built; the `xlogistx.*` tokens get their dark values from
> `themes/FlatDarkLaf.properties`, shared by both dark cores. gui-audio followed: `ListSection`'s
> border and `MermaidRenderer`'s palette read the tokens.
> **2026-11-03, the engine left this repo** (commit `80cded0`): `no-sneak-core` and `no-sneak-net`
> are deleted here and live in **io-xlogistx** as **`xlogistx-scan`** and **`xlogistx-net`**, with
> new base packages — `io.xlogistx.nosneak.*` → **`io.xlogistx.scan.*`** (`ProbeChecker`, `nmap`,
> `model`, `data`, …) and `io.xlogistx.nosneak.net.*` → **`io.xlogistx.net.*`**. This reactor is
> now `no-sneak-app`, `ai-assistant` and `ai-model`; `no-sneak-app` takes both engine modules as
> `io.xlogistx:*:${xlogistx.version}` jars (`xlogistx-scan` itself depends on `xlogistx-net`), so
> an engine change is built and installed from io-xlogistx first. The engine's docs moved with it
> (`xlogistx-scan/CLAUDE.md`, `README.md`, `PROBE-DEFINITION.md`; `xlogistx-net/CLAUDE.md`,
> `README.md`). The two non-engine classes core carried — **`DMTool`** (the subject admin CLI) and
> **`NSCoreUtil`** (its cached `DomainSecurityManager` over `XlogistxMongoDataStore`) — moved to
> `no-sneak-app`'s `io.xlogistx.nosneak.app.tools`, which is why the app now declares
> `org.zoxweb:xlogistx-datastore`. Dated references above to `no-sneak-core`, "core" or
> `io.xlogistx.nosneak.data` read as `xlogistx-scan` / `io.xlogistx.scan.data`.
> **Same day, uncommitted:** a **Text size** row on the unlock screen (top-right of the
> right pane; the maintainer: "at start sometimes it is too small") — the same `FontSizeWidget`
> + Reset as Settings → Appearance, applied at once and remembered, so a subject fixes the size
> before signing in (`UnlockPanel.buildTextSizeRow`, `UnlockPage.TEXT_SIZE*`).
> **2026-11-04, uncommitted:** the **Password row and the change-password form moved from the
> API Keys page to the Profile page** (the maintainer: "in the api key panel there the password
> panel it should be under profile"): a Password block between Name and Identifiers, its Edit
> opening the form as a card of the profile stack; API Keys holds only the keys
> (`ProfilePage.PASSWORD`, `PasswordEditor`; `ApiKeysPage.PASSWORD_SECTION` deleted). **Same
> day**, the **API Keys page became a table page** like Probe groups and Scan history ("it is
> still like the old look, make it standard like the rest of the application"): search and
> count over a keys table (Label · Provider · Base URL · Scope · Description,
> `NSAppUtil.ApiKeyColumn`), a how-to or the selected key's facts with Edit / Delete on the
> right, the editor behind Edit (`no-sneak-app/CLAUDE.md` → *SubjectPanel* → *Credentials*).
> **2026-11-06, uncommitted (gui-audio):** the **Reset link beside Font size** on the Settings page
> and the unlock screen read *Re…* ("fix the Font size in setting"): FlatLaf's one-point MigLayout
> `visualPadding` on every button cut the toolbar-type link's text; `UITokens.link` now pins it to
> zero (`UITokensLinkTest`; `PENDING-ISSUES.md` → the 2026-11-06 block). **Later that day** the
> two rows (Settings, unlock) became one gui-audio part: `FontSizeWidget.withLabel().withReset()`
> carries the caption and the Reset link itself (`getLabel()` / `getResetButton()` take the app's
> constants); the PDF viewer's bare toolbar widget is unchanged. **Same evening, uncommitted:** a
> **Local networks** link beside the Scan form's Targets label ("add cidr block as helper in scan
> panel from `NetUtil.allV4CIDRBlocks()`"): a menu of this machine's IPv4 CIDR blocks, read off
> the EDT from zoxweb-core's new `NetUtil.allV4CIDRBlocks()` (install zoxweb-core from source
> first: the method is uncommitted there), a pick appending one to the targets, a **Refresh**
> item last for a network that came up since
> (`ScanFormPanel.networksMenu`, `no-sneak-app/CLAUDE.md` → *ScanPanel* → the form bullet).
> **Late that evening, uncommitted:** "+ New Sc.." — button text ending in dots on every page
> ("you cannot put dots, you have to be explicit to the user"): `Component.focusWidth` went from
> 1 to 0 in `themes/FlatLaf.properties`, because FlatLaf hands it to MigLayout as the button's
> visual padding and MigLayout clamps it at a row's edge, one point off every row-ending button
> (`ButtonTextNotClippedTest`; `PENDING-ISSUES.md` → the 2026-11-06 late block).
> **2026-11-10, uncommitted — Discovered hosts only:** a box on the Scan form and one beside
> *Scan again* on the history bar ("a check box for rerunning the scan on the discovered host …
> you always check if the host is alive before you probe, that is mandatory"). Ticked, the
> targets become the hosts the earlier report found up and **host discovery stays on**, so only
> those hosts are checked and only the ones that still answer are scanned and probed; `-Pn` and
> `-sn` are dropped from the rerun. App-only, no engine change (`ProbeSelection.rerunCommand`,
> `ReportView.Report.discoveredTargets`, `ScanFormPanel.setDiscoveredHosts`;
> `no-sneak-app/CLAUDE.md` → *ScanPanel* → the form bullet and *History*).
> **Same day, uncommitted:** the Scan form is **two cards** ("group target, Local networks, port
> and Name in a panel by itself and add clear target"): Targets (with the *Local networks* and
> the new *Clear* links), Ports and Name in the first, the options, timing, probes and command
> in the second (`ScanForm.TARGET_CARD` / `SETUP_CARD` / `TARGETS_CLEAR`,
> `ScanFormPanel.clearTargets`). **Then the Targets field became a text area** ("change target
> text field to text area … create it under xlogistx-gui-audio … call it TextAreaWidget"):
> gui-audio's new **`TextAreaWidget`** (three wrapping rows that scroll, Enter runs the scan,
> Shift+Enter breaks the line) over the card's full width, a count beside the links
> (*60 targets*). Install gui-audio from io-xlogistx first. **Last that day**, the card's head
> is one line ("next to Targets put Name (optional) [name], Ports [ports], Local networks,
> Clear"): Targets · count · Name · Ports · Local networks · Clear, the area under it; Name
> and Ports are a fixed 20 characters wide (15 at first). The **Command field is a `TextAreaWidget`** as
> well ("make command textarea as well"): two wrapping rows, Enter runs the scan; it is 80
> characters wide and the Targets area is as wide as the head line above it (one size group).
> An **unnamed scan** of more than three targets is named *first and N more*
> (`ScanPanel.defaultName`): the name is the result's title, and a rerun on 23 discovered
> hosts printed every address there ("why you are printing … all the ip"). A scan's name is
> **at most 30 characters** ("limit the scan name to 30 characters"): the Name field stops
> there (gui-audio's new `GUIUtil.limitLength`; install gui-audio first) and the made-up name
> is cut to fit (`ScanFormPanel.NAME_MAX`). **Run reads everything again** ("whenever I hit
> scan button read all the parameters and run the scan accordingly"): `ScanPanel.prepareRun`
> takes the command and every field as they stand, refuses a command that does not parse,
> lets the chips alone decide the probes, and the worker resolves the ticks against the
> store again; *Scan again* clears the result left on the Scan page
> (`ScanRunReadsTheFormTest`). The stale scan the maintainer reported was **not reproduced**.
> **2026-11-11, uncommitted:** Help, Run scan and Stop sit beside the **Command label**, on the
> line above the command area ("next to command move info, run scan and stop"), and the
> **Match** segment is a line of the options block ("Match section put under options").
> **Copy** follows Stop on that line and the page's **New scan** button sits on the left,
> beside the title ("move copy next to stop, and NewScan to the left"). The **Targets and
> Command areas have no fixed width** any more: both fill their card and follow the window
> ("the 2 text area remove length limitation and make their resize natural"). **Discovered
> hosts only is validated at every Run** ("when I check the box and click scan it should
> always be validated"): ticked, Run puts the discovered hosts in Targets with discovery on,
> whatever was typed since, and the tick survives a new result (the targets follow it).
> **The rule for that rerun** (the maintainer: "when the discovered host is checked and
> probes are selected you only scan the selected ones and the associated ports, unless the
> ports are set specifically"): only the ticked probes, on their declared ports, unless Ports
> is typed. One path broke it: the history bar's rerun of a scan that saved no probes (a
> host discovery) wiped the ticks, so the run was 1-1024 on every host with no probing; the
> ticks on the Scan page now stay (`ScanPanel.loadRerun`, `ScanRunReadsTheFormTest`).
> A temporary run log (`SCAN RUN` / `SCAN DONE`) found the slow scans: `https-scan` takes
> 48 s on one of the maintainer's hosts (a Pi Zero W), known and left alone; the log was
> removed the same day ("remove the logs printout").

Assessment tooling for what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — plus a Swing front-end and an AI-assistant layer.

## Operating scope — read this before changing anything

no-sneak is **defensive assessment tooling**. It answers *"what does this endpoint expose, and how
good is its posture"* for an operator assessing infrastructure they own, administer, or have been
authorized to test. Everything it ships is observational: open a connection, complete an ordinary
protocol handshake, read what the peer volunteers, record it, report it.

**In scope** — TLS/PQC handshake assessment, certificate chain trust and revocation, protocol and
cipher enumeration, service/version identification through declared probes, ICMP/ARP/NDP host
discovery on a segment the operator controls, grading, and reporting.

**Out of scope, permanently.** These are design constraints, not backlog items:

- **No exploitation.** Vulnerability work here is *detection*: infer exposure from advertised
  versions, extension presence, negotiated parameters, and ordinary handshake behaviour. Never
  send input meant to read a peer's memory, corrupt its state, or execute code on it.
- **No credential attacks.** No password or key guessing, spraying, brute force, or capture.
- **No denial of service.** No flooding, amplification, resource exhaustion, or fuzzing of a live
  target. The rate limits, bounded concurrency, timeouts and soft-fails are safety properties —
  they are not overhead to optimise away.
- **No evasion.** Nothing is built to be hard to observe, log, or attribute. Traffic leaves under
  our own addresses. nmap's `-sS/-sF/-sX/-sN/-sA` flags and the word "stealth" appear in this repo
  only as **legacy nmap vocabulary** in pre-merge notes and CLI-compatibility text; the scanner rejects those flags
  with a clear error and those engine classes are deleted rather than implemented.
- **No persistence, C2, or exfiltration.** The tool runs, reports and exits. Results stay in the
  local encrypted store unless the operator deliberately sends them somewhere.

**Data handling.** Everything a subject produces is scoped to that subject in the encrypted H2
store. Scan reports carry network topology and are sensitive: they cross a trust boundary only when
the subject attaches one to a chat, under the subject's own provider credentials. Any path that
shows one subject's data to another is a defect, not a feature — see `PENDING-ISSUES.md` finding 1.

A change that would cross one of those lines is out of scope for this repo: say so, and propose the
detection-only or narrower-design version instead.

Three modules in this reactor, one-way dependencies (`no-sneak-app → ai-assistant → ai-model`),
plus the two engine modules `no-sneak-app` consumes as jars from **io-xlogistx**
(`no-sneak-app → xlogistx-scan → xlogistx-net`; the app also reads `xlogistx-net`'s
`NSNetUtil.MAC_VENDORS` directly, from `Session`):

| Module | Where | What it is | Orientation |
|---|---|---|---|
| **`no-sneak-app`** | here | Swing desktop front-end, session/access layer | `no-sneak-app/CLAUDE.md` |
| **`ai-assistant`** | here | Swing window to send network data to third-party AI models and compare | `ai-assistant/CLAUDE.md` |
| **`ai-model`** | here | The backend contract (DAOs + service interfaces, no implementations) | `ai-model/CLAUDE.md` |
| **`xlogistx-scan`** | io-xlogistx | The scanning engine (TLS/PQC + protocol probes + network scanner), package `io.xlogistx.scan` | `io-xlogistx/xlogistx-scan/CLAUDE.md` |
| **`xlogistx-net`** | io-xlogistx | Host discovery (ICMP/ARP/NDP over FFM), package `io.xlogistx.net` — built; verified on live hardware on Linux, Windows and macOS | `io-xlogistx/xlogistx-net/CLAUDE.md` |

`io-xlogistx/xlogistx-net/CLAUDE.md` is two documents in one: an authoritative build spec (base package
`io.xlogistx.net`, JDK 25 FFM, house libraries only) in §1–§12, and a running verification
log in §13. Anything in this repo that wants host discovery goes through **`HostScanner`** (§14.1) —
a session you open once and run many pings, resolves and sweeps through; `HostScan` is a CLI over
it. The code is real — three backends, that CLI, ~370 green tests in 39 classes — so §13 is where
you learn what has actually touched a wire versus what merely compiles, and it is worth reading
before trusting any claim in the earlier sections. **§13.21 is the open-items list, split per
platform** — start there if you are picking work up.

**Every platform now has a layer-2 backend**; macOS was the last, and goes through libpcap rather
than the kernel neighbour table §7.3 gated on — that ABI is retired, not measured (§13.14). macOS was
brought up on Apple Silicon on 2026-07-29 and now has runtime evidence like the others — active ARP,
sweep over wired and Wi-Fi, and passive observe all moved packets (§13.20). The last claim without a wire, **Linux IPv6/NDP**, was verified on live hardware on 2026-09-13 (§13.24), and the whole Linux backend was re-run against its 2026-07-28 baseline the same day after the September rewrite.

## `xlogistx-scan` is one code base now

Until 2026-09-12 the module carried two generations side by side: the original packages and a
from-scratch non-blocking rebuild under `io.xlogistx.nosneak.v2`. **The merge is done.** The
original packages (`nmap`, `probe`, `scanners`, `services`, `tools`) and their tests are deleted,
the rebuild lives at **`io.xlogistx.scan`** (`io.xlogistx.nosneak` until the 2026-11-03 move out of
this repo), and the 18 bundled probes are at `/probes/` on `xlogistx-scan`'s classpath. There is no
`v2` package, no `v2` class name and no frozen code left. The merge analysis and the pre-merge
action plan were deleted on 2026-10-26 as history; the vulnerability checklist the action plan
held is now in `io-xlogistx/xlogistx-scan/CLAUDE.md`. Read that file first; it routes to the
plan log, the probe definition, and the open-work list.

**2026-09-20 — the scan pipeline was made fast on a LAN.** Adaptive per-host connect deadline
(`--min-rtt-timeout` floor, `-t` ceiling), probes streamed from the connect callback under `-sV`,
a `ScanGate` that honours rate caps above 1000/s, NIOSocket's connect monitor released when the
scanner's own deadline wins, and `--up-only` to list live hosts only. A `/24 × 1024 ports` on the
maintainer's segment went from 136 s to 6 s; the design is `io-xlogistx/xlogistx-scan/CLAUDE.md` → *The scan
pipeline*.

## Build and test

```bash
mvn clean install                         # this reactor: no-sneak-app, ai-assistant, ai-model

# the engine is built in io-xlogistx — run this there and install it first when it changed
# (-am also builds xlogistx-net and the house modules it needs)
mvn clean install -pl xlogistx-scan -am

# tests are skipped by the parent pom (xlogistx-mvn); override to run them
mvn -pl no-sneak-app test -DskipTests=false
```

External dependencies are zoxweb (`org.zoxweb.*`, including zoxweb-datastore's `xlogistx-datastore`
and `h2p-datastore`) and the `io-xlogistx` modules (`common`, `core`, `http`, `shiro`, `opsec`,
`gui-audio`, `scan`, `net`). **Bouncy Castle is the only cryptographic library**, and
reusable crypto/utility helpers belong in `opsec/OPSecUtil`, not in this repo.

If a TLS-intercepting proxy is installed locally, Maven can't reach central and every scanned
certificate reads `UNTRUSTED_ROOT` — neither is a code defect. Its mail shield also completes TCP
handshakes on the mail ports locally, so those read `open` on every host. Scan with it off. See
`io-xlogistx/xlogistx-scan/CLAUDE.md` → *Build, test, verify*.
