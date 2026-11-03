# Coding plan — Appearance settings (theme and text size)

**Date:** 2026-11-02 · **Owner:** Marwan · **Status:** implemented 2026-11-02 (uncommitted, in
no-sneak and io-xlogistx/gui-audio) — see `no-sneak-app/CLAUDE.md` → *SubjectPanel* → *Settings*.
As written, with what the code taught: the size listener is registered once in `NoSneakMain.main`,
not in `AppShell` (a rebuilt shell would add a second one); Step 4's audit found the panels' hand-built
colours are white glyphs on accent buttons and two `UIManager` fallbacks, fine in dark, so only the
unlock screen's ground and the two monospaced fonts changed — but two keys read ad hoc through
`UITokens.color(key, null, fallback)` (`xlogistx.chip`: the command field and the header chip;
`xlogistx.navHover`: the sidebar) needed dark values, which the dark file gives and the light file
leaves to the fallbacks so Light stays pixel-identical; `xlogistx.border` must be written
`{color}…` (FlatLaf parses a key ending in *border* as a `Border`); the frame rebuilds the unlock
panel with the shell (bound to the session, marked open), else a sign-out after a switch would
show stale light colours. **Two themes in the end, Light and Dark, where Dark is FlatLaf's macOS
Dark** (`FlatMacDarkLaf`): after the maintainer's first look Darcula was found to share Dark's
palette in FlatLaf 3.7 (focus rings, arrows and bold default-button text apart, most of which our
shared properties override), was replaced by macOS Dark, and the grey FlatDark was then dropped
too ("remove dark and keep dark macos and call it dark"); stored `darcula` / `mac-dark` resolve to Light. **Found on the first live run:** the
rebuilt shell had never seen a login, so its library and history were empty — the panels load on
the session's authenticated event; `applyTheme` now drops the old shell's listeners
(`Session.removeListeners`, the frame's own re-registered) and replays the event to the new one
(`Session.replayAuthenticated`), pinned by `SessionListenersTest` and `ThemeSwitchReloadTest`.
**Rule:** never commit. Edit, build, test, leave staging and commits to the maintainer.
**Review rule:** this plan creates **no entity** and touches **no store**: both values are
per-installation preferences (`AppPrefs`, a Java `Preferences` node), like the reply timeout.
If a value should ever follow the account instead, that is a store change and needs review first.

## Goal
Two settings on the Settings page, in a new **Appearance** block above *Sync*:

- **Theme** — *Light* (today's look), *Dark*, *Darcula*. The three are FlatLaf's own cores, already
  on the classpath; nothing new is downloaded. The combo shows the theme in force and a choice
  **applies at once**: the look and feel is switched and the pages are rebuilt on the same
  session, with Settings shown again. The block says *Switching the theme reloads the pages*; a
  running scan blocks the switch.
- **Text size** — the control text size in points (menus, buttons, labels, fields, tooltips),
  8 to 32, default 13. It **applies at once** through gui-audio's `UIFontSize` and is restored at
  the next start before the unlock screen appears. The font family stays Roboto; size only.

## Decisions taken (the maintainer's, 2026-11-02)
1. Light, Dark and Darcula. Not IntelliJ, not the IntelliJ themes pack (not in the offline repository).
2. The theme switches **live, by rebuilding the pages** (route A). Panels read `UITokens` at
   build time and keep the colors in `setBackground`, so a `FlatLaf.updateUI()` alone would leave
   about 124 of them stale; a fresh `AppShell` on the same `AppContext` and session is the move
   the window already makes on login and logout. What a page held in memory is lost (an unsent
   chat draft, a dirty probe editor), which the block says; a running scan refuses the switch.
   Re-reading tokens per panel is the later pass, if ever.
3. Size only. No family choice, no View-menu Larger / Smaller in this pass.
4. Both values are per installation (`AppPrefs`), because they are about this screen and are
   needed on the unlock screen, before any login.

## Invariants (do not break)
- Every new control has a constant in `NSAppUtil.SettingsPage` and is rendered through
  `GUIUtil.applyProp`; no literal label, tooltip or note in the panel.
- Generic widgets stay in gui-audio: `UIFontSize` and `FontSizeWidget` already exist there and are
  used as they are; nothing font-related is written in no-sneak-app beyond the preference and the row.
- `UIFontSize.getBase()` must read 13 (the app's default), so *Reset* goes back to the look the
  app ships with. Startup therefore sets the Roboto 13 default font first and applies the saved
  size after it, never the other way round.
- The light theme must render pixel-identical to today when nothing is stored (before/after
  renders of the Scan, Library, Chat and Settings pages, diffed).

---

## Step 1 — Preferences (`no-sneak-app/ui/utility/AppPrefs.java`)
- `static final String THEME = "ui.theme"`, `UI_FONT_SIZE = "ui.font.size"`.
- `public enum Theme` **in `NSAppUtil`** (it is a UI descriptor like the rest, implementing
  `GetNameDescriptionDisplay`): `LIGHT("light", "Light", …)`, `DARK("dark", "Dark", …)`,
  `DARCULA("darcula", "Darcula", …)`, each carrying its FlatLaf class
  (`FlatLightLaf`, `FlatDarkLaf`, `FlatDarculaLaf`) and `setup()`; `static Theme of(String name)`
  → the constant for a stored name, `LIGHT` for null or unknown.
- `AppPrefs.theme()` → `NSAppUtil.Theme` (LIGHT when nothing stored); `theme(Theme)`.
- `AppPrefs.uiFontSize()` → `float`, `UI_FONT_SIZE_DEFAULT = 13f`, clamped by `UIFontSize.clamp`;
  `uiFontSize(float)`; `clampUiFontSize(float)` mirroring `clampAiTimeout`.

## Step 2 — Startup (`NoSneakMain.main`)
Today: `FlatRobotoFont.install(); registerCustomDefaultsSource("themes"); FlatLightLaf.setup();
UIManager.put("defaultFont", Roboto 13)`. After:
```java
FlatRobotoFont.install();
FlatLaf.registerCustomDefaultsSource("themes");
AppPrefs.theme().setup();                                   // FlatLightLaf / FlatDarkLaf / FlatDarculaLaf
UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));
SwingUtilities.invokeLater(() -> {
    UIFontSize.apply(AppPrefs.uiFontSize());               // base reads 13 here; a stored 13 is a no-op
    launchApp(…);
});
```
`UIFontSize.apply` runs on the EDT (its contract) and before any window exists, so the unlock
screen opens at the saved size with no flash.

## Step 3 — Theme files (`no-sneak-app/src/main/resources/themes/`)
FlatLaf loads `FlatLaf.properties` for every theme, `FlatLightLaf.properties` for the light cores,
`FlatDarkLaf.properties` for the dark cores (Dark **and** Darcula), then the theme's own file.
- `FlatLaf.properties` keeps the shared shapes and margins. Its `@accentColor` and
  `Component.borderColor=#E2E2E8` move to `FlatLightLaf.properties` (the border is light-only).
- `FlatLightLaf.properties` gains the seventeen **`xlogistx.*` token keys** with today's fallback
  values from `UITokens` (`xlogistx.accentSoft=#EEEEFB`, `xlogistx.ground=#F4F4F7`, …) so the light
  theme is pinned explicitly, not by fallback.
- New `FlatDarkLaf.properties`: the same seventeen keys in dark values (surfaces from
  `@background` lightened in steps, text from `@foreground`, ok / warn / danger as readable
  tints on dark with their *Soft* companions as low-alpha fills), `TitlePane.background=lighten(@background,5%)`.
- New `FlatDarculaLaf.properties`: only what Darcula needs over Dark (its own `@accentColor`, if any).
No code change in `UITokens`: its accessors already ask `UIManager` for `xlogistx.<name>` first.

## Step 4 — Fixed colors out of the panels
The panels that build a `Color` by hand, to be read in dark before the renders decide:
`ScanPanel` (6), `UnlockPanel` (2), `ScanFormPanel` (1), `NoSneakMain` (1); in ai-assistant
`AssistantUtil` (6), `ProvidersPanel` (4), `ChatHistoryPanel` (3), `SkillsPanel` (2),
`CapturePanel` (2), `ChatPanel` (1). Each becomes a `UITokens` accessor or a FlatLaf key
(`UIManager.getColor`). `RegionOverlay`'s six stay: the capture overlay is drawn over the screen,
not over the theme. The three hand-built monospaced fonts (`ScanPanel` 583, ai-assistant
`PanelSupport` 37, and the 12-point one in `ScanPanel`'s probe text) become `UITokens.mono(…)`
so they follow the size setting.

**gui-audio (io-xlogistx, same pass; `mvn -o -q -pl gui-audio install -DskipTests` before the
app sees it):** `ListSection` defaults its border to `UITokens.border()` instead of
`Color.LIGHT_GRAY` when the caller passes none (the Profile page's four sections do);
`MermaidRenderer` takes its palette from the tokens at render time (node fill `surfaceAlt`,
stroke `border`, text `text`, edge `muted`, edge-label background `ground`, page fill
`surface`) so a diagram in a chat reply is a dark card on a dark page. The four painters that
read tokens at paint time (Badge, Chip, HeaderBar, Stepper) need nothing; the 29 plain-Swing
classes need nothing.

## Step 5 — The Appearance block (`SubjectPanel.buildSettingsArea`)
`area.add(buildAppearance())` first, then a separator, then Sync as today. `buildAppearance()`:
- `title(APPEARANCE_TITLE)` and `note(APPEARANCE_NOTE)` like the Assistant block.
- Row **Theme**: label, a `JComboBox<NSAppUtil.Theme>` rendered by display name
  (`ComponentRef`-driven like the other enum combos), preselected from `AppPrefs.theme()`; a change
  stores it and hands it to the block's `Consumer<Theme>` (the assistant block's shape), which
  `AppFrame.applyTheme` serves on the EDT: `theme.setup()`, `FlatLaf.updateUI()`,
  `shell = new AppShell(ctx)`, `menuBar = shell.menuBar()`, `setContentPane(shell)`, then
  `ctx.nav().show(Screen.SETTINGS)`. The old shell is dropped; the session, the store and the
  MAC vendor table are untouched. While `shell.scanPanel().isScanning()` (new accessor over the
  `running` handle) the combo snaps back to the theme in force, nothing is stored and the row
  shows `THEME_BUSY` (*Finish or stop the scan first*); otherwise the row's note is `THEME_NOTE`
  (*Switching the theme reloads the pages*).
- Row **Text size**: label, gui-audio's `FontSizeWidget()` (application scope — it applies at
  once and follows a size set elsewhere), a *Reset* link button → `UIFontSize.reset()`. The size
  is stored on every change through `UIFontSize.addListener(AppPrefs::uiFontSize)`, registered
  once in `AppShell` (not in the block, which can be rebuilt) so a change from any future knob is
  remembered too.
- `NSAppUtil.SettingsPage` constants: `APPEARANCE_TITLE`, `APPEARANCE_NOTE`, `THEME_LABEL`,
  `THEME` (the combo, with the tooltip), `THEME_NOTE`, `THEME_BUSY`, `TEXT_SIZE_LABEL`, `TEXT_SIZE`
  (the widget), `TEXT_SIZE_RESET`; `PAGE`'s description gains "the look and text size".
  Rule of the convention: a label and its field never share a constant.

## Step 6 — Tests (headless)
- `AppPrefsAppearanceTest`: theme round trip and the fallback to LIGHT for null / unknown; size
  round trip, clamping to 8..32, default 13.
- `NSAppUtilTest` finds the new enum by reflection (nothing to add); `ScreenLabelsTest` if it
  lists Settings constants.
- `SettingsAppearanceBlockTest` (the `SettingsAssistantBlockTest` pattern): the combo lists the
  three themes in order with their display names, preselected from the stored one; selecting
  Dark stores `dark` and hands DARK to the consumer; with the busy supplier true it snaps back,
  stores nothing, calls nothing and shows the busy note; the widget's spinner at 15 makes
  `UIFontSize.get()` 15 and stores 15; Reset goes back to 13 and stores 13.
- `ScanPanel.isScanning()` true between the scan's start and its completion or Stop (the
  existing `ScanPanelTest` harness), false after `newScan`.
- Startup order pinned: `UIFontSize.getBase()` is 13 after the Step 2 sequence with a stored 15.
- Renders (scratchpad `RenderAll` + a `RenderDark`): Settings with the block in all three themes;
  Scan, Library, Chat, Unlock in Dark and Darcula read for any light patch; a shell built after
  `theme.setup()` + `FlatLaf.updateUI()` at panel level (the rebuild path, no frame headless);
  Light before/after diffed pixel-wise (`ImgDiff`) — must be identical with nothing stored.

## Step 7 — Docs (same day)
- `no-sneak-app/CLAUDE.md`: Settings page (the Appearance block, what applies when), `AppPrefs`
  list, startup order in the `NoSneakMain` paragraph, the themes resource folder and the
  `xlogistx.*` keys, the fixed-colors note.
- `ai-assistant/CLAUDE.md`: the colors moved to tokens.
- Root `CLAUDE.md` banner line; `app-description.md` (Help → Settings); `PENDING-ISSUES.md`
  (live checks: a switch to Dark and to Darcula with a chat open, a switch refused during a
  scan, a dark start, a size of 18 surviving a restart, Reset).
- This file's status line.

## Order & checkpoints
1. Step 1 + `AppPrefsAppearanceTest` → green.
2. Step 3 + Step 4 → `RenderDark` read, Light diff identical.
3. Step 2 + Step 5 + `SettingsAppearanceBlockTest` → app suite green; renders of the block in
   the three themes read.
4. Step 7.

## Out of scope (this pass)
A theme switch that keeps the pages' state (every panel re-reading its tokens); a font family
choice; View-menu Larger / Smaller shortcuts; following the operating system's dark mode; the
IntelliJ themes pack; per-account appearance in the store.
