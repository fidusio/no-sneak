# NoSneak

Assessment tooling for what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — with an AI assistant for making sense of the results.

## What it does

| Area | What you get |
|---|---|
| **Scanning** | Host liveness, open ports, service and version probes, and the TLS / PQC posture of every TLS endpoint, graded per host |
| **Host discovery** | ICMP / ARP / NDP sweeps of a segment you control; the MAC of each host and its vendor name |
| **Probes** | The bundled service probes and your own, one JSON file each, with the definition they follow |
| **AI assistant** | Chats with the providers you configure, fed with the scan reports, captures and skills you attach; switch provider inside a chat |
| **Account** | Your profile, your API keys, the reference data this installation keeps, and the store's backup |

## Opening the store and signing in

The first screen has two steps. **Step 1** opens or creates the store: pick the installation
directory and type its **vault password**. On a first run the same step creates the vault, the
encrypted database and the operator account; every input there carries a tooltip. **Keep the
vault password safe: it is not recoverable.** There is no reset and nobody who can retrieve it;
lose it and the vault, the database and everything they hold are gone for good. **Step 2** signs
you in, or registers a new account, with your own username and password — a different password
from the vault's. The header shows which store is open; the status bar at the bottom shows who is
signed in and the state of the MAC vendor list.

## Where things live

Every page is in the sidebar on the left; the **View** menu lists the same pages. Rest the
pointer on a sidebar item or a menu entry for a line on what the page is for; every button,
option, filter segment and tab carries the same kind of tooltip.

### Scan

- **Scan** — targets, ports, a name, the options (*Service detection*, *Host discovery only*,
  *Skip ping*, *Live hosts only*, *Open ports only*), a timing segment T0 to T5 (each says what
  it sets when you rest the pointer on it), the probe chips and the **command** they all build.
  The command is the truth: edit it and the form follows; change the form and the command is
  reprinted. *Host discovery only* and *Ports* are exclusive — the last one you touched wins,
  and a note under the command says when typed ports are not scanned.
- **Probes are the chips.** *Add probe* ticks bundled and your own probes into the run; a chip's
  × removes it. **No chip means no probing** — the scan then reports open ports only. The
  *Service detection* box is the shortcut: ticking it with no chips selects every probe,
  unticking it clears them.
- **The result** sits under the form: the counts (hosts up, open ports, TLS endpoints, PQC
  ready), then a **Hosts** tab — address, hostname, **MAC**, **vendor**, status, open ports,
  services, the worst TLS endpoint's version and key exchange, and the posture letter — with a
  detail pane per host (its ports, the TLS facts, a *Network adapter* block with MAC and vendor,
  and the verdict in words), a **Services** tab with every open port, and the **Raw JSON**.
  *Copy* takes the JSON, the text icon beside it the command the scan ran with, *Send to
  assistant* attaches the report to the open chat, *Scan again* puts the command back in the
  form. *Stop* ends a running scan and keeps the partial report, marked as not saved.
- **Scan History** — every report you ran, kept under your account, newest first, with a search
  over every column. Select a row to **View**, **Scan again**, copy its command or result,
  **Send to assistant**, or **Delete** it; select several rows to delete them together, or
  **Delete all** to clear the list after one confirmation.
- **Probe Library** — every probe, bundled and yours, in one table (name, service, ports,
  transport, priority, source); **All**, **Bundled** and **Mine** filter it, the search box
  matches name, service, description or an exact port. Select a row to read its facts and its
  JSON in full. Three ways to add one: **Copy to my probes** a bundled one and change it, write
  one by hand with **New probe** against the *Probe definition* shown in the app (the editor's
  *Check* says whether it is valid and what it would probe), or **Write with the assistant** —
  name the service and port, the definition is attached and the request typed for you, and the
  reply carries a **Save as probe** button. A probe of yours with a bundled name replaces that
  probe in your scans.

### Assistant

- **Chat** — the list of your chats is the page: open one to continue it, or **New chat** by
  naming it and picking the provider and model. Inside a chat:
  - the **Provider** box switches the assistant for the next message — the chat is rebound,
    the model list refilled with that provider's models, and the transcript stays; every reply
    says which **provider · model** answered it, so a chat that changed hands stays readable;
  - the **Model** box is a filter as well as a list: type to narrow it (`mini` matches
    anywhere, `gpt*` is a pattern, `!mini` excludes, `*` shows everything the provider
    discovered, audio and embedding models included);
  - **Send history** sends the whole conversation with each message, unticked only the new
    message goes; **Auto-copy code** puts the fenced code of every reply on the clipboard;
  - the **+** button attaches to the next message: skills (an *md* skill goes with the message,
    a *prompt* skill is pasted into the composer), images from disk, and the **capture areas**
    to shoot when you press Send; what is attached shows as chips above the input box, each
    removable from its ×;
  - a report sent from the scanner shows in full at the end of the transcript with a *Delete*
    until it is sent;
  - the **copy icon** on a past prompt puts its text back in the composer to send it again,
    the **×** inside the input box empties the prompt;
  - every reply has *Copy*, a *PDF* button, **Save as skill** and **Save as probe**;
    **Chat as PDF** in the head prints the whole conversation, attachments included;
  - **Edit** renames the chat or rebinds its provider and model; **All chats** returns to the
    list.
- **Capture** — **Define area** drags out a region of the screen (on any monitor; Esc cancels)
  and keeps it as a named area for the session; **Capture (N)** shoots every area at once and
  keeps the captures under your account. The **Hide window** box beside it decides whether the
  application disappears while an area is drawn or shot: ticked, the application hides so it
  never ends up in the picture; unticked, it stays on screen, so you can draw an area over it
  and capture the application itself. Rename, redraw or remove an area; open a capture, send it
  to the chat, rename or delete it, or **Delete all**.
- **Skills** — instructions the assistant can carry into a chat, written in markdown with a live
  preview; a reply can be saved as one with **Save as skill**.
- **Providers** — which of your API keys the assistant may use, each as a provider with a type,
  a base URL and a default model; one key can back several providers. **Add provider** picks a
  key or creates one, and adding it discovers its models. Removing a provider never deletes the
  key.

### Account

- **Profile** — name and date of birth, the identifiers you sign in with, and your addresses.
- **API Keys** — your password, and the third-party keys the assistant borrows (import, edit,
  delete). The assistant holds none of its own. *Copy* on a key's secret clears the clipboard
  again a minute later.
- **Settings** — *Sync* refreshes the MAC vendor list (the Wireshark manufacturer file,
  downloaded once at the first sign-in; the status bar shows its state); *Backup* writes the
  whole store to a zip archive and *Restore* reads one back — a backup carries your scan
  reports, which describe your network's layout, so keep it as safe as the store.
- **Access Control** — subjects, permissions, roles and grants; shown to the super-admin only.

## What it will and won't do

It looks, and it reports: TLS handshakes, certificates, service banners, host liveness. It does
not break into anything — no exploiting what it finds, no password guessing, no flooding a target,
nothing built to hide from a log. Traffic leaves under this machine's own address. Point it at
endpoints you own, administer, or have permission to test.

## Your data stays yours

Everything is kept in a local **encrypted H2 store** that is opened with your own credentials,
and every scan report, chat, capture, skill and probe is kept under your account alone. The
assistant holds no keys of its own — it borrows the ones you added under API Keys — and nothing
leaves the machine that you did not attach to a message: a report, a capture or a file crosses to
a provider only when you send it, under your own key. Sign out and nothing of yours stays on
screen.
