# NoSneak

Assessment tooling for what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — with an AI assistant for making sense of the results.

## What it does

| Area | What you get |
|---|---|
| **Scanning** | Host liveness, open ports, service and version probes, and the TLS / PQC posture of every TLS endpoint, graded per host |
| **Host discovery** | ICMP / ARP / NDP sweeps of a segment you control; the MAC of each host and its vendor name |
| **Probes** | The bundled service probes and your own, one JSON file each, with the definition they follow |
| **AI assistant** | Chats with a provider you configure, fed with the scan reports, captures and skills you attach |
| **Account** | Your profile, your API keys, the reference data this installation keeps, and the store's backup |

## Where things live

Every page is in the sidebar on the left; the **View** menu lists the same pages. Rest the
pointer on a sidebar item or a menu entry for a line on what the page is for; every button,
option, filter segment and tab carries the same kind of tooltip.

- **Scan** — targets, ports, options and the command they build; the result below it: a Hosts
  tab (address, MAC, vendor, status, open ports, services, TLS and PQC readiness, with a detail
  pane per host), a Services tab and the raw JSON. The timing segments T0 to T5 say what each
  one sets when you rest the pointer on them. *Send to assistant* attaches the report to the
  open chat.
- **Scan History** — every report you ran, kept under your account: open one, send it to the
  assistant, scan it again, or delete it.
- **Probe Library** — the bundled probes and yours, readable in full; All, Bundled and Mine filter
  the list. Copy a bundled one and
  change it, write one by hand against the *Probe definition*, or ask the assistant to write it:
  the reply carries a *Save as probe* button.
- **Chat** — your chats with the assistant. The list is the page: open a chat to continue it,
  or start a new one by naming it and picking the provider and model. In a chat, the **+** button
  attaches skills, images, files, URLs and screen areas to the next message; *Chat as PDF*
  prints the whole conversation.
- **Capture** — draw areas on the screen and shoot them all at once; the captures are kept
  under your account and can be sent to the chat.
- **Skills** — instructions the assistant can carry into a chat: an *md* skill goes with the
  message, a *prompt* skill is pasted into the composer. A reply can be saved as a skill.
- **Providers** — which of your API keys the assistant may use, each as a provider with a base
  URL and a default model; adding one discovers its models.
- **Profile** — name, identifiers and addresses.
- **API Keys** — your password and the third-party keys (import or generate, edit, rotate,
  delete). The assistant borrows these; it holds none of its own.
- **Settings** — *Sync* refreshes the MAC vendor list (the Wireshark manufacturer file,
  downloaded once at the first sign-in); *Backup* and *Restore* export and import the store.
- **Access Control** — subjects, permissions, roles and grants; shown to the super-admin only.

## What it will and won't do

It looks, and it reports: TLS handshakes, certificates, service banners, host liveness. It does
not break into anything — no exploiting what it finds, no password guessing, no flooding a target.
Traffic leaves under this machine's own address. Point it at endpoints you own, administer, or
have permission to test.

## Your data stays yours

Everything is kept in a local **encrypted H2 store** that is opened with your own credentials,
and every scan report, chat, capture and skill is kept under your account alone. The assistant
holds no keys of its own — it borrows the ones you added under API Keys — and nothing leaves the
machine that you did not attach to a message.
