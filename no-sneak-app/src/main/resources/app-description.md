# NoSneak

Security tooling for assessing what a network endpoint exposes — TLS posture, **post-quantum
readiness**, and running services — with an AI assistant layer for making sense of the results.

## What it does

| Area | What you get |
|---|---|
| **Scanning** | TLS/PQC posture and protocol probes against a host or endpoint |
| **Host discovery** | ICMP / ARP / NDP sweeps of the local network |
| **PQC file sharing** | A registry of public keys and the documents shared under them |
| **AI assistant** | Send your own scan data to a provider you configure, and compare answers |
| **Credentials** | Your subject profile, identifiers, addresses, and API keys |

## Where things live

- **File → Settings** — your account: profile, identifiers, addresses, and the full API-key
  lifecycle (import or generate, edit, rotate, delete).
- **Tools → Network scanner** — endpoint and local network scanning.
- **Tools → ACL Tool** — subjects, permissions, roles, role groups, and grants.
- **Tools → AI Assistant** — chats, skills, and the providers they run against.

## What it will and won't do

It looks, and it reports: TLS handshakes, certificates, service banners, host liveness. It does
not break into anything — no exploiting what it finds, no password guessing, no flooding a target.
Point it at endpoints you own, administer, or have permission to test.

## Your data stays yours

Everything is kept in a local **encrypted H2 store** that is opened with your own credentials.
The assistant holds no keys of its own — it borrows the ones you added under Settings, and
nothing leaves the machine that you did not attach to a message.