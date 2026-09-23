# no-sneak-core v2 — Plan of Action

> ## 2026-09-22 — `tls-connect` paid a reverse DNS lookup inside its own deadline (open item 3 closed)
>
> **Symptom (2026-09-20, PENDING-ISSUES item 3):** `https-scan` against 10.0.0.8 recorded
> `no-server-header` in 9.5 s where every other host took 5.0 s; the host was written up as
> "TLS-1.2-only", cause not investigated. Reproduced today: deterministic, 9.4–10.1 s, and the
> tail-only `https-version` probe fails outright on that host (`tls=NONE`, one 5 s timeout) under
> **both** SunJSSE and BCJSSE, while a plain blocking `SSLSocket` completes the same handshake and
> `GET` in 0.5 s. TLS 1.2 was a red herring; so was the provider.
>
> **Cause, from zoxweb's own driver logs with timestamps kept** (`SSLUtil`, `TCPSessionCallback`,
> `NIOSocket` loggers on, plus `-Djavax.net.debug=ssl:handshake`): TCP connected at t = 0, "SSL
> upgrade started" at t = 0, the ClientHello left at **t = 4.7 s**, the server's flight (22 KB —
> that host requests a client certificate and lists its CAs) was consumed to ServerKeyExchange by
> t = 5.09 s, and at t = 5.09 s the probe's own `arm()` deadline closed the engine (`Closing
> outbound of SSLEngine`, the close_notify then reads as `NEED_WRAP` to the worker one step from
> finishing). The 4.7 s is `SSLContextInfo.newInstance()` → `createSSLEngine(clientAddress
> .getHostName(), port)`: on an `InetSocketAddress` built from an IP literal, `getHostName()` is a
> **reverse DNS lookup**, and on this segment an address without a PTR record costs 4.6 s
> (measured: 10.0.0.8 4613 ms, 10.0.0.1 2566 ms → `XLOGISTX`, xlogistx.io 0 ms because the
> resolver stored the name on the address). Not a thread race — `NIOSocket` zeroes the key's
> interest before every dispatch and only the finishing worker restores it, exactly as the
> maintainer described; the first reading of the log (a second worker) was wrong and is withdrawn.
> The Bouncy Castle path never paid it: `ProbeContext` hands `PQCSessionConfig` an
> `InetSocketAddress.createUnresolved(hostname(), port)`, whose `getHostName()` is the string.
>
> **Fix (this repo):** `ProbeSecureCallback.namedAddress(host, port)` resolves once and pins the
> host string as the `InetAddress`'s name via `InetAddress.getByAddress(host, bytes)`, so the
> framework's `getHostName()` answers from memory for literals and names alike (SNI unchanged: a
> literal never was a valid server name, a name is kept); an unresolvable host yields the same
> unresolved address as before. `TlsConnectContextTest` +3: the production constructor's address
> for `192.0.2.1` (TEST-NET-1, never a PTR) resolves, names itself and answers `getHostName()`
> inside 1 s — the time bound *is* the pin; a name is kept; an unresolvable host stays unresolved.
> **Upstream, for the maintainer:** the one-line zoxweb fix is `clientAddress.getHostString()` in
> `SSLContextInfo.newInstance()` (line 436, zoxweb-core 2.4.0) — same value, no lookup, and it
> would cover every other client of that constructor. **Applied by the maintainer the same day**
> and verified against the rebuilt jar: `newInstance()` on an *unpinned* 10.0.0.8 address 4604 ms
> → 23 ms, 10.0.0.1 → 0 ms; suite 402 / 402; `https-scan` 10.0.0.8 4.4–4.7 s, xlogistx.io 4.1 s.
> The no-sneak pin stays — it costs nothing and guards the probe against any other caller of
> `getHostName()`.
>
> **The header `GET` is HTTP/1.1 now (maintainer's request, same day).** `https-scan` and
> `https-version` sent `GET / HTTP/1.0`; 1.0 had been chosen only for a self-delimiting response,
> which `Connection: close` already gives on 1.1, and 1.1 is what every real client sends — a
> front-end that treats a 1.0 request differently would have answered unrepresentatively. Both
> probes and the `PROBE-DEFINITION.md` recipe now send `GET / HTTP/1.1` with the same headers;
> the two `expect` patterns are unchanged (they match the header block, not the status line).
> Verified: xlogistx.io `https-server-header` (`NOYFB`) 1.9 s; dbs.xlogistx.io and
> lax-2.xlogistx.io `https-no-server-header` 1.9–2.0 s — genuine, a raw `curl` shows no `Server:`
> on either; 10.0.0.8 `https-scan` 4.6 s. Suite 402 / 402.
>
> **`/24 -sV` run and one banner fix (same day).** `10.0.0.0/24 -sV -T5 --min-rtt-timeout 200
> --max-inflight 4096 --up-only --open`: 254 targets, 20 up, **23.5 s** wall (the 2026-09-20
> `-sV` run was 68.9 s at `-T3`). Real identifications: eleven `OpenSSH_x`/`dropbear` versions,
> `Microsoft-IIS/10.0`, two VMware authentication daemons (902/912), `NOYFB` on the two xlogistx
> fronts, HTTPS posture on eight hosts (10.0.0.35's certificate `EXPIRED`), STARTTLS+PQC on the
> gateway's 25/tcp. The Web Shield was **on** for this run and it shows twice: the nine mail ports
> read `open` on every host as documented, and — new evidence — the shield's own proxy answered
> the banner grabs with `421 concurrent connection limit in Avast exceeded (processes:
> java.exe[100])`, so it also caps this process at 100 concurrent connections; that, plus the
> all-at-once candidate sweep (open item 2), is the likely reason the `ssh` probe lost on
> 10.0.0.170 during the scan while identifying `dropbear` every time on its own. Five
> `ClosedChannelException` traces on stderr are open item 1, unchanged. Report saved outside the
> repo. One defect it surfaced: dropbear sends its binary KEXINIT in the same read as
> `SSH-2.0-dropbear`, and `PortScanCallback.cleanBanner` stripped only the unprintable bytes, so
> the packet's printable fragments (algorithm names, key material) were glued onto the row. The
> rule is now *the greeting ends at the first binary byte* (CR/LF/TAB stay text); the old test
> that asserted a mid-greeting control byte is skipped over was asserting the defect and was
> rewritten. `PortScanCallbackTest` +1 (`cleanBannerEndsAtTheFirstBinaryByte`). Rescan of
> 10.0.0.170:22 → `ssh  dropbear`. Suite **403 / 403**.
>
> **The same `/24 -sV` with the shields off (same day, maintainer switched them off; a watcher
> fired the scan the moment xlogistx.io presented its Let's Encrypt chain and a printer's 25/tcp
> refused).** 254 targets, 19 up, **20.3 s**. The difference to the shields-on run is the whole
> antivirus footprint and nothing else: the nine mail ports are gone from every host but the
> gateway (10.0.0.1 keeps 25/465/993/995 — a real mail server, its 465 and 995 now grade **B** on
> a Let's-Encrypt chain, `TRUSTED`); every public chain reads `TRUSTED` with grade **A** (.1, .6,
> .8, .39, .45); .9 and .12 are `SELF_SIGNED`, .35 `EXPIRED`; `10.0.0.107` no longer answers ARP
> (19 up, was 20). One thing the shields-on run had **wrong that only the diff reveals**: the
> gateway's 25/tcp read `STARTTLS_UPGRADED pqc=PQC` — that was the Mail Shield's proxy completing
> a PQC-hybrid handshake with us, not the server, which negotiates classical and now reads
> `PQC_CAPABLE`. Rows that changed for a product reason: 10.0.0.170 → `ssh  dropbear` (the banner
> fix). Rows the sweep still lost under load: 10.0.0.9 (banner fallback, `OpenSSH_7.9p1`) and
> 10.0.0.12 (nothing) — both identify on every standalone run (`dropbear_2016.74`,
> `OpenSSH_7.9p1`, sweep and `ssh`-only alike), so this is open item 2 (all candidates at once
> vs. the daemon's unauthenticated-connection cap), now with a clean measurement: 2 of 13 SSH
> hosts missed with the shields off, 1 of 13 with them on. Four `ClosedChannelException` traces
> (item 1). Both reports are in the session scratchpad, not the repo.
>
> **Measured after, 10.0.0.8:** `https-version` 2.3–3.0 s ×5 (JVM start included), all
> `https-no-server-header; done`, complete — that server sends no `Server:` header at all, so the
> "missing" header was never recoverable; `https-scan` 4.8–5.3 s ×3 (was 9.4–10.1), grade A,
> `GOOD`/`crl`. xlogistx.io unchanged (`NOYFB`, 4.7 s). Suite **402 / 402 in 36 classes**.
>
> **Also seen, not chased:** (a) one CLI run and one `curl` on 10.0.0.8 stalled ~8 s in the
> handshake before any of this — that server occasionally sits on a ClientHello; (b) BCJSSE 1.0.24
> on a plain blocking `SSLSocket` times out against xlogistx.io's TLS 1.3 while SunJSSE completes
> it — the probe path is fine there under both, so it is only an observation.

> ## 2026-09-19 — Faster port + probe scan: adaptive connect timeout, probes streamed from the connect
>
> Two changes to `NMapScanner`, prompted by "how can we make the port and probe scan faster".
> Where the time went: a silently dropped port (host firewall) held its in-flight slot for the
> full `-t` (5 s) — 21 LAN hosts × 1024 ports sharing 256 slots — and identification could not
> start until the last of those had timed out on the last host.
>
> **Adaptive connect timeout.** `NMapScanner.connectTimeoutMs(hr, cfg)` = `RTT_MULTIPLIER` (10) ×
> the host's discovery RTT (`HostReport.latencyMs`, from ARP/ICMP), clamped between the new
> `--min-rtt-timeout <ms>` (`NMapConfig.minRttTimeoutMs`, default 500 — below that a lost SYN on
> Wi-Fi reads as filtered) and `-t` (still the ceiling). No measured RTT (`-Pn`, TCP-ping-only)
> keeps the full `-t`, as before. `PortScanCallback` gained a millisecond constructor; the
> second-based ones delegate to it. On a 10 ms segment a filtered port now costs 0.5 s, not 5.
>
> **Probes streamed from the connect callback.** The `ProbeChecker` is built in `scan()` before
> the first connect (cancel wired once there), and `scanHostPorts` launches a port's probe sweep
> the moment that port reports open — as a further child of the host's own barrier via the new
> `CountdownMonitor.addChild()` (register before the port's `childDone`, release the connect's gate
> slot, then launch, so the sweep never queues behind a slot the port still holds). A host is
> done when its ports *and* their probes are; `probeStage` now handles only the UDP ports that
> answered (no connect event to stream from). Still nothing blocks: `CountdownMonitor` is an atomic
> countdown whose last child runs the continuation, and `addChild` is the same primitive with a
> dynamic count. Pacing is unchanged — probe sockets still admit through the same `ScanGate`.
>
> Pinned: `CountdownMonitorTest` (4, new), `PortScanCallbackTest.aMillisecondDeadline…`,
> `NMapScannerTest.connectTimeout…` (3), `NMapParseCommandTest.minRttTimeout…`, and
> `NMapScannerEndToEndTest.anOpenPortIsProbedAsItConnectsNotAfterTheStage` — `-sV --probes ssh`
> against the loopback listener identifies the open port through the streamed path (the probe
> stage proper no longer touches TCP, so a non-null `probe` there is the proof). 108 tests across
> the seven touched classes green through IntelliJ. Live check on the `/24` is the maintainer's.
>
> **Later the same day — the gate was capped at 1000/s whatever the flag said.** The maintainer's
> `/24 --up-only --open` still took 136 s, so the gate was *measured* (`ScanGateThroughputTest`,
> new: no-op launches on the app's `TaskSchedulerProcessor`): **990 launches/s at the 2000/s
> default, and the same at `-T5`'s 10000/s.** Cause: zoxweb `RateController` paces in whole
> milliseconds rounded up, so every cap ≥ 1000/s is one launch per 1 ms slot — the class comment
> had said so and called it acceptable; on 21,500 connects it is a 22 s floor and made `-T4`/`-T5`
> no faster than `-T3`. Fix: `ScanGate` treats each pacer slot as a quantum of
> `maxPerSec × slotMs / 1000` launches (`perSlot()`: 2 at 2000/s, 10 at 10000/s, 1 at ≤ 1000/s),
> spent within the slot or lost — still leaky, still `RateController` TIME mode, never a token
> bucket. Measured after: 1992/s at 2000, 9888/s at 10000; the existing `ScanGateTest` contract
> (leaky, non-parking, held launch counts against the window, close runs it) unchanged. With the
> rate no longer the bottleneck, the in-flight window is (256 slots × a 500 ms filtered-port
> deadline = 512 timeouts/s): on a LAN use `-T4` (512 in flight, 5000/s, 3 s ceiling) or `-T5`.
>
> **And NIOSocket's own connect timeout was being left behind.** The maintainer asked whether the
> scanner knows about `NIOSocket.addClientSocket`'s built-in timeout — an `NIOChannelMonitor`
> appointment on the scheduler that closes the channel and delivers
> `exception(IOException("Connection timed out"))`. It did, half-way: the port scan passes
> `to + 2` so the monitor is a backstop behind the callback's own (now adaptive) deadline, and
> the probe path already released it (`ProbeContext.closeCurrent` → `transport.abort(key)` →
> `NIOSocket.abortClientSocket`). The port scan did **not**: `PortScanCallback.finish` closed the
> channel, which — as `abortClientSocket`'s own javadoc warns — does not cancel the appointment
> (only a successful connect does). Every filtered port therefore left a monitor in the scheduler
> for 7 s that later woke to close a closed channel and report a timeout nobody was listening for:
> ~21,000 of them on the `/24`. Fixed: `PortScanCallback.releaseWith(Runnable)` — the scanner
> hands in `() -> nio.abortClientSocket(key)` for both connect sites (discovery TCP-ping and the
> port scan), run exactly once on finish, or immediately if the probe finished inside
> `addClientSocket` (loopback). And `classify` now maps "timed out" to `FILTERED/timeout` rather
> than `error:IOException`, for the case where the monitor wins the race. Pinned:
> `PortScanCallbackTest` `nioSocketsConnectionTimedOutIsFilteredTimeout`,
> `theReleaserRunsExactlyOnceWhenTheProbeFinishes`, `aReleaserSetAfterAnInstantFinishRunsImmediately`.
>
> **2026-09-20 — measured on the maintainer's `/24`: 136 s → 39.8 s → 13.9 s.** The 39.8 s run
> (25 hosts up, ~23,300 filtered ports) also showed the same nine ports — 25 110 119 143 465 563
> 587 993 995 — "open" at 0 ms on *every* host, printer and dropbear routers included: the local
> antivirus mail shield completing the handshake before any packet left the box. With it disabled
> the run took 13.9 s and those ports vanished except on the gateway, which really runs JAMES.
> Not a scanner defect (a completed handshake *was* observed). An interception-pattern warning
> was proposed and **declined by the maintainer (2026-09-20): an antivirus issue, not a scanner
> one; heuristics keyed to whichever product is installed would add false positives, and the
> project is complex enough.** Do not reopen; the operator's remedy is to scan with the shield
> off or from another box. Last tail found in that run: four swept hosts (own address,
> passive-only neighbours) had no `latencyMs`, so each of their 1024 filtered ports waited the
> full ceiling; `inheritSegmentRtt` now gives an unmeasured on-link host the segment's measured
> RTT (`NMapScannerTest` ×3). First cut took the *slowest* measurement; the very next run showed
> why not — one Wi-Fi client answered ARP in 81 ms on a 9 ms segment and seven unmeasured hosts
> inherited an 810 ms deadline — so it is the upper median. Final figures on the maintainer's
> `/24`, 25 up, ~24,500 filtered ports: `-T5 --min-rtt-timeout 200` 8.25 s; plus
> `--max-inflight 4096` 6.17 s. Every host on that segment drops rather than resets (Windows
> Firewall stealth on the scanning box, ufw/IoT elsewhere), so nearly every port pays the full
> deadline; a segment that resets closed ports would finish in ~3 s.
>
> **Rename (2026-09-20, maintainer's request): `runtime.ParallelJoin` → `runtime.CountdownMonitor`.**
> The old name read as a thread join and prompted "is it fully async?"; the class is an atomic
> countdown whose last child runs the continuation, and now says so. IntelliJ rename refactoring,
> 95 usages; `ParallelJoinTest` → `CountdownMonitorTest`; docs and comments swept. No behaviour change.
>
> **First `-sV` run on the /24 (2026-09-20, 68.9 s, default -T3) — two defects, one design question.**
> (1) *Streamed probes were starved.* Every probe's `duration-ms` was 30–58 s while its port had
> connected in 0–3 ms: probe starts were admitted through the gate's single FIFO queue, behind
> ~20,000 not-yet-launched port connects, so identification began only as the port stage drained.
> Fix: `ConnectionGate.submitFirst` (default = `submit`) and a priority lane in `ScanGate`,
> drained before the plain queue under the same window and pacer; `GatedProbeTransport.Registry
> .start` admits candidate starts on it. `ScanGateTest.aPriorityLaunchTakesTheNextSlotAheadOfTheQueue`.
> (2) *SSH read as PostgreSQL* on 10.0.0.8 and .12: `postgres-db` expected `^S`/`^N` for the
> one-byte SSLRequest answer, and an SSH banner starts with `S`; it then failed the TLS handshake
> and still reached `done` via `recordTlsFailed` with `success: true`. Fixed in the JSON: `^S$`/`^N$`
> (the reply is exactly one byte), and a failed handshake is `fail`, never an identification.
> (3) *Open:* the tier-1 `ssh` probe must have failed on those two hosts for the tier-2 fallback
> to win at all, while the port scan's own banner grab succeeded. Every candidate is launched at
> once — ~18 simultaneous connections to one sshd, plus the banner grab — and OpenSSH's
> `MaxStartups 10:30:100` drops connections at random past ten unauthenticated ones. Candidate
> for the maintainer: run tier 2 only if tier 1 yields nothing (fewer connections per service,
> deterministic on SSH; costs one round of timeouts on a service on a non-standard port).
>
> **Single-host discovery no longer waits for its slowest unit (2026-09-20).** `10.0.0.1 -p
> T:53,U:53 -sV` took 7.9 s in the app. Per-host discovery (the path every non-CIDR target takes)
> ran ARP, ICMP and five TCP-pings and handed the verdict on only when the *last* unit reported —
> so a gateway that answered ARP in 8 ms still waited the full `-t` for the one discovery port it
> silently drops (3389). `discoverHost` now decides at the first positive from any unit, aborts the
> outstanding TCP-pings to free their slots, and lets the rest drain; a down verdict still needs
> every unit to give up. Measured after, same host: no probes 1.25 s; `-sV` 6.8 s; `-sV -t 2`
> 3.3 s; `-p U:53 -sV` 0.75 s. The remaining `-sV` cost is one full `-t` for **53/tcp**: no tier-1
> TCP probe declares port 53, so every fallback candidate connects and waits its `expect` timeout
> before "none identified" — the inherent price of match-first-with-fallback on a port nothing
> matches (nmap pays the same). `-t 2` on a LAN halves it; the tier-2-only-after-tier-1 question
> above would not change this case, since there is no tier 1 to succeed.
>
> **`https-scan` now reads the `Server:` header too (2026-09-20, maintainer's request).** After
> `enumerate-groups` the probe opens a JSSE session (`tls-connect`, a fresh connection index),
> sends `GET / HTTP/1.0` and captures `Server:` as `service-version` — the same three states
> `https-version` is made of. Every failure on that tail (`tls-connect` error/timeout, send error,
> no header, `nomatch`, `timeout`) lands on `recordNoServer` (`https-scan; no-server-header`), so
> the TLS/PQC posture already gathered is always delivered and the header is a bonus, never a
> gate. Priority and `portScoped` unchanged, so the election is unchanged; `https-version` stays
> bundled for ports where only the header is wanted.
>
> **Gated probes never ran the network revocation check (2026-09-20).** Comparing the app's
> `https-scan` of xlogistx.io (`revocation-status: UNKNOWN`, method `none`) with the direct
> `ProbeChecker` run minutes apart (`GOOD` via `crl`) exposed it: `GatedProbeTransport.Registry
> .create(NIOSocket, …)` routed through the socket-less seam constructor, so `ProbeContext.httpNio()`
> had nothing to wrap and `NetworkRevocationChecker` answered "no HTTP transport available". Every
> scanner and app probe since P14 (2026-09-11) skipped OCSP/CRL this way; only the ungated CLI ran
> it, which is where P14 was verified. Fix: a `ProbeContext(ProbeTransport, NIOSocket, …)`
> constructor that keeps the socket (HTTP client still built lazily, only by `revocation-check`),
> used by the registry's production `create`; the scripted seam stays socket-less by design.
> `GatedContextRevocationTest` (3) pins both production constructors to a usable client and the
> seam to none. Live after the fix: `NMap xlogistx.io -p 443 -sV --probes https-scan` →
> `revocation-status: GOOD`, `revocation-method: crl`, grade A, 4.0 s (was `UNKNOWN`/`none`
> minutes earlier on the same host). Suite 399 / 399.
>
> **BCJSSE workaround removed (2026-09-20, maintainer's request).** P23's pin —
> `ProbeSecureCallback` minting the `tls-connect` engine from `SunJSSE` by name because the
> published `bctls-jdk18on` 1.86 could not create an `SSLEngine` on JDK ≥ 9 — is gone, along with
> its canary `BcjsseEngineCreationTest`, which fired today on the local repository's `bctls` 1.85
> (a full-suite run: 396 found, 395 green, the canary the one red). `tlsContext()` now takes the
> JCA's default `"TLS"` provider, BCJSSE under `SecUtil`'s registration. Replacement pin:
> `TlsConnectContextTest` (2) — the default context mints a client engine in both trust modes and
> names the provider on failure, so a broken jar is recognised at once rather than half-way through
> a probe. Live gate passed the same day: `ProbeChecker xlogistx.io 443 --all https-version.json`
> through the default provider → `service-version: NOYFB` (the `Server:` header), TLSv1.3,
> `TLS_CHACHA20_POLY1305_SHA256`, complete, 921 ms. Full suite after removal: **395 / 395 green**.
>
> ## 2026-09-19 — `--up-only`: list only live hosts, keep the range counts
>
> Prompted by a `10.0.0.0/24 -sn` run in the app: 254 host entries, 233 of them
> `"up": false, "reason": "no-response"`, around the 21 that mattered. The scan was right — the
> JSON lists every target the way nmap's XML does — but nothing let a reader ask for the live
> ones. `--up-only` (`NMapConfig.upOnly`) is the host-level twin of `--open`: a rendering
> preference, honoured by **one rule for all five formatters**, `ScanReport.hostsToRender()`.
> The run-level counts (`targets` / `up` / `hostsDown`, XML `<hosts up down total/>`, the Normal
> "N target(s), M up" line) are deliberately *not* filtered, so "233 silent" stays
> distinguishable from "233 never scanned". The Normal summary stats and the XML `scaninfo` port
> union still iterate every host, since they are aggregates. Pinned by
> `FormattersTest.upOnlyListsOnlyLiveHostsButTheCountsStillCoverTheRange` and
> `NMapParseCommandTest.upOnlyFlagIsRecorded`; both classes green through IntelliJ (20 + 46).
> In the app the flag is typed into the command box like any other.
>
> ## 2026-09-12 — C1 closed: `DMTool` has no datastore default
>
> The stale `mongodb://localhost:27017/xlog_datastore_test?replicaSet=rs0` constant is gone.
> `DMTool.resolveDbUrl` takes the first non-blank of `db-url=` (param), `NOSNEAK_DB_URL` (env),
> `nosneak.db.url` (system property) and otherwise throws, so the tool prints usage and exits
> without opening a connection to a database nobody chose. `tools/DMToolTest` (5) pins the
> order, the refusal message, and that no `mongodb://localhost` / `replicaSet=` literal returns
> to the source. Suite: 373 green.
>
> ## 2026-09-12 — MERGED: one generation, package `io.xlogistx.nosneak`
>
> The original packages (`nmap`, `probe`, `scanners`, `services`, `tools`), their five test files,
> the old `/probes/` resources and the orphan `services-categories-info.json` are deleted; every
> `v2` package collapsed one level (`io.xlogistx.nosneak.v2.x` → `io.xlogistx.nosneak.x`); bundled
> probes moved from `/v2/probes/` to `/probes/` (`ProbeDefinitionLoader.BUNDLED` updated); this
> file and `PROBE-CONFIG.md` moved from the source tree to the module root (the older authoring
> tutorial that held that name is now `PROBE-DEFINITION.md`, extended the same day with the deep-TLS actions and budgets, scrubbed of implementation references, and pinned to the code by `model/ProbeDefinitionGuideTest`: every JSON example loads through the real loader, §8's action list equals `KNOWN_ACTIONS`, §3's field table equals `ProbeState`'s fields); `NoSneakNIOHTTPServer` (the
> config-driven server harness) moved to the test root package; `http_server_config.json` names
> `io.xlogistx.nosneak.service.Checker`; `no-sneak-app` imports retargeted. Verified: whole repo
> `mvn -o clean test-compile` green, 365/365 tests under the new package, `ProbeChecker` and `NMap`
> CLIs live. Entries below this one use the pre-merge `v2/…` paths.
>
> ## 2026-09-12 — TLS/PQC parity pass: the v1 scanner's edges are back, in v2's shape
>
> `V1-V2-MERGE-ANALYSIS.md` §1.2/§4 found nine TLS/PQC regressions against `scanners/`. All closed:
> a malformed OCSP staple now **falls through** to the active OCSP/CRL check; `pqc-status` regained
> v1's three-way split (`PQC` / `CLASSICAL` = TLS 1.3 upgradeable / `NOT_READY` = ≤ TLS 1.2, via
> `ProbeContext.classifyPqc`); `enumerate-versions`/`enumerate-ciphers`/`enumerate-groups` take
> per-state toggles (`includeSSLv3`, `includeTLS10/11`, `includeWeak`, `includeInsecure`,
> `maxInFlight`, `rankServerPreference`) and a definition may declare `overallTimeoutSec`
> (`https-scan`/`tls-scan`: 90 s); `Grade` carries v1's remediation wording; `ProbeResult` has
> `success`/`error-message` and per-suite `authentication`/`encryption`/`mac`; a CRL with no
> presented issuer is `UNKNOWN`, never GOOD; enumeration children run through
> `Fanout.runBounded` (8 in flight per context) and the REST `Checker` paces its sweep through a
> `ScanGate` and counts `total-scanned` from `start-count-at` again. Optional v1 cipher **ranking**
> is back behind `rankServerPreference` (bounded, sequential). New pure tests drive every
> enumeration and revocation path through `ScriptedTransport` seams (`TlsEnumerationContextTest`,
> `TlsAnalysisContextTest`, `NetworkRevocationCheckerTest`). v2 suite: 365 green.
>
> ## 2026-09-12 — nmap parity pass: every v1-only scanner feature closed in v2
>
> `V1-V2-MERGE-ANALYSIS.md` §1.3/§4 listed what `nmap/**` still had over `v2/nmap/**`. All of it
> is now in v2, in v2's style (gate-paced units, injected scheduler, no blocking), so the v1
> package can be deleted at merge without losing scanner behaviour:
>
> - **Down hosts render** in Normal (`Host <t> is down (<reason>)`) and CSV (one row, port
>   columns blank). XML/Grepable/JSON already had them.
> - **Target grammar**: per-octet ranges (`192.168.1-5.1-254`, any octet `n` or `a-b`, reversed
>   bounds normalised) and comma-separated lists inside one token; expansion beyond
>   `NMapScanner.MAX_EXPANSION` (65536) is cut short **with a warning on the report**
>   (`expand(targets, warnings)`), never silently.
> - **CLI aliases**: `--timeout`, attached `-p22,80`, `-sP`, `-PN`, `-h/--help/-?` (usage, exit 0;
>   `NMap.HelpRequested` is an `IllegalArgumentException` whose message is the usage text, so the
>   app's command box shows it unchanged), `-v/--verbose`, `--max-parallelism`/`-P N`,
>   `-T <n|name>` / `-T4` / `-Taggressive` (paranoid…insane = T0…T5), and v1's `host=`, `range=a,b`,
>   `timeout=` tokens. Unknown flags are still refused. `-v` adds a run header and per-host
>   scanned-port counts to Normal; **warnings print regardless** — a degraded discovery mode is
>   never hidden behind a flag.
> - **Port spec dedupes** (first-seen order): `-p 80,80` scans 80 once.
> - **Default ports are 1–1024** (v1's default; `--top-ports` remains the cheap alternative).
>   `ScanPanel` builds its config through `NMap.parseCommand`, so a typed command without `-p`
>   now scans 1024 ports per host and `maxWaitMs` grows with it — no code there depends on the
>   old 20-port list.
> - **XML metadata**: `<!DOCTYPE nmaprun>`, `scanner="nosneak"`, `args`/`start`/`startstr`/`version`,
>   `<scaninfo type="connect" protocol="tcp" numservices services>` (+ a `udp` one when UDP ports
>   were named), host `starttime`/`endtime`, `<hostnames><hostname type="PTR"/>`, `<runstats>`
>   with `finished time/timestr/elapsed/summary` and `hosts up/down/total`. **Grepable** has the
>   `# … scan initiated <date> as: <args>` header, the `# NoSneak done at …` footer and
>   `Host: <ip> (<hostname>)`. **JSON** adds `startTime`/`endTime` (ISO-8601 UTC), `durationSec`,
>   `hostsDown`, per-host `startTime`/`endTime` and `portStats {open, closed, filtered}`.
> - **`HostReport.ip` on every path**: set at expansion for IP literals, and from the first
>   `PortScanCallback` built for a hostname (`remoteIp()`), so `-Pn` reports carry the address.
> - **Reverse DNS, non-blocking**: `ReverseDnsCallback` (a `UDPSessionCallback`, one PTR
>   datagram per host through the `ScanGate`, deadline on the injected scheduler, dnsjava for the
>   wire format) fills `HostReport.hostname`. Stage 0b between discovery and the port scan; `-n`
>   never, `-R` every target, default live hosts only; `--dns-servers <ip>` overrides the system
>   resolver (fallback `8.8.8.8`). `InetAddress.getHostName()` is not used anywhere.
> - **Dead fields removed**: `HostReport.osGuess/osAccuracy` and `PortReport.ttl` (never assigned;
>   OS detection is refused, a connect scan has no TTL) and their formatter branches.
> - **One service table**: `WellKnownPorts` gained v1's `1521/tcp oracle` and `520/udp route`;
>   `ProbeChecker`'s private 18-entry map is gone and its fallback label reads
>   `WellKnownPorts.lookup(port, transport)` (null when unknown, transport-aware).
> - **Formatter API**: `OutputFormatter.formatTo(report, OutputStream)` (UTF-8) and `mimeType()`;
>   `NMap.main` writes files through `formatTo`.
> - **Cleanups**: the 4-arg `NMapScanner.buildChecker` and `NMapScanner.log` are deleted.
> - **Tests** (`v2/nmap`): `FormattersTest` (down hosts, metadata, JSON extras, mime/formatTo),
>   `NMapParseCommandTest` (every alias, dedupe, defaults, `-n/-R/--dns-servers`),
>   `NMapScannerTest` (per-octet, commas, cap warning, IP literals, table entries),
>   `ReverseDnsCallbackTest` (hand-built PTR replies through the ingress hook, `ManualScheduler`
>   deadline), and `NMapScannerEndToEndTest` — the one nmap test that owns pools and a real
>   `NIOSocket`, scanning a loopback listener (`-Pn -n`): open port with banner, refused port
>   closed, all five formats render.

> ## 2026-07-29 — no-sneak-net discovery, pool injection, async REST, defect pass
>
> **1. nmap host discovery now goes through `no-sneak-net`.** An **on-link CIDR** is handed to
> **`HostScanner.sweep()`** — that module's purpose-built range sweep (ARP + ICMP per host, on-link
> interface chosen for you, `HostRecord`s streamed, its own tuned pacing: 256 in flight, 1 s
> per-host timeout, a single ping probe because ARP is the liveness oracle). Everything else —
> hostnames, off-link IPs, dash-ranges — keeps a per-host path (TCP-ping + `ping` + `resolve`),
> since ARP cannot apply beyond the segment. Either way **`HostReport.mac` is populated**, closing
> the old "no JDK API exposes a remote MAC" deferral rather than working around it. The session is
> opened once per scan, borrows the injected pools, and degrades honestly — no Npcap/root still
> yields a usable session with the lost capability recorded in `ScanReport.warnings`.
> New flags `-PR` / `-PE` / `--no-arp` / `--no-tcp-ping` / `--icmp-probes N`, and every run now ends
> with a `NMap done: … host(s) up … in N.NN seconds` stats line.
> Verified live: `10.0.0.0/24` → 254 targets, **22 up, all 22 with a MAC, in 1.6 s**.
>
> > **The 25× lesson.** First implementation hand-rolled the sweep out of per-host `resolve`/`ping`
> > calls plus five TCP-connects: **55 s** for the identical result, because it used a 3 s resolve
> > timeout instead of 1 s, 2 ping probes instead of 1, a quarter of the intended concurrency, and
> > TCP-connects that on-link tell you nothing ARP has not already answered. Forwarding
> > `--max-inflight` into `SweepOptions` made it worse still (a `/24` did not finish in 100 s) —
> > that flag caps concurrent TCP connections in the *port-scan* stage, not the sweep's packet
> > window. **When `no-sneak-net` offers a primitive, use it; do not rebuild it from its
> > lower-level calls.**
>
> **2. The executor and scheduler are injected, not looked up.** Every v2 class takes them from the
> `NIOSocket` it rides on (`getExecutor()` / `getScheduler()`) or as an explicit constructor
> argument — `ProbeContext`, `Fanout.run`/`dispatch`, `Version`/`CipherProbeCallback`,
> `ProbeUDPCallback`, `RateLimiter`, `PortScanCallback`. `TaskUtil.default*` survives only in the
> composition roots that own the process: the `ProbeChecker` and `NMap` CLI `main` methods and
> `Checker.checkQDZDirect`. It is now structurally impossible to arm a timeout on one pool while
> the I/O it guards runs on another.
>
> **3. REST `/check-qdz` is fully asynchronous.** It blocked on `checkBlocking` → `future.get` from
> a thread belonging to the very pool the sweep needs (`NIOHTTPServer` builds its `NIOSocket` on
> `TaskUtil.defaultTaskProcessor()` and dispatches request data to it, while `Fanout.dispatch`
> publishes candidate starts onto the same one) — enough concurrent requests and no worker was left
> to run the probes. The handler now returns `Boolean.FALSE` so the server writes no response,
> **and** installs a `ProtoSession` whose `canClose()` stays false until the response is written;
> both halves are required. A scheduled backstop answers 504 if the sweep never calls back.
> **This endpoint had never been runtime-tested.** Now: `example.com:80` 123 ms, `google.com:443`
> 371 ms, `github.com:443` 1825 ms, and **24–32 concurrent requests all 200 on an 8-thread pool**.
> Keep-alive needs no special value — it bounds the *idle* gap between exchanges, not the time
> spent producing a response, so a 5.2 s scan answers fine under a 1 s keep-alive. Running it
> caught one defect nothing else would: `buildResponse(contentType, result, …)` re-serializes an
> already-rendered JSON document into a JSON *string*; use the status/headers-only overload.
>
> **4. `Checker.checkQDZDirect(String hostPort)`** runs the same check **server-free** (no
> `NIOHTTPServer`, no `ResourceManager`, no Shiro — just an `NIOSocket` it owns and closes), with
> `Checker.main` as a timing harness: google.com:443 4.5 s, example.com:443 4.5–4.8 s,
> example.com:80 0.8 s cold. Use it to embed or test the check, and to tell a scanner problem apart
> from a transport problem — isolating it this way is what localised (1)'s regression.
>
> **5. Defect pass**, each verified: cipher suites rendered as raw hex (`CIPHER_0x9d`) because the
> name table was a hand-written 11-entry switch — now reflected over Bouncy Castle's 328
> `CipherSuite` constants; `Grade`'s weak-cipher rule matched `_RSA_WITH` as a substring, capping
> every healthy `TLS_ECDHE_RSA_*` server at B while the static-RSA suites went unnamed and
> unflagged; `Grade` awarded **A** to any scan that never ran the version enumeration — a false
> clean bill of health for every shallow probe; `NMapScanner`'s catch blocks double-counted a scan
> unit (`NIOSocket.addClientSocket` delivers `exception()` to the callback *and* rethrows), firing
> the stage barrier early and rendering reports mid-scan; `RateLimiter.release` drove `inFlight`
> negative, after which `--max-inflight` could never trip again, and `drain()` recursed once per
> queued unit on synchronously-completing (loopback) launches. Also: nmap CLI no longer dies with
> an `ArrayIndexOutOfBoundsException` on a flag with no value, no longer exits 0 on failure, and
> `-p 1-2000000000` no longer looks like a hang. Tests **79 → 88**.
>
> **Testing note, learned the hard way:** do not benchmark against a port with nothing listening
> (e.g. `example.com:81`). The connect is black-holed rather than refused, so every candidate probe
> runs to its full timeout and the scan takes ~10 s — our own timeout budget, not a defect, and it
> makes a healthy endpoint look broken.
>
> **Build note:** the working tree's `no-sneak-core/pom.xml` added a `no-sneak-net` dependency with
> no version and nothing managing it, so Maven could not read the project at all; the root pom now
> manages it at `${project.version}`.

> **Status: ALL PHASES (0–10) DONE — v2 meets-or-exceeds v1, ready for the maintainer's merge.**
> Non-blocking on `NIOSocket` + trigger `StateMachine` (no `MonoStateMachine`); the executor and
> scheduler are injected from the `NIOSocket` rather than looked up (see the 2026-07-29 entry
> above). v1 untouched throughout. Of the deferrals this section originally listed, **nmap
> discovery and REST runtime testing are now done**; active OCSP and Mongo/DM-tool runtime testing
> remain. Detail below.
>
> **v2 test suite added (2026-07-26) — 79 tests, no network, all green.** Previously v2 had
> **zero** tests while the only four test classes in the module targeted v1, so the merge would
> have taken coverage to nothing. New pure suites under `src/test/java/io/xlogistx/nosneak/`:
> - `model/ProbeDefinitionLoaderTest` (16) — every bundled probe loads/validates, priority sort,
>   **filename ↔ probe-name** agreement, `KNOWN_ACTIONS` ↔ `ActionRegistry` drift check (an action
>   the validator accepts but the registry can't build would fail mid-scan, not at load),
>   portScoped invariants, `tls-scan`/`https-scan` priority contracts, five validator rejections,
>   pattern/capture model incl. ISO-8859-1 matching inside a binary payload.
> - `grade/GradeTest` (21) — trust-verdict precedence, T/F letters, hostname mismatch stays
>   report-only, soft `UNKNOWN` chain is not a failure, protocol/cipher posture, serialization.
> - `result/ProbeResultTest` (12) — note merging, fact dedupe, chain breakdown, and the
>   negative-fact serialization trap below.
> - `runtime/FanoutTest` (11) — join fires exactly once (incl. 64-thread contention and double
>   `childDone()`), fires at zero children, survives a throwing handler, and children genuinely
>   run **concurrently on distinct pool threads** (a serialised fan-out fails the test).
> - `nmap/NMapScannerTest` (19) — CIDR/range expansion (/30 usable-only, /31, /32, cross-octet,
>   reversed, dedupe, malformed-stays-literal), port specs, top-ports clamping, port-state
>   semantics.
>
> **Running them:** tests were believed "env-blocked"; they are not. Two real causes, both
> solvable: (1) the **parent pom** (`xlogistx-mvn`) sets `<skipTests>true</skipTests>` globally →
> pass `-DskipTests=false`; (2) Maven cannot reach central because the local **Avast TLS
> interception** breaks PKIX → point Maven at a trust store containing that root:
> `MAVEN_OPTS="-Djavax.net.ssl.trustStore=<cacerts+avast>.jks -Djavax.net.ssl.trustStorePassword=changeit"`.
> With those: `mvn -pl no-sneak-core test -DskipTests=false -Dtest='io.xlogistx.nosneak.**'` →
> 79/79. (v1's `ProbeDefinitionLoaderTest.bundledDefinitionsLoadAndValidate` fails on a stale
> BUNDLED assertion — left alone, v1 is being deleted.)
>
> **Two defects the suite caught:** (1) `postgres-db.json` declared `"name": "postgresql"` while
> every other probe's name matches its filename — and since `--probes` selects **by name**,
> `--probes postgres-db` matched nothing; renamed to `postgres-db`. (2) `NMapScanner.buildChecker`
> **silently fell back to all bundled probes** when no requested name matched, so a typo'd
> `--probes` scanned with everything instead of failing loudly; it now records an
> `unknown probe '<name>' (ignored)` warning per name plus a fallback warning on `ScanReport`.
>
> **Certificate-trust hardening ported from v1 (2026-07-26) — closes a merge regression.** The
> v1 cert-trust sprint (W1–W5c) lived only in `scanners/PQCScanResult` and would have been
> **deleted with v1**: v2 recorded just subject/issuer/not-before/not-after/validity/chain-trust.
> Now ported, keeping v2's facts-vs-rules split — facts on `ProbeResult`, verdict in
> `grade.Grade`:
> - `ProbeContext.recordCertFacts` → leaf key/signature analysis via
>   `OPSecUtil.analyzeCertificatePQC` (`cert-signature-type/-algorithm`, `cert-public-key-type/
>   -size`, `cert-signature-pqc`) **and** the RFC 6125 hostname check via
>   `OPSecUtil.matchesHostname` (`cert-hostname-match` + message). Both run on every cert-bearing
>   path (`pqc-check` *and* `tls-facts`), so even shallow `https-pqc` detection reports them —
>   v1 only produced them on a full scan.
> - `ProbeContext.validateCertChain` → `cert-chain-trust-message`, chain-wide
>   `cert-chain-time-validity`, and the per-certificate `cert-chain[]` breakdown with the
>   **PKIX-matched Root CA appended** (W5c: servers don't send it; skipped when the server already
>   terminated with a self-signed root).
> - `grade.Grade` → `TrustVerdict` (TRUSTED/EXPIRED/NOT_YET_VALID/UNTRUSTED_CHAIN/
>   CHAIN_TIME_INVALID/REVOKED/UNKNOWN) in v1's precedence + `reason()` + report-only
>   `advisories()`; a trust failure grades **T**, revocation **F**. Hostname mismatch stays
>   report-only per the v1 decision. `Grade.toNVGenericMap()` is merged into the REST `Checker`
>   response, so `/check-qdz` keeps v1's `trust-verdict`/`trust-reason` surface.
>
> Verified live against badssl: `expired` → `T/EXPIRED`, `self-signed` → `T/UNTRUSTED_CHAIN`,
> `wrong.host` → `cert-hostname-match: MISMATCH` with presented names (report-only, verdict
> unchanged), plus leaf key/signature facts on all. NOTE: this environment runs an **Avast
> TLS-intercepting proxy**, so every public chain re-signs to `CN=Avast Web/Mail Shield Root` and
> reads `UNTRUSTED_ROOT`. The positive path was therefore verified by pointing
> `javax.net.ssl.trustStore` at a JKS holding that root: example.com:443 → `trust=TRUSTED`,
> `cert-chain-time-validity: VALID`, and a 2-entry `cert-chain[]` whose appended
> `role:"root"` entry is the self-signed CA the server never sent — proving the W5c append.
>
> **Serialization defect found and fixed while verifying.** `GSONUtil.toJSONDefault` **omits
> default values**, so every `false` boolean and `0` int vanished from the JSON — including
> `cert-chain-time-valid:false` (the flag that reports an expired intermediate),
> `cert-hostname-valid:false`, `complete:false`, and a connection's `index:0`. Isolated with a
> minimal repro. Two-part fix: (1) the CLI now renders with
> `GSONUtil.toJSONGenericMap(m, true, true, false)` (include-defaults); (2) tri-state cert facts
> are emitted as explicit **strings** (`cert-chain-time-validity`, `cert-hostname-match`,
> `cert-signature-pqc`) so absence unambiguously means "not checked" even under a serializer we
> don't control — the REST path returns an `NVGenericMap` the HTTP framework serializes with its
> own settings, so strings are the only robust answer there. (v1 had the identical defect; it is
> not carried forward.)
>
> **Fix (HTTPS on nonstandard ports):** a plaintext HTTPS port (e.g. xlogistx.io:6443) was
> mis-identified as `http` because the plaintext `http` probe matched the server's "requires TLS"
> HTTP-400 error. Fixed two ways: (1) `https-version` priority 45→68 so the TLS probe is tried
> before the plaintext `http` probe in the fallback tier; (2) `http.json` now has an `istls` gate
> that fails on "requires TLS / plain HTTP sent to HTTPS / speaking plain HTTP to SSL" replies.
> Verified: 6443 → `https` in match-first and match-all; example.com:80 still `http`.
>
> **Fix (JSSE `tls-connect` TLS facts):** the `https-version` probe completed a full JSSE TLS
> handshake but reported `tls-state=NONE` (only the Bouncy-Castle path recorded TLS facts), so an
> HTTPS result read as `service=https tls=NONE`. Added `SSLSessionConfig.getSSLSession()` to
> zoxweb-core and `ProbeContext.recordSecureTlsFacts()`, invoked on secure-handshake completion:
> it sets `tls-state=DIRECT_TLS` and records the JSSE-negotiated `tls-version` / `cipher-suite`.
> PQC stays `UNKNOWN` on this path (JSSE does not surface the key-exchange group; the `https-scan`
> BC probe classifies PQC). Verified: xlogistx.io:6443 → `tls=DIRECT_TLS tls-version=TLSv1.3
> cipher=TLS_AES_256_GCM_SHA384`; example.com:80 still `tls=NONE`.
>
> **Investigation + fix (open-but-silent port → `checker-timeout`):** a full-run probe of
> `imap.gmail.com:143` returned `complete=false note=checker-timeout` after ~165s. A thread dump
> (`jstack`) plus a transition trace (ProbeEngine/ProbeContext loggers enabled) proved there is
> **no deadlock and no timeout bug** — a single probe fires its `arm()` timeout at exactly
> `timeoutSec` and delivers cleanly (`connect --connected--> banner`, then `banner --timeout-->
> fail` at +Ns). Root cause: on that host port 143 accepts the TCP connection but sends **no
> banner** in this environment (Avast MITM / transparent proxy), so tier-1 `imap-starttls-pqc`
> fails on a banner timeout and `ProbeChecker` then sweeps ~13 tier-2 fallback probes
> **sequentially**, each also waiting the full `timeoutSec` on the silent port; the cumulative
> time exceeded `maxWaitMs`, tripping the blocking backstop (`checker-timeout`). The genuine
> defect: match-first sized `maxWaitMs = (timeout*6+15)s` and **ignored candidate count**, while
> match-all already added `candidates*timeout`. Fixed `ProbeChecker.main` to size the match-first
> wait the same way, so an open-but-silent port now returns a clean, accurate
> `no-probe-identified; N probe(s) tried: ...` verdict instead of the misleading `checker-timeout`.
> Verified: `imap.gmail.com:143` → `no-probe-identified` (13 probes listed); example.com:443 →
> `https`, :80 → `http`, xlogistx.io:6443 → `https`, 127.0.0.1:27017 → `mongodb 7.0.21` all
> unchanged and fast.
>
> **Parallel candidate sweep + fast-path short-circuit (implemented):** `ProbeChecker` no longer
> runs candidates sequentially (`runFrom`/`runAll` removed). `check()` now launches every candidate
> concurrently (`FirstSweep`) and delivers the **highest-priority completed** result the instant no
> higher-priority candidate can still win — index `k` wins once indices `0..k-1` have all resolved
> incomplete and `k` completed; losers are torn down via a new `ProbeContext.cancel()` (idempotent
> teardown that never clobbers the winner). `checkAll()` (`AllSweep`) runs all concurrently and
> returns every completion. **Selection is identical to the old sequential priority sweep** — only
> latency (bounded by the winner, not the sum) and concurrency (one connection per candidate)
> change. Result-delivery is now ~winner time (example.com:80 http = 81ms) and an open-but-silent
> port resolves in ~`timeout` instead of `candidates*timeout` (imap.gmail.com:143: 165s → ~8s).
> A superseded `tls-connect` can keep its NIOSocket session-timeout pending up to `timeout`, which
> would make the CLI's busy-wait shutdown linger; `main` now `System.exit(0)`s once the result is
> printed (one-shot CLI — OS reclaims sockets). Verified: example.com:80/443, xlogistx.io:6443,
> 127.0.0.1:27017 all identify in ~1s; `--all` on :443 returns both https probes in ~8s (was
> ~`N*timeout`); imap:143 → clean `no-probe-identified` in ~8s.
>
> **Sweep runs on the native trigger-StateMachine parallel dispatch (not hand-rolled threads):**
> the candidate fan-out uses the same mechanism as the rest of v2 — a single `StateMachine`
> configured with an `Executor` supports `publishSync` (inline/sequential) and `publish`
> (executor-threaded/parallel) per call. `AllSweep` = `Fanout.run(children, onAllDone)` (parallel
> `publish` + `CountdownMonitor` barrier); `FirstSweep` constructs all contexts then launches their
> starts via `Fanout.dispatch(...)` (barrier-free parallel `publish`) with the match-first election
> kept as a small `synchronized` block — the one genuine correctness necessity (concurrent
> completions race to elect the highest-priority winner; the mandated multi-threaded
> `defaultTaskProcessor` means `publishSync` can't serialize them). Deep-analysis-verified against
> zoxweb `StateMachine`/`TriggerConsumerHolder`/`CountdownMonitor` sources; results are deterministic
> across repeats (443→https/PQC, 80→http, 27017→mongodb every time).
>
> **Superseded-probe connection reclamation (embedded path fixed):** empirically (logs + polling
> `defaultTaskScheduler().pendingTasks()`) a match-first winner left ~2 scheduler tasks pending for
> the full `timeout` after delivery — the `NIOChannelMonitor` connect-timeout appointments of
> loser probes cancelled *before* their TCP connect completed (`finishConnecting` only cancels that
> appointment on a successful connect; `ctx.cancel()` closed the channel but not the appointment).
> Added **`NIOSocket.abortClientSocket(SelectionKey)`**; `ProbeContext` now captures the
> `SelectionKey` from `addClientSocket`/`addDatagramSocket` and aborts it in `closeCurrent()`.
> Verified against the select loop (NIOSocket lines 640–646): closing the socket makes the selector
> cancel the key and the run loop clean it up — but that path does NOT release the pending
> appointment. So `abortClientSocket` cancels the still-attached `ScheduledAttachment` appointment
> (the one thing that lingers) and closes the socket, letting NIOSocket handle the key (no explicit
> `cancelSelectionKey` needed).
>
> **Deep-scan additions (cert validity + SSLv3):** with the Avast MITM disabled, `cert-chain-trust`
> on example.com:443 correctly reads `TRUSTED` (real `Cloudflare TLS Issuing ECC CA 3` chain, not
> the re-signed `UNTRUSTED_ROOT`). Added on top: (1) **cert validity** — `recordCertFacts` now emits
> `cert-not-before`, `cert-not-after`, and `cert-validity` (`VALID` / `EXPIRED` / `NOT_YET_VALID`
> via `X509Certificate.checkValidity()`); example.com → `VALID`, not-after 2026-08-29. This is
> captured on every cert-bearing path (`pqc-check` and `tls-facts`), so bundled https detection
> shows it too. (2) **SSLv3 enumeration** — `enumerateVersions` now also probes `ProtocolVersion.
> SSLv3` (weakest-last) so an insecure server is flagged; verified BC actually sends an SSLv3
> ClientHello and example.com correctly rejects it (`handshake_failure`), while TLS1.0/1.1 are
> genuinely accepted (Cloudflare default min TLS = 1.0) → grade `C`. NOTE: `cert-chain-trust` and
> the protocol/cipher enumeration come from the `https-scan` probe, which is present but NOT in the
> bundle — run it via `--all` (bundled) or as an explicit probe file; bundled https detection
> (`https-pqc`) still yields cert facts + validity + PQC but not chain-trust/version-enumeration.
>
> **`https-scan` is now BUNDLED and primary on TLS ports (the project's core objective).** Raised
> its priority 66→72 (above `https-pqc` 70 and `https-version` 68) and added it to
> `ProbeDefinitionLoader.BUNDLED`, so a default scan of 443/8443 delivers the full TLS assessment —
> `cert-chain-trust`, `cert-validity` (+ not-before/after), `pqc-status`, and the supported
> protocol-version / cipher enumeration — as the winning result (example.com:443 → `https-scan`,
> TRUSTED, VALID, PQC, grade C, ~4s). `https-pqc` (70) remains as the graceful TLS-handshake-failure
> fallback; `https-version` (68, non-portScoped) still handles shallow HTTPS on NONSTANDARD ports.
>
> **Deep TLS on ANY port via `tls-scan` (non-portScoped, service=`tls`).** Added a bundled
> `tls-scan` probe: same deep flow as `https-scan` (handshake→pqc→cert-chain→revocation→versions→
> ciphers) but `service: "tls"`, `ports: []` (never tier-1, always the fallback tier), priority 71,
> `portScoped: false`. So on a nonstandard TLS port it is the top fallback and delivers the full
> assessment labelled `tls` rather than mislabelling it `https`; on a non-TLS port its handshake
> just fails and the real probe wins (the losing connection is aborted immediately). Verified:
> xlogistx.io:6443 → `service=tls DIRECT_TLS pqc=CLASSICAL`, TRUSTED, VALID, grade A (PQC now
> classified, was UNKNOWN). Declared TLS ports keep their specific label via tier-1 (443→`https`
> via `https-scan`, 993→`imaps`); non-TLS ports (80/22/27017) unaffected and still ~1s.
>
> **Staged nmap scanner (host discovery → port scan → probe scan), non-blocking + embeddable.**
> New in `v2/nmap/`: `NMapConfig` (targets host/CIDR/range, ports, discovery/probe toggles, rate
> limits, probe subset), `RateLimiter` (non-blocking throttle: max-in-flight + per-second token
> bucket on `defaultTaskScheduler`), `NMapScanner` (staged pipeline: expand targets → discover
> (TCP-ping via `PortScanCallback`, up if OPEN|CLOSED, + optional executor-run ICMP) → per-host
> port scan → optional probe scan on open ports, all `CountdownMonitor`-barriered and rate-limited),
> `ScanReport`/`HostReport`/`PortReport`, and a flag-driven `NMap` CLI (`-p -sV --probes -Pn -sn
> --no-icmp --max-inflight --max-rate -t`). Embed via `NMapScanner.scan(nio, cfg, cb)`. Verified:
> single-host `-sV` (mongodb/http/https-with-TLS-line), discovery-only over a range, CIDR
> expansion (`127.0.0.1/30` → usable hosts), and rate-limited multi-host scans. TLS ports render
> inline with `[DIRECT_TLS pqc=PQC cert=VALID/TRUSTED grade=C]`.
>
> **nmap parity port (in progress).** Inventoried the old `io.xlogistx.nosneak.nmap` app (~45
> files; its live path was only TCP-connect + UDP on NIO — `service/`, `os/`, and `raw/` SYN/FIN
> engines were dead/stub code). Porting the real features into v2. **Done this pass:** five output
> formats (`v2/nmap/output/` Normal/JSON/XML/CSV/Grepable + `OutputFormat`/`OutputFormatter`, CLI
> `-oN -oX -oG -oJ -oC -oA`, console=Normal — all carry the deep TLS/PQC/validity/grade, beyond the
> old banner-only), enriched `ScanReport`/`PortReport`/`HostReport` model, full `PortState`,
> `WellKnownPorts` (service table + TOP_100_TCP/TOP_20_UDP), and scan reasons/timing. Verified
> multi-format render on example.com. **Decisions:** raw scans → reject (real ones via a JDK-25
> Panama-FFM native layer later); OS detect → open-port heuristic; ARP/remote-MAC → deferred to the
> same FFM layer (no JDK API exposes a remote MAC — layer-2/ARP; won't ship the `arp`-command
> shell-out). **Remaining (see PROBE-CONFIG.md deferrals):** UDP scan `-sU` and an `-O`-style
> heuristic under its own flag. Timing templates, `T:`/`U:`/`--top-ports`/`--open` port specs and
> raw-scan rejection shipped on 2026-09-11. The FFM raw-socket layer is out of scope by design
> (repo-root `CLAUDE.md`, *Operating scope*); ARP/MAC shipped separately in `no-sneak-net`.
>
> Verified: pending scheduler tasks drop to 0 right after delivery (example.com:80: was pending 8s,
> now `pendingSchedTasks=0` at +8ms; `isBusy` false at ~578ms) — so the REST `Checker` no longer
> holds cancelled connections for `timeout`. The one-shot CLI still `System.exit(0)`s after
> printing, since the only remaining threads are the shared non-daemon pools (DE/TSP), not any
> leaked connection (confirmed by thread dump). CLI exits: 80/443/6443/27017 all 0–1s.
> **Cross-module note:** this adds `NIOSocket.abortClientSocket` to zoxweb-core (alongside
> `SSLSessionConfig.getSSLSession()`); the module was rebuilt and installed to `.m2`.
>
> **Bundle:** all 16 probes copied to `/probes/` and bundled — ssh, ftp, http, pop3, redis,
> mysql, mongodb (with `buildInfo` version capture), https-pqc, imaps-pqc, https-version,
> smtp-starttls-pqc, imap-starttls-pqc, postgres-db, postgres-version, postgres-tls, dns (udp).
>
> **Status (history):** **Phases 0–3 complete and green.** 0/1 = engine + raw-TCP
> (ssh/ftp/http). 2 = TLS/PQC handshake on the trigger `StateMachine` (no MonoStateMachine;
> X25519MLKEM768 on google/cloudflare/github:443). 3 = JSSE secure app-data channel
> (`tls-connect`, RSA-capable) — HTTPS `Server:` header over TLS (github/cloudflare), match-all
> returns PQC posture + version together, graceful failure on plaintext ports. Phases 4–10
> pending (see below for 4). v1 remains frozen and working.
>
> **Phase 4 complete and green:** `starttls` mid-session upgrade + Postgres SSLRequest —
> smtp.gmail.com:587 → smtp/STARTTLS_UPGRADED/PQC + banner; lax-2.xlogistx.io:5432 →
> postgresql/DIRECT_TLS/CLASSICAL.
>
> **Phase 5 complete and green:** parallel fan-out + join primitive (`Fanout` + `CountdownMonitor`)
> on native `StateMachine` parallel dispatch (`TaskUtil.defaultTaskProcessor()`). Proven: 6
> children ran on 6 distinct pool threads concurrently (CyclicBarrier gate), join fired
> exactly once.
>
> **Phase 6 PARTIAL (6a done, 6b pending):** 6a = `cert-chain-validate` (opsec PKIX) +
> `enumerate-versions` (parallel version probes via `Fanout`, in `v2/analysis`) as FSM actions
> — verified: https-scan.json on cloudflare/google:443 records pqc, cert-chain-trust, and the
> supported-version set; TLS-1.3 correctly rejected by a TLS-1.2 server (discrimination works).
> Fixed a latent v1 bug (version probe now advertises `supported_groups` so ECDHE negotiates on
> strict servers).
>
> **Phase 6b done:** `enumerate-ciphers` (parallel per-cipher probes via `Fanout`) +
> `revocation-check` (handshake-stapled OCSP, in-memory). Verified: https-scan on cloudflare:443
> yields the full SSL-Labs-style fact set — pqc, cert-chain-trust, revocation, supported
> versions, and supported ciphers; the enumeration **discriminates** (ECDHE/GCM/ChaCha accepted,
> the RSA-key-exchange candidates correctly excluded). **Deferred: active/network OCSP+CRL**
> (needs the HTTP NIO stack → Phase 9).
>
> **Phase 7 complete and green:** UDP seam — `ProbeUDPCallback` on `UDPSessionCallback`
> (ephemeral datagram bind via `addDatagramSocket`, send/expect over UDP), `--udp` CLI, `dns.json`.
> Verified: DNS-over-UDP identified on 8.8.8.8 / 1.1.1.1 / 9.9.9.9:53.
>
> **Phase 8 core done:** NIO-native TCP-connect port scanner (`v2/nmap`: `PortScanCallback`,
> `NMapScanner`, `NMap` — there is no `PortScanner` class; the staged scanner is `NMapScanner`)
> — concurrent connect scan gated by `RateLimiter`/`CountdownMonitor`, then the probe engine
> identifies service+version on each OPEN port (the nmap→probe seam). Verified: scanme.nmap.org
> → 22 ssh OpenSSH_6.6.1p1, 80 http Apache/2.4.7; github.com → 22/80/443. **Deferred (polish):**
> output formatters (JSON/XML/CSV/grepable), host discovery, top-ports/`--open`/UDP-scan flags,
> full v1 NMap CLI parity.
>
> **Phase 9 done:** services + tools. `v2/service/Checker` (REST `/check-qdz/{domain}/{detailed}`
> on the v2 engine, bounded wait vs v1's unbounded `future.join()`); `v2/tools/DMTool` +
> `NoSneakUtil` (copied, **fixed v1 issue C2** — the domain manager is always built from the
> cached-or-new datastore). Compile-clean; DMTool usage verified. **Deferred: active/network OCSP**
> (needs an HTTPNIOSocket plumbed through ProbeContext; only meaningful in the HTTP-server context;
> stapled OCSP already covers the common case).
>
> **Phase 10 done:** grading layer (`v2/grade/Grade` — SSL-Labs-style letter + PQC readiness from
> recorded facts, shown in the CLI for TLS results) and the **parity gate**. Parity verified: v1
> and v2 produce identical service/version/tls/pqc across ssh, ftp, http, https/PQC, smtp
> STARTTLS, postgresql; v2 additionally emits cert-chain-trust, revocation, version+cipher
> enumeration, and grade (which v1's *probe* ProbeChecker never produced — unified from the
> separate v1 scanner). **v2 meets-or-exceeds v1.** Migration ready for the maintainer's merge
> (remaining deferrals are polish: active OCSP, nmap output formatters/discovery, REST/tools
> runtime testing).

## 1. What v2 is

`io.xlogistx.nosneak` is **version 2 of `no-sneak-core`** — a from-scratch rebuild
of the whole module on a single **non-blocking, trigger-`StateMachine`** core. When it
is complete, **the maintainer (not the agent)** merges v2 and deletes the old code, so
v2 becomes the module. Until then, v1 (`io.xlogistx.nosneak.{nmap,probe,scanners,
services,tools}`) is **frozen and untouched**.

### Non-negotiable rules
1. **v1 is read-only.** v2 never modifies, deletes, or depends on v1 classes.
2. **Clean final names — no `v2` in any class name.** Separation comes only from the
   `io.xlogistx.nosneak` package path. Classes keep their final names
   (`ProbeChecker`, `ProbeEngine`, `ProbeResult`, `PQCSessionConfig`, …) so that after
   the maintainer's merge/rename they are already correct. (This `PLAN.md` and other
   docs may say "v2"; class names may not.)
3. **Copy + rearchitect for anything inside `no-sneak-core` — never a blind copy.**
   Because v1 is deleted at merge, v2 must be self-contained: every no-sneak-core class v2
   needs is **copied into v2** and reworked to be **fully non-blocking**. Any blocking
   `java.net.Socket`, `Thread.sleep`, `future.join()`/`get()`, or blocking selector loop
   from v1 is replaced with `NIOSocket` + callbacks + scheduled tasks. No v2→v1
   references, ever.
4. **Reuse freely (call, don't copy) the surviving modules:** `zoxweb`
   (`org.zoxweb.*` — `NIOSocket`, `org.zoxweb.server.fsm.StateMachine`,
   `TCPSessionCallback`, `UDPSessionCallback`, `SSLContextInfo`, `HTTPNIOSocket`, …) and
   **opsec** (`io.xlogistx.opsec.OPSecUtil`). These are separate Maven modules that
   survive the merge.
5. **No `MonoStateMachine`** anywhere in v2. The TLS/PQC handshake uses the trigger-based
   `StateMachine` design (the proven `org.zoxweb.server.net.ssl.SSLStateMachine` /
   `SSLHandshakingState` pattern, adapted to Bouncy Castle).
6. **Always green.** Every phase compiles and runs; a working vertical slice comes first,
   then widens. No phase leaves the tree broken.

## 2. Core architecture

One engine drives everything: **`StateMachine<ProbeContext>`**. A JSON `ProbeDefinition`
builds the machine — each declared state becomes a `org.zoxweb.server.fsm.State` carrying
a `ProbeActionConsumer` (`TriggerConsumer`) that runs a fixed, trusted **action**. An
action reports an **outcome**; the engine resolves the state's `on{}` map and publishes
the next state's trigger. JSON selects behavior; JSON never executes code.

- **Sequential** = `publishSync` on an inline executor (`r -> r.run()`) — linear probes
  (connect → handshake → pqc → cert → starttls → version).
- **Parallel** = a fan-out state that `publish`es one trigger to **N registered consumers
  on a pool executor** (native `StateMachine` fan-out: `tcMap.get(id)` is a *set*, each
  dispatched via the executor). Each consumer spawns an **independent child sub-flow**
  (own connection + wait guard); a **join barrier** (`AtomicInteger` count, the proven
  `PQCScanCallback` pattern) fires the parent's next trigger at zero. This is how the
  scanner's cipher/version/revocation fan-out becomes data.
- **Transport:** TCP via `TCPSessionCallback` (raw + JSSE-secure subclasses) and UDP via
  `UDPSessionCallback` (`NIOSocket.addDatagramSocket`) for DNS/QUIC/DTLS-shaped probes.
- **TLS/PQC handshake:** a trigger-`StateMachine` driver over Bouncy Castle
  (`PQCSessionConfig` `offerInput`/`readOutput`/`isHandshaking`), replacing the v1
  MonoState `PQCSSLStateMachine`.

### Concurrency conventions (fixed, project-wide in v2)
Everything is non-blocking; no thread is ever parked on I/O. Standard wiring:
- **Executor** — `org.zoxweb.server.task.TaskUtil.defaultTaskProcessor()`. Used for the
  `StateMachine` **parallel** dispatch (fan-out states) and as the `NIOSocket` task
  processor (`new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler())`).
- **Scheduler** — `org.zoxweb.server.task.TaskUtil.defaultTaskScheduler()`. Used for all
  **timeouts / watchdogs / wait guards** (connect, handshake, expect deadlines, overall
  probe deadline) via `schedule(...)`.
- **Sequential** transitions use the inline executor `r -> r.run()` (no dispatch); only
  fan-out states use `TaskUtil.defaultTaskProcessor()`.
- No `Thread.sleep`, no `future.join()/get()` on a live path, no blocking sockets — ever.

## 3. Target package layout (v2)

```
io.xlogistx.nosneak
├── model/        ProbeDefinition, ProbeState, PatternRule, ProbeDefinitionLoader
│                 (copied from probe/model; + portScoped, + parallel/fan-out fields)
├── runtime/      ProbeContext   (StateMachine config C: NIO conns, result builder, wait guards, child registry)
│                 ProbeEngine    (builds StateMachine<ProbeContext> from a definition; seq + parallel)
│                 ProbeTCPCallback (raw), ProbeSecureCallback (JSSE), ProbeUDPCallback (UDP)
├── action/       Action, ActionRegistry, ProbeActionConsumer,
│                 Connect, Send, Expect(+capture), StartTLS, TLSHandshake(BC/PQC), TLSConnect(JSSE),
│                 PQCCheck, CertInfo, TLSFacts, Record, Terminal, FanOut(+Join),
│                 Revocation, CertChain, CipherEnum, VersionEnum, VulnCheck (Sprint-4, later)
├── tls/          PQCConnectionHelper, PQCHandshakeStateMachine (trigger SM), PQCHandshakeStates,
│                 PQCHandshakeUtil (extracted BC handler helpers),
│                 PQCSessionConfig, PQCTlsClient, PQCTlsClientProtocol   (copied from scanners)
├── analysis/     RevocationChecker, CipherEnumerator, VersionEnumerator, ScanResult, ScanOptions
│                 (copied+rearchitected from scanners; PQCScanResult → ScanResult facts)
├── discovery/    HostDiscovery (copied from probe/discovery + nmap/discovery, unified on NIO)
├── nmap/         NMap, NMapScanner, config/, output/, scan/{tcp,udp}, util/
│                 (copied+rearchitected on NIOSocket; feeds ProbeEngine for service/version)
├── service/      Checker (REST endpoint; copied+adapted from services/QDZChecker)
├── tools/        DMTool, NoSneakUtil   (copied; known bugs fixed)
├── result/       ProbeResult, ProbeResult grading hook
└── ProbeChecker, ProbeDispatcher   (library API + CLI)

src/main/resources/probes/   (all 17 JSON copied verbatim; + parallel/full-scan definitions)
```

## 4. Migration of each v1 subsystem (all **by copy**)

| v1 subsystem | files | v2 destination & treatment |
|---|---|---|
| **probe** | 27 | **The core.** Copy `model`/`runtime`/`action`/`discovery` → v2 `model`/`runtime`/`action`. Add parallel fan-out; convert nothing to MonoState. This is the engine everything else plugs into. |
| **scanners** | 16 | Copy the reusable TLS engine: `PQCSessionConfig`, `PQCTlsClient`, `PQCTlsClientProtocol`, `PQCConnectionHelper` → v2 `tls`. **Convert** `PQCSSLStateMachine` (MonoState) → v2 `tls/PQCHandshakeStateMachine` (trigger SM). Copy+rearchitect `NIORevocationChecker`→`analysis/RevocationChecker`, `CipherProbeCallback`→`CipherEnum` action, `VersionProbeCallback`→`VersionEnum` action, `PQCScanResult`→`analysis/ScanResult`, `PQCScanOptions`→`analysis/ScanOptions`. **Retire** the bespoke `PQCScanCallback`/`PQCNIOScanner`/`ScanCallback`/`TLSProbeCallback` orchestration — replaced by FSM fan-out. **Drop** dead blocking `CipherSuiteEnumerator`/`ProtocolVersionTester` (keep only their static name/strength helpers). |
| **nmap** | 49 | Copy `config`/`discovery`/`output`/`scan/{tcp,udp}`/`util` → v2 `nmap`; rearchitect scan engines on `NIOSocket` (fix v1 blocking/fake-engine debt). **Wire the seam:** nmap port discovery hands open `ip:port`s to `ProbeEngine` for service+version identification. **Drop** the dead `nmap/service/*` + `nmap/os/*` (superseded by the probe engine) and the fake raw/SYN/"stealth" engines (nmap's naming for its raw scan types; v2 rejects those flags outright rather than building evasion). |
| **services** | 1 | Copy `QDZChecker` → v2 `service/Checker`; adapt to call `ProbeEngine`/`ProbeChecker`; keep the REST endpoint, remove `future.join()` blocking. |
| **tools** | 2 | Copy `DMTool`, `NoSneakUtil` → v2 `tools`; fix the known bugs (stale mongo URL, latent NPE-return). |
| **resources/probes** | 17 JSON | Copy verbatim to v2 resources; add parallel/full-scan definitions. |

**Reused from surviving modules (never copied):** `org.zoxweb.*` and `io.xlogistx.opsec.OPSecUtil`.

## 5. Phased plan of action (each phase is green + verified)

| Ph | Deliverable | Copied/created | Verify |
|----|-------------|----------------|--------|
| **0** ✅ | Engine skeleton: `model` (copied), `ProbeEngine`, `ProbeContext`, `ProbeChecker`; trivial `connect → record → done` | probe/model, new runtime | BUILD SUCCESS; loads JSON; runs vs a host |
| **1** ✅ | Raw TCP: `Connect/Send/Expect(+capture)/Reconnect`, `ProbeTCPCallback`; ssh/ftp/http probes | probe/action+runtime | **DONE** — live: ssh `OpenSSH_6.6.1p1…`, ftp banner, http `Server: cloudflare`; no-match + match-all paths verified |
| **2** ✅ | **Handshake → trigger StateMachine**: `tls/*` (copied glue + new `PQCHandshakeStateMachine`), `TLSHandshake/PQCCheck/TLSFacts` | scanners TLS glue | **DONE** — google/cloudflare/github:443 → X25519MLKEM768 / TLSv1.3 / PQC, cert facts, v1-parity |
| **3** ✅ | JSSE secure app-data: `ProbeSecureCallback` + `TLSConnect` | new | **DONE** — HTTPS `Server:` header over TLS (github/cloudflare); match-all = PQC + version; clean failure on plaintext ports |
| **4** ✅ | `StartTLS` mid-session upgrade + Postgres SSLRequest | new | **DONE** — gmail:587 smtp/STARTTLS_UPGRADED/PQC + banner; lax-2:5432 postgresql/DIRECT_TLS |
| **5** ✅ | **Parallel** fan-out + join (`Fanout`+`CountdownMonitor`) on native StateMachine pool-executor dispatch | new | **DONE** — 6 children on 6 distinct threads concurrently (barrier-gated), join exactly-once |
| **6** ✅ | Scanner analysis as actions: `CertChain`(opsec), `Revocation`(stapled OCSP), `VersionEnum` + `CipherEnum` (parallel via Fanout, `v2/analysis`) | scanners copied | **DONE** — https-scan on cloudflare:443 → full fact set (pqc, cert-chain-trust, revocation, versions, ciphers); enumeration discriminates. Active OCSP+CRL deferred to Phase 9 (HTTP stack) |
| **7** ✅ | UDP: `ProbeUDPCallback` + udp connect/send/expect, `--udp` CLI, `dns.json` | new (uses zoxweb UDP) | **DONE** — DNS-over-UDP on 8.8.8.8 / 1.1.1.1 / 9.9.9.9:53; QUIC/DTLS-ready seam |
| **8** ◑ | **nmap** core: NIO TCP-connect scanner (`PortScanCallback`/`NMapScanner`/`NMap`) + port-scan → ProbeEngine seam. Since shipped: output formatters, discovery, `--top-ports`/`T:`/`U:`/`--open`/`-T0..T5`, raw-scan rejection. Deferred: UDP scan | new (dead v1 nmap dropped) | **DONE** — scanme.nmap.org → 22 ssh OpenSSH_6.6.1p1, 80 http Apache/2.4.7; github 22/80/443 |
| **9** ◑ | **services + tools**: `service/Checker` (REST on v2 engine, bounded wait), `tools/*` (C2 NPE fixed) | services+tools copied | **DONE** — compile-clean, DMTool usage verified. Active OCSP deferred (needs HTTP-server context) |
| **10** ✅ | Grading layer (`v2/grade/Grade`) + full-scan definition + **parity gate** | new | **DONE** — v1≡v2 service/version/tls/pqc across 6 services; v2 adds cert-chain/revocation/enum/grade. **v2 ≥ v1** |

Ship order rationale: **0→1** = a working v2; **2** kills the MonoState debt; **5** unlocks all parallelism; **6** folds the scanner into definitions; **8** folds nmap in and wires the long-planned service-detection seam; **10** is the parity gate before the maintainer's merge.

## 6. Verification & parity strategy

- Each phase: `mvn -pl no-sneak-core -am compile test-compile` green, plus **live** runs
  against real endpoints (google/cloudflare/github, gmail SMTP/IMAP, the maintainer's
  Postgres, public FTP/SSH).
- No-network unit tests mirror v1's `ProbeDefinitionLoaderTest` (graph validity, capture
  wiring, wire-message byte checks). (Surefire execution is env-skipped today — same as
  v1 — so live verification is the primary gate.)
- **Parity harness (Phase 10):** run v1 and v2 against the same target set and diff the
  fact maps; v2 must meet-or-exceed v1 on service id, version, TLS/PQC facts, cert trust,
  revocation, cipher/version enumeration, and nmap port results.

## 7. Open items / notes

- Phase 6 reuses `io.xlogistx.opsec.OPSecUtil` (chain validation, cipher/version
  classification) by **calling** it — opsec survives the merge.
- The v1 nmap debt (fake raw/SYN engines, dead service/os packages, blocking sleeps) is
  **not** carried over; v2 nmap is NIO-native and defers to the probe engine for service
  detection.
- `MonoStateMachine` is eliminated project-wide within v2 (the v1 `TODO(no-monostatemachine)`
  is resolved by construction, not migration).
- Grading (SSL-Labs A–F, PQC readiness, CNSA 2.0) lands as a **post-`record` layer** over
  the unified `ProbeResult`, per the v1 roadmap — Phase 10.

## 8. First checkpoint

On go, I start **Phase 0 + 1** (engine skeleton + raw-TCP, green end-to-end with
ssh/ftp/http running live) and report back at the first green build before proceeding to
TLS/parallel/nmap.
