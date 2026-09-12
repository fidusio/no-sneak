# no-sneak-core — v1 vs v2 merge analysis (2026-09-12)

Code-level comparison of the two generations that coexist in this module, written to answer one
question before the maintainer merges: **which side is the more complete code base, and what has
to move across before the other is deleted.** Every claim below was verified in source, not taken
from `CLAUDE.md`, `v2/PLAN.md` or `ACTION-PLAN.md`. Citations are `file:line` under
`src/main/java/io/xlogistx/nosneak/`.

## Verdict

**Keep v2. Delete v1.** v2 is smaller, tested, non-blocking, policy-compliant, and the only side
whose service detection, UDP scan, host discovery, cancellation and revocation actually work end to
end. v1's apparent breadth is mostly surface: its service and OS detection are never invoked, its
raw-scan engines are TCP-connect impostors, `-sS` cannot run, `-sV` hangs on a silent open port,
and its discovery shells out to `arp` and blocks pool threads.

The merge is not free, though. The comparison found **real regressions v2 must close first** (the
docs' "v2 meets-or-exceeds v1" claim is true for the scanning core but not for the edges), listed in
§4 in priority order. The highest-risk one is a revocation-check short-circuit in the TLS path.

| | v1 (`nmap`, `probe`, `scanners`, `services`, `tools`) | v2 (`v2/**`) |
|---|---|---|
| Main source | 95 files, 15,964 lines | 70 files, 10,762 lines |
| Dead or unreachable in production | ~2,700 lines (nmap `service/`, `os/`, `scan/raw/`; blocking `CipherSuiteEnumerator`/`ProtocolVersionTester`; `ProbeDispatcher`; `HardenedHostDiscovery`; UDP stub) | ~0 (a few dead fields and enum values, listed in §5) |
| Tests | 5 classes, 37 tests, **24 need the Internet** | 28 classes, 311 tests, **0 touch a wire** |
| Blocking on pool threads | `Thread.sleep`, `Semaphore.acquire`, `.join()`, blocking `Socket`, `ProcessBuilder`, reverse DNS on the selector thread | none outside CLI `main` methods |
| `MonoStateMachine` | yes (`scanners/PQCSSLStateMachine:29`) | no |
| Executor / scheduler | global `TaskUtil.default*` | injected from `NIOSocket` or constructor |
| Rate limiting | blocking semaphore + sleeps | `ScanGate` on zoxweb `RateController` TIME mode |
| Consumers outside the module | **none** | `no-sneak-app` (`ScanPanel`, `Session`, `ScanPanelTest`), all v2 |
| Policy | ships an SNMP probe with community `public` (`nmap/util/PacketDataConst:6-32`) — a credential guess | rejects `-sS/-sF/-sX/-sN/-sA/-O` by name; no credential payloads |

## Status after the fix pass (2026-09-12, same day)

**Every item in §4 is closed in v2, plus the §5 cleanups and the "merge anything v1 has"
extras.** v2 is now the only code base that needs to survive; what remains is the maintainer's
merge itself (§2: delete the v1 packages, collapse `v2` to `io.xlogistx.nosneak`, move
`/v2/probes/` to `/probes/`, retarget the listed files). Verified: the whole repo compiles
offline, the v2 suite is **365 tests in 31 classes, all green, none touching a wire**, and live
runs against `xlogistx.io:443`, `example.com:443/80`, loopback and the local `/24` gateway
exercised the new paths.

What landed, by §4 number:

| # | Closed by |
|---|---|
| 1 | `ProbeContext.checkRevocation` accepts a staple only when its status is not ERROR; a malformed staple falls through to OCSP/CRL (`TlsAnalysisContextTest.aMalformedStapleFallsThroughToTheActiveCheck`) |
| 2 | `ProbeContext.classifyPqc`: hybrid → `PQC`, TLS 1.3 classical → `CLASSICAL` (grade `PQC_CAPABLE`), ≤TLS 1.2 → `NOT_READY` (grade `CLASSICAL_ONLY`); dead `PQC_READY` enum value and `Grade.rank` D/E removed |
| 3 | `ProbeState.includeSSLv3/includeTLS10/includeTLS11/includeWeak/includeInsecure/maxInFlight/rankServerPreference`, `ProbeDefinition.overallTimeoutSec` (validated > 0); `https-scan`/`tls-scan` declare them explicitly with a 90 s deep-scan budget |
| 4 | `Grade.advisoriesOf` carries v1's remediation text (SSLv3/POODLE, TLS 1.0/1.1 PCI, upgrade to TLS 1.3, enable hybrid kex, ML-DSA, cert renewal per `TrustVerdict`) |
| 5 | `ProbeResult.success` / `error-message` (strings, survive the default serializer); REST `Checker` extends `PropertyContainer`, reads `start-count-at`, emits `total-scanned`; `http_server_config.json` repointed to `v2.service.Checker` |
| 6 | CRL without a presented issuer → `UNKNOWN/crl`, never GOOD, and not fetched |
| 7 | `CipherSuiteInfo.authentication/encryption/mac` from `OPSecUtil.parseCipherSuite` |
| 8 | `Fanout.runBounded`: enumeration children run 8 at a time per context (`maxInFlight`); REST `Checker` builds its `ProbeChecker` behind a `ScanGate` (8 in flight, 200/s) |
| 9 | `TlsEnumerationContextTest` (11), `TlsAnalysisContextTest` (13), `NetworkRevocationCheckerTest` (9) drive versions, ciphers, preference, groups, chain validation and every revocation path through the scripted seams |
| 10 | Down hosts print in Normal and CSV |
| 11 | Per-octet ranges, comma-separated tokens, expansion cap recorded as a report warning |
| 12 | `--timeout`, attached `-p<spec>`, `-sP`, `-PN`, `-h/--help/-?`, `-v`, `--max-parallelism`/`-P`, numeric and named `-T`, legacy `host=`/`range=`/`timeout=`; `-oX -` and friends write to stdout |
| 13 | Port spec de-duplicated, first-seen order |
| 14 | XML: DOCTYPE, `scaninfo`, `startstr`, `version`, host times, PTR hostnames, `runstats` with `finished`/`hosts down`; Grepable header, footer and `(hostname)` |
| 15 | `HostReport.ip` on every path; `hostname` via a non-blocking PTR lookup (`ReverseDnsCallback`: dnsjava message over the NIO datagram socket, deadline on the injected scheduler; `-n`/`-R`/`--dns-servers`); dead `osGuess`/`osAccuracy`/`ttl` removed |
| 16 | Default port set is 1–1024 (v1's); `--top-ports` unchanged |
| 17 | `WellKnownPorts` gained 1521/tcp oracle and 520/udp route; `ProbeChecker` uses it (transport-aware) and its private map is gone |
| 18 | `NMapScannerEndToEndTest` scans a loopback listener and renders all five formats; dead 4-arg `buildChecker` and unused logger removed |
| 19 | `https-classical.json` and `smtp-starttls.json` copied to `/v2/probes/` (on disk, unbundled, exactly as in v1); `probes-tried` is a name list in both `cancelled()` and `noneIdentified()` |

Also done: v1's server cipher **ranking** (`rankServerPreference`, off by default, bounded to 10
sequential handshakes, recorded as `server-cipher-ranking`); JSON `startTime`/`endTime`/
`durationSec`/`hostsDown`/per-host `portStats`; `OutputFormatter.formatTo(OutputStream)` and
`mimeType()`; `key-exchange-algorithm` now names the mechanism (`ML-KEM hybrid`/`ECDHE`/`DHE`/`RSA`)
instead of repeating the group; the `xlogistx-gui-audio` dependency dropped from the core pom;
every §5 cleanup.

Deliberate differences from v1, on record: the REST scan counter is process-wide rather than
per-instance; the JSON report keeps `"scanner": "XNMap"` for stored-report consumers while XML and
Grepable say `nosneak`; `-v` adds detail but warnings always print; the default deep-scan budget is
90 s (v1's) instead of the old `max(4×timeout, 30)` formula.

## 1. Subsystem ledgers

### 1.1 Probe engine — `probe/**` vs `v2/{ProbeChecker,action,runtime,model}`

v2 is a strict superset. Nothing functional needs to move.

| Capability | v1 | v2 |
|---|---|---|
| Action library | 12 actions (`action/ActionRegistry:15-28`) | 17: the same 12 plus `cert-chain-validate`, `revocation-check`, `enumerate-versions`, `enumerate-ciphers`, `enumerate-groups` (`v2/action/ActionRegistry:15-33`) |
| Definition model / loader | identical fields and validation | identical, plus `revocationTimeoutMs` on a state and a shared `parse()` entry point |
| Candidate sweep | sequential, one probe at a time, no cancel (`probe/ProbeChecker:158-231`) | all candidates launched concurrently, highest-priority election, losers cancelled, `cancelAll()`; pacing via `ConnectionGate` (`v2/ProbeChecker:290-358`) |
| UDP | stub that logs and drops datagrams, never instantiated (`probe/runtime/ProbeUDPCallback:29-46`) | real: ephemeral bind, send, expect (`v2/runtime/ProbeContext:378-467`) |
| `tls-connect` (JSSE) facts | records nothing; results read `tls-state=NONE` (`probe/runtime/ProbeSession:507-510`) | records state, version, cipher (`ProbeContext:1123-1154`) |
| Teardown | never aborts the NIOSocket connect-timeout appointment | `transport.abort(key)` in `closeCurrent` (`ProbeContext:1282-1289`) |
| User callback | invoked while holding the session monitor (`ProbeSession:144-165`) | delivered after the monitor is released (`ProbeContext:249-270`) |
| Bundled probes | 15 bundled (17 on disk; `https-classical`, `smtp-starttls` orphaned) | 18 bundled, all on disk; adds `dns` (UDP), `https-scan`, `tls-scan`; `http` gains an `istls` gate, `postgres-db` name fixed, `https-version` priority raised |
| Tests | 1 class (loader only) | 12 classes on the engine incl. `ScriptedTransport`/`ManualScheduler` seams |

Twelve of the fifteen bundled v1 probe JSONs are byte-identical in v2; the other three are improved.

### 1.2 TLS / PQC — `scanners/**` vs `v2/{tls,analysis,grade,result}` + TLS actions

v2 is the sounder design and does more, but **this is where the regressions live**.

| Capability | v1 | v2 |
|---|---|---|
| BC handshake, PQC groups offered, negotiated-group capture, hybrid predicate | `PQCSessionConfig`, `PQCTlsClientProtocol`, `PQCTlsClient` | byte-identical copies, driven by a trigger `StateMachine` instead of `MonoStateMachine` |
| PQC classification | READY / PARTIAL (TLS1.3 classical) / NOT_READY (≤TLS1.2) / UNTRUSTED / ERROR (`scanners/PQCScanResult:1018-1084`) | only `PQC` / `CLASSICAL` / `UNKNOWN` (`ProbeContext:570-579`); `PqcStatus.PQC_READY`, `NOT_READY` and `Grade.Pqc.PQC_CAPABLE` are never assigned |
| Named-group enumeration | none | `enumerate-groups`, 10 single-group handshakes, `supported-groups` + `server-group-preference` |
| Version enumeration | TLS1.3/1.2 always; 1.1/1.0 default on; **SSLv3 opt-in** (`PQCScanOptions:41-43`) | all five always incl. SSLv3 (`ProbeContext:745-749`); children advertise classical groups so ECDHE negotiates on strict servers |
| Cipher enumeration | sequential "offer all, remove the pick, repeat" → server's full ranking; strong only unless weak/insecure opted in; names via an 11-entry switch → `CIPHER_0x…` for most suites (`PQCScanCallback:395`, `PQCTlsClient:377-408`) | parallel single-suite probes, up to 44 concurrent, **weak and insecure always included** (`ProbeContext:793-802`); names reflected over all 328 BC constants; accepted set + top pick only |
| Server cipher preference | two probes hard-coded to TLSv1.2 while the first two collected suites are TLS1.3 → false on modern servers (`PQCScanCallback:470,486`) | version-aware forward/reverse probe (`ProbeContext:889-959`) |
| Cert chain, leaf facts, hostname match, chain time validity, root append | yes | yes, on every cert-bearing path (v1 only on full scan); tri-states as strings |
| Revocation | staple → active OCSP; **malformed staple falls through to the network check** (`scanners/NIORevocationChecker:104-116`); CRL never fetched | staple → OCSP → CRL with issuer-signature and staleness checks (`v2/analysis/RevocationChecker:61-94`); **but a staple that fails to parse is recorded as `ERROR/stapled` and the network path is skipped** (`ProbeContext:1030-1035`) |
| Grading | status enum + `TrustVerdict` + free-text recommendations; no letter | letter A/B/C/F/T, no A without version enumeration, cipher-posture rules, `TrustVerdict` with v1's precedence, advisories |
| Remediation text | "Upgrade to TLS 1.3", "Enable PQC hybrid key exchange", cert renew wording, POODLE/PCI notes | hostname, classical cert with PQC kex, no PQC group, insecure suite, CBC list only |
| Result status fields | `success`, `secure`, `error-message`, `overall-status`, `scan-id`, `total-scanned` | `complete` + `note` |
| Options | `PQCScanOptions` (SSLv3, TLS1.0/1.1, weak, insecure, revocation, overall watchdog 90 s) | which actions the probe JSON lists; overall deadline hard-coded `max(4×timeout, 30 s)` (`ProbeContext:184`) |
| Blocking dead code | `CipherSuiteEnumerator` (463 lines), `ProtocolVersionTester` (341), `new Socket()` — only `FeatureIntegrationTest` calls them | none |
| Non-BC TLS | none | `tls-connect` uses SunJSSE (`ProbeSecureCallback:77-89`) because `bctls` 1.86 is broken on JDK 9+; `BcjsseEngineCreationTest` is the canary |
| Tests | 3 classes, 1,209 lines, network-bound | `Grade`, `ProbeResult`, `RevocationChecker` parsing, `GroupProbeCallback`; **nothing drives enumeration, chain validation or network revocation through `ProbeContext`** |

Neither side implements ALPN, session resumption, renegotiation, compression, HSTS/security
headers, CNSA, SCT/CT, must-staple, or OCSP responder-signature/freshness validation. Those are
gaps in both generations, not regressions.

### 1.3 Network scanner — `nmap/**` vs `v2/nmap/**`

v2 is a quarter of the size and the only working one.

| Capability | v1 | v2 |
|---|---|---|
| Size / tests | 49 files, 11,029 lines, **0 tests** | 17 files, 3,142 lines, 10 test classes (~120 tests) |
| Host discovery | "ARP" = 11 blocking connects + `arp -a` shell-out (`nmap/discovery/ARPPing:96-158`); ICMP = `isReachable`; sequential chain; MAC/reason lost in port-scan mode | real ICMP/ARP/NDP via `no-sneak-net` `HostScanner`, whole-range sweep for on-link CIDRs, MAC and reason on every host, degraded-mode warnings |
| TCP connect scan | NIO, but `-sV` banner grab has **no completion path on a silent port** → `scan().join()` never returns (`nmap/scan/tcp/TCPPortScanCallback:59-64`, `timeout()` has no caller) | NIO, bounded banner window, own FILTERED deadline |
| UDP scan | one unconnected socket, ICMP unreachable not attributable → closed reads `open|filtered`; 100 ms `Thread.sleep` between probes; **SNMP `public` payload** | connected socket per target → real `closed`; one retransmit; DNS/NTP payloads; SNMP removed on policy |
| SYN/FIN/Xmas/NULL/ACK | listed, but engines are connect-scan impostors and `-sS` fails at run time (`nmap/scan/raw/RawScanEngine:21-27`; `NMap:102-107`) | rejected at parse time with a policy message |
| Service/version | `-sV` only sets `grabBanner`; `service/ServiceDetector` has zero callers; `PortResult.service` never set | full probe engine per open port through the shared `ScanGate`; `--probes` subset; stored extra probes |
| OS detection | `os/OSDetector` has zero callers and its TTL path can never fire | none; `-O` rejected; `osGuess/osAccuracy/ttl` fields exist but are never assigned |
| Concurrency | blocking `Semaphore.acquire` on the thread that completes discovery; NIOSocket delivers the releasing events on the same 64-thread pool → starvation with 64+ hosts | `ScanGate` (in-flight window + `RateController`), never parks |
| Cancellation | cancels futures only; sockets keep running; no partial report | idempotent `ScanHandle.cancel()`, every in-flight unit aborted, partial report with `cancelled=true`, Ctrl-C hook |
| Target parsing | CIDR (network/broadcast excluded only for /24+), last-octet range, **per-octet ranges `1-5.1-254`**, comma-separated tokens; >65536 returns the spec string as a host | CIDR (correct for all prefixes), last-octet and full `a.b.c.d-w.x.y.z` ranges, dedupe; **no per-octet ranges, no comma tokens, silent truncation at 65536** (`v2/nmap/NMapScanner:976-977`) |
| Default ports | 1–1024 | 20 common ports |
| Port spec | `TreeSet` → sorted, deduped | order kept, **duplicates kept** |
| CLI | lenient: `--timeout`, `-p22,80`, `-sP`, `-PN`, `-h`, `-v`, `--max-parallelism`, `-T4`/`aggressive`, `host=` legacy; unknown flags silently ignored | strict: `-t`, `-p <spec>`, `-T0..-T5` only; unknown flag → usage + exit 2 |
| Output: down hosts | Normal prints `Host is down (reason)`; CSV writes a row | **Normal and CSV skip down hosts entirely** (`output/NormalFormatter:34-36`, `output/CSVFormatter:31-33`) |
| Output: XML | DOCTYPE, `scaninfo`, `startstr`, `version`, host times, `hostnames type=PTR`, `finished elapsed summary`, `hosts down` | `nmaprun`, status, address ipv4/mac, extraports, port rttms, service tls/pqc, runstats up/total; none of the v1 metadata |
| Output: Grepable / JSON | header/footer comments, `(hostname)`; JSON with formatted times, `hostsDown`, per-host stats | no header/footer; JSON is `ScanReport.toNVGenericMap` with `printNull=true`, `cancelled`, `warnings`, full probe map |
| `-oA` | N/X/G/J, not CSV | all five |
| Host IP / hostname | always resolved (blocking forward + reverse DNS) | `ip` set only when ICMP or ARP ran; `hostname` never set |

### 1.4 Services and tools

| | v1 | v2 |
|---|---|---|
| REST `/check-qdz/{domain}/{detailed}` | `services/QDZChecker`: `future.join()` on the request thread; private-IP guard on request thread; `start-count-at` property → `scanCount` → `total-scanned` in the body | `v2/service/Checker`: fully async, `ProtoSession` held open, 504 backstop at 100 s, guard resolves all addresses off-thread, `Grade` merged into the body, `checkQDZDirect` server-free entry; **`total-scanned` and `start-count-at` dropped** |
| `DMTool` | identical byte-for-byte except package and one line break; same stale Mongo URL (C1) | same |
| `NoSneakUtil` | latent null return when the datastore is cached but the manager is not | fixed (C2) |
| `v2/data/{ProbeContent,ReportContent}` | no v1 equivalent | two `PropertyDAO` rows used by the app's `Session`/`ScanPanel` |

## 2. Consumer map — what the rename touches

Only `no-sneak-app` depends on `no-sneak-core`, and every one of its usages is v2. When v1 is
deleted and `io.xlogistx.nosneak.v2` collapses to `io.xlogistx.nosneak`, retarget:

- `no-sneak-app/src/main/java/io/xlogistx/nosneak/app/ui/ScanPanel.java` (9 imports + 1 javadoc), `…/ui/utility/Session.java` (2), `no-sneak-app/src/test/…/ScanPanelTest.java` (5)
- `no-sneak-core/src/test/resources/http_server_config.json:104` — `"bean": "io.xlogistx.nosneak.services.QDZChecker"` → `…nosneak.service.Checker`; its `start-count-at` property has no v2 reader
- `.idea/workspace.xml:298-318` — two JUnit run configurations on `v2.nmap.*` / `v2.analysis.*`
- Docs naming the package: `README.md:49,52`, `no-sneak-core/README.md:44,47,66`, `CLAUDE.md:88`, `no-sneak-core/CLAUDE.md:121,125`, `no-sneak-app/CLAUDE.md:27,506`, `ai-model/CLAUDE.md:130`
- The 28 v2 test files' `package`/`import` lines
- `src/main/resources/v2/probes/` → `/probes/` and `ProbeDefinitionLoader.BUNDLED`

Delete with v1: the five v1 test files (`probe/ProbeDefinitionLoaderTest`, `scanners/{FeatureIntegrationTest,PQCCallbackTest,PQCScannerTest}`, and `scanners/NoSneakNIOHTTPServer`, which should move to the v2 test tree if the config-driven server harness is kept), `src/main/resources/probes/`, and `services-categories-info.json` (2,515 lines, **read by nothing on either side**).

Build: no v1-only third-party dependency exists. `no-sneak-net` is v2-only. `junit-jupiter-params`
and `xlogistx-gui-audio` in `no-sneak-core/pom.xml` are unused by both sides; the parent pom's
`xlogistx-no-sneak` managed artifact has no consumer.

## 3. Things v2 does that v1 never could

Named-group enumeration; CRL revocation with signature and staleness checks; letter grade with
evidence gating and cipher-posture rules; correct cipher names; correct cipher-preference probing;
STARTTLS mid-session upgrades; real UDP `closed`; real ICMP/ARP with MAC; whole-range on-link
sweep; cancellation with partial reports; a working `-sV`; `--open`, `--probes`, `-PR/-PE`;
injected executors everywhere; `RateController` pacing; 311 pure tests; policy rejection of raw
scans and removal of the SNMP community guess.

## 4. Port list — close these before deleting v1

Ordered by risk. "Port" means re-implement in v2's style, not copy v1 code.

### TLS / PQC (`v2/runtime/ProbeContext`, `v2/grade/Grade`, `v2/result/ProbeResult`)

1. **Staple parse failure must fall through to OCSP/CRL.** `checkRevocation` (`ProbeContext:1030-1035`) tests only the method name; require `stapled.getStatus() != ERROR` as v1 did (`NIORevocationChecker:104-116`). Add a `ProbeContextTest` case pinning it.
2. **Restore the TLS-1.3-classical vs ≤TLS-1.2 distinction.** `recordTls` should emit `NOT_READY` when the negotiated version is not 1.3, or the dead enum values (`PqcStatus.PQC_READY/NOT_READY`, `Grade.Pqc.PQC_CAPABLE`, `Grade.rank` D/E) should be deleted. Pick one.
3. **Enumeration toggles.** `ProbeState` fields for `enumerate-versions` (`includeSSLv3`, `includeTLS10/11`) and `enumerate-ciphers` (`includeWeak`, `includeInsecure`), and an overall-deadline field replacing the hard-coded `max(4×timeout, 30 s)`. A deep `tls-scan` (handshake + 44 ciphers + 5 versions + 10 groups + revocation) with the default timeout gets a 30 s ceiling today.
4. **Remediation advisories.** Port the v1 recommendation strings (`PQCScanResult:1027-1099`, `ProtocolVersionTester:78-93`) into `Grade.advisoriesOf` so SSLv3/TLS1.0/1.1/no-TLS1.3 findings carry text, not only a letter.
5. **Explicit `error`/`success` on `ProbeResult`** and restore `total-scanned` (or drop `start-count-at` from the server config deliberately). Any consumer keyed on v1's `error-message` breaks today.
6. **Unverified-CRL GOOD.** When `issuer == null`, record `UNKNOWN/crl` rather than `GOOD` (`NetworkRevocationChecker:108-109`).
7. **Cipher component fields** (authentication/encryption/mac) on `CipherSuiteInfo` from `OPSecUtil.CipherComponents`.
8. **Pacing check.** `enumerateCiphers` launches up to 44 handshakes at one host at once, and the REST `Checker` builds `ProbeChecker` without a `ConnectionGate` (`Checker:210`), so a single check opens ~17 candidate connections to one port. Confirm both are covered by the gate before v2 is the only implementation.
9. **Tests** driving `enumerateVersions`, `enumerateCiphers` (incl. preference), `enumerateGroups`, `validateCertChain`, `checkRevocation` (stapled / OCSP / CRL / timeout) through `ScriptedTransport`/`ManualScheduler`.

### Network scanner (`v2/nmap`)

10. **Print down hosts** in Normal and CSV (v1 `NormalFormatter:70-77`, `CSVFormatter:35-39`).
11. **Target parsing:** per-octet ranges, comma-separated tokens, and a warning instead of silent truncation above 65536 addresses.
12. **CLI aliases:** `--timeout`, attached `-p<spec>`, `-sP`, `-PN`, `-h/--help`, `-v`, `--max-parallelism` → `--max-inflight`, numeric/named `-T`. Decide explicitly whether `host=/range=/timeout=` survive.
13. **Port-spec dedupe** (and optionally sort).
14. **XML metadata** nmap consumers expect (DOCTYPE, `scaninfo`, `startstr`, host times, `hostnames type=PTR`, `finished elapsed summary`, `hosts down`) and Grepable header/footer.
15. **`HostReport.ip` on every path** and `hostname` via a non-blocking reverse lookup; otherwise delete the never-assigned `hostname/osGuess/osAccuracy/ttl` fields and their formatter branches.
16. **Default port set:** 1–1024 (v1) vs 20 (v2). A product decision; state it.
17. **One service-name table.** Merge `ServiceMatch` entries (1521 oracle, 520 route) into `WellKnownPorts`, and make `ProbeChecker` use it instead of its private 18-entry map with the stale "once the nmap subsystem is copied" comment (`v2/ProbeChecker:539-553`).
18. **An end-to-end `NMapScanner.scan()` test** against a loopback listener; remove the dead 4-arg `buildChecker`.

### Probe engine

19. Nothing functional. Optionally carry `https-classical.json` (the only `mode:"classical"` example) and `smtp-starttls.json` (the only `tls-facts` user); both were unbundled in v1 too. Unify the `probes-tried` fact (count in `cancelled()`, name list in `noneIdentified()`).

## 5. Cleanups in v2 worth doing at the same time

Dead: `PqcStatus.PQC_READY/NOT_READY`, `Grade.Pqc.PQC_CAPABLE`, `Grade.rank` D/E, duplicate
`keyExchangeAlgorithm`, `PQCSessionConfig.outNetData/inAppData`, `printStackTrace` calls in
`PQCSessionConfig`/`PQCTlsClient`, `ProbeTCPCallback.selectionKey`, `NMapScanner.log`, 4-arg
`buildChecker`, `PortState.UNFILTERED/CLOSED_FILTERED`. Also: gate the unconditional "Key
Mismatch" log, consider one `HTTPNIOSocket` per checker instead of one per candidate
(`ProbeContext:144`), and move the detached javadoc in `v2/runtime/ProbeUDPCallback:10-17`.

## 6. Do not port

`nmap/scan/raw/*`, `nmap/service/*`, `nmap/os/*`, the `arp` shell-out and every blocking
discovery method, `PacketDataConst.SNMP_PROBE`, `scanners/CipherSuiteEnumerator`,
`scanners/ProtocolVersionTester`, `PQCSSLStateMachine`, `PQCScanOptions.connectTimeoutMs`/
`enumerationTimeoutMs` (never read), reverse-DNS hostname derivation, `probe/ProbeDispatcher`,
`probe/discovery/HardenedHostDiscovery`, `probe/runtime/ProbeUDPCallback`.
