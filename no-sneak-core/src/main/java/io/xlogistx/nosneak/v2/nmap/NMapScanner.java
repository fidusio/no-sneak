package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.ProbeChecker;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;

import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.tools.HostScanner;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.runtime.ParallelJoin;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.CallableConsumer;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Staged, fully non-blocking network scanner (the embeddable core behind {@link NMap}):
 * <ol>
 *   <li><b>host discovery</b> (optional) over the target range — TCP-ping + optional ICMP;</li>
 *   <li><b>port scan</b> of the selected ports on each live host;</li>
 *   <li><b>probe scan</b> (optional) — run the probe engine on open ports to identify
 *       service / version / TLS / PQC (all bundled probes, or a named subset).</li>
 * </ol>
 * Everything rides the shared {@link NIOSocket} and {@link ParallelJoin} barriers, paced by a
 * {@link RateLimiter} (max in-flight + per-second). No blocking sockets, no per-target threads.
 */
public final class NMapScanner {

    public static final LogWrapper log = new LogWrapper(NMapScanner.class).setEnabled(false);

    /** Small common set used for TCP-ping host discovery. */
    public static final int[] DEFAULT_DISCOVERY_PORTS = {80, 443, 22, 3389, 445};

    private NMapScanner() {
    }

    /**
     * One-shot completion for a single scan unit (one connect attempt, or one probe sweep).
     * <p>
     * Both the callback and the launch-failure path can report the same unit:
     * {@link NIOSocket#addClientSocket} delivers {@code exception()} to the callback <em>and
     * then rethrows</em>, and the callback's own deadline can fire for a launch that never
     * registered. Counting such a unit twice releases the {@link RateLimiter} twice (driving
     * its in-flight counter negative, which disables {@code --max-inflight} entirely) and
     * decrements the {@link ParallelJoin} twice, firing the stage barrier before the remaining
     * units have answered — so the report is rendered mid-scan with ports and hosts still
     * outstanding. This guard makes the completion happen exactly once.
     */
    private static final class Unit {
        private final AtomicBoolean fired = new AtomicBoolean(false);
        private final RateLimiter limiter;
        private final ParallelJoin join;

        Unit(RateLimiter limiter, ParallelJoin join) {
            this.limiter = limiter;
            this.join = join;
        }

        /** @return true when this call performed the completion, false if it already happened. */
        boolean complete() {
            if (!fired.compareAndSet(false, true)) {
                return false;
            }
            limiter.release();
            join.childDone();
            return true;
        }

        boolean isComplete() {
            return fired.get();
        }
    }

    /** Run the staged scan; deliver the {@link ScanReport} once every stage completes. */
    public static void scan(NIOSocket nio, NMapConfig cfg, CallableConsumer<ScanReport> onComplete) {
        final ScanReport report = new ScanReport();
        report.startTimeMs = System.currentTimeMillis();
        report.config = cfg;
        for (String h : expand(cfg.targets)) {
            report.hosts.add(new HostReport(h));
        }
        if (report.hosts.isEmpty()) {
            report.endTimeMs = System.currentTimeMillis();
            onComplete.accept(report);
            return;
        }
        // The scan rides the pools the caller built its NIOSocket with, rather than reaching for
        // the process-wide defaults: an embedder that supplied its own executor/scheduler gets
        // the whole pipeline — connects, deadlines, pacing, ICMP and ARP — on those pools.
        final Executor executor = nio.getExecutor();
        final ScheduledExecutorService scheduler = nio.getScheduler();
        final RateLimiter limiter = new RateLimiter(scheduler, cfg.maxInFlight, cfg.maxPerSec);
        final int[] ports = cfg.ports != null ? cfg.ports : NMap.DEFAULT_PORTS;
        final int[] discPorts = cfg.discoveryPorts != null ? cfg.discoveryPorts : DEFAULT_DISCOVERY_PORTS;
        final int to = cfg.timeoutSec;

        // Layer-3/2 discovery comes from no-sneak-net. Opening the session costs a pcap handle or
        // raw socket plus reader threads per interface, so it is opened once for the whole scan
        // and closed at the end (HostScanner borrows the pools — closing it does not shut them
        // down). It never throws: a box without Npcap/root still yields a usable object in a
        // degraded mode, which is recorded as a warning so a silently ICMP-less scan is visible.
        final HostScanner hostScanner = openHostScanner(cfg, report, scheduler, executor);

        final Runnable finish = () -> {
            limiter.close();
            if (hostScanner != null) {
                try { hostScanner.close(); } catch (Exception ignored) { }
            }
            report.endTimeMs = System.currentTimeMillis();
            onComplete.accept(report);
        };
        final Runnable afterDiscovery =
                () -> portScanStage(nio, limiter, report, ports, cfg, to, finish);

        if (cfg.discovery) {
            // A CIDR that is on-link goes through no-sneak-net's purpose-built range sweep, which
            // does ARP+ICMP per host with its own tuned pacing. Doing it host-by-host instead —
            // one resolve at the 3 s default, one multi-probe ping, plus five TCP-connects — was
            // 55 s on a /24 where the sweep needs seconds, and the TCP-connects bought nothing:
            // on-link, ARP is the liveness oracle. Everything else (hostnames, off-link IPs,
            // dash-ranges) keeps the per-host path, where ARP cannot apply.
            Map<String, HostReport> byHost = new HashMap<>();
            for (HostReport hr : report.hosts) {
                byHost.put(hr.host, hr);
            }
            List<String> sweepCidrs = sweepableCidrs(cfg, hostScanner);
            Map<String, List<HostReport>> covered = new LinkedHashMap<>();
            Set<String> sweptHosts = new HashSet<>();
            for (String cidr : sweepCidrs) {
                List<HostReport> inRange = new ArrayList<>();
                for (String h : expand(Collections.singletonList(cidr))) {
                    HostReport hr = byHost.get(h);
                    if (hr != null && sweptHosts.add(h)) {
                        inRange.add(hr);
                    }
                }
                covered.put(cidr, inRange);
            }
            List<HostReport> perHost = new ArrayList<>();
            for (HostReport hr : report.hosts) {
                if (!sweptHosts.contains(hr.host)) {
                    perHost.add(hr);
                }
            }

            ParallelJoin hostsJoin =
                    new ParallelJoin(covered.size() + perHost.size(), afterDiscovery);
            for (Map.Entry<String, List<HostReport>> e : covered.entrySet()) {
                sweepRange(hostScanner, e.getKey(), e.getValue(), cfg, report, hostsJoin::childDone);
            }
            for (HostReport hr : perHost) {
                discoverHost(nio, limiter, hr, discPorts, cfg, to, hostScanner, hostsJoin::childDone);
            }
        } else {
            for (HostReport hr : report.hosts) {
                hr.up = true;
                hr.reason = "skipped";
            }
            afterDiscovery.run();
        }
    }

    /**
     * The declared CIDR targets that can be swept: layer 2 is available and the range is on-link.
     * Off-link ranges are excluded because ARP and NDP are link-local by definition — a sweep
     * there would fall back to whatever ICMP finds, which the per-host path already covers.
     */
    private static List<String> sweepableCidrs(NMapConfig cfg, HostScanner scanner) {
        List<String> out = new ArrayList<>();
        if (scanner == null || !cfg.discoveryArp || !scanner.mode().canLayer2()) {
            return out;
        }
        for (String t : cfg.targets) {
            String s = t == null ? "" : t.trim();
            if (s.indexOf('/') < 0) {
                continue;
            }
            try {
                if (scanner.interfaceFor(CidrRange.parse(s).networkAddress()).isPresent()) {
                    out.add(s);
                }
            } catch (RuntimeException ignored) {
                // Not a parseable CIDR — expand() leaves it literal and the per-host path takes it.
            }
        }
        return out;
    }

    /**
     * One no-sneak-net sweep over a whole range: ARP + ICMP per host with the library's own
     * concurrency and packet pacing. Its defaults are deliberately tuned for this (256 in flight,
     * a 1 s per-host timeout, a single ping probe because ARP is the liveness oracle), so only the
     * knobs the caller actually set are overridden.
     */
    private static void sweepRange(HostScanner scanner, String cidr, List<HostReport> covered,
                                   NMapConfig cfg, ScanReport report, Runnable done) {
        SweepOptions base = SweepOptions.defaults();
        // maxInFlight is deliberately NOT taken from --max-inflight: that flag caps concurrent
        // TCP connections in the port-scan stage, and forcing it onto the sweep's packet window
        // throttles ARP/ICMP to a crawl (a /24 at 64 did not finish in 100 s, versus 2 s on the
        // library default). --max-rate still applies, since that is a packet-rate policy.
        SweepOptions opts = new SweepOptions(
                base.maxInFlight(),
                cfg.maxPerSec > 0 ? cfg.maxPerSec : base.maxPacketsPerSecond(),
                base.perHostTimeout(),
                cfg.discoveryIcmp,
                cfg.discoveryArp,
                base.pingCount(),
                base.maxHosts());
        Map<String, HostReport> byIp = new HashMap<>();
        for (HostReport hr : covered) {
            byIp.put(hr.host, hr);
        }
        Runnable finishSweep = () -> {
            for (HostReport hr : covered) {
                if (!hr.up && hr.reason == null) {
                    hr.reason = "no-response";
                }
            }
            done.run();
        };
        try {
            scanner.sweep(cidr, opts, rec -> applySweepRecord(rec, byIp))
                    .whenComplete((summary, err) -> {
                        if (err != null) {
                            report.warnings.add("sweep of " + cidr + " failed: " + err);
                        }
                        finishSweep.run();
                    });
        } catch (Exception e) {
            report.warnings.add("sweep of " + cidr + " failed: " + e);
            finishSweep.run();
        }
    }

    /**
     * Fold one swept host into the report. A MAC and an ICMP reply are independent facts — a host
     * that answers ARP but not ICMP is alive and must be reported (see {@code HostRecord.alive()}).
     */
    private static void applySweepRecord(HostRecord rec, Map<String, HostReport> byIp) {
        if (rec == null || !rec.alive()) {
            return;
        }
        String ip = rec.ip().getHostAddress();
        HostReport hr = byIp.get(ip);
        if (hr == null) {
            return;
        }
        hr.up = true;
        hr.ip = ip;
        hr.reason = rec.mac().isPresent() ? "arp-reply" : "icmp-echo";
        rec.mac().ifPresent(m -> hr.mac = m.toString());
        rec.rtt().ifPresent(d -> hr.latencyMs = d.toMillis());
    }

    /**
     * Open the no-sneak-net session backing ICMP echo and ARP/NDP, or {@code null} when neither
     * is wanted. A degraded session is kept (ping still works in {@code ICMP_ONLY}) but reported.
     */
    private static HostScanner openHostScanner(NMapConfig cfg, ScanReport report,
                                               ScheduledExecutorService scheduler,
                                               Executor executor) {
        if (!cfg.discovery || (!cfg.discoveryIcmp && !cfg.discoveryArp)) {
            return null;
        }
        if (!(executor instanceof ExecutorService)) {
            report.warnings.add("ICMP/ARP discovery disabled: the NIOSocket executor is not an "
                    + "ExecutorService, which HostScanner requires as its dispatcher");
            return null;
        }
        try {
            HostScanner scanner = HostScanner.open(scheduler, (ExecutorService) executor);
            HostScanner.Mode mode = scanner.mode();
            if (cfg.discoveryIcmp && !mode.canPing()) {
                report.warnings.add("ICMP discovery unavailable: " + scanner.diagnostic());
            }
            if (cfg.discoveryArp && !mode.canLayer2()) {
                report.warnings.add("ARP/NDP discovery unavailable (mode " + mode + "): "
                        + scanner.diagnostic());
            }
            return scanner;
        } catch (Throwable t) {
            report.warnings.add("ICMP/ARP discovery unavailable: " + t);
            return null;
        }
    }

    // ==================== Stage 0: discovery ====================

    private static void discoverHost(NIOSocket nio, RateLimiter limiter, HostReport hr,
                                     int[] discPorts, NMapConfig cfg, int to,
                                     HostScanner hostScanner, Runnable hostDone) {
        final AtomicBoolean up = new AtomicBoolean(false);
        final java.util.concurrent.atomic.AtomicReference<String> reason =
                new java.util.concurrent.atomic.AtomicReference<>();
        final boolean icmp = cfg.discoveryIcmp && hostScanner != null && hostScanner.mode().canPing();
        final boolean arp = cfg.discoveryArp && hostScanner != null && hostScanner.mode().canLayer2();
        final int tcpUnits = cfg.discoveryTcp ? discPorts.length : 0;
        final int unitCount = tcpUnits + (icmp ? 1 : 0) + (arp ? 1 : 0);
        if (unitCount == 0) {
            // Every discovery method is off or unavailable. Treating that as "down" would drop
            // every target silently; say so instead and let the port scan decide.
            hr.up = true;
            hr.reason = "no-discovery-method";
            hostDone.run();
            return;
        }
        final ParallelJoin j = new ParallelJoin(unitCount, () -> {
            hr.up = up.get();
            hr.reason = up.get() ? reason.get() : "no-response";
            hostDone.run();
        });

        if (icmp) {
            icmpPing(limiter, hr, cfg, hostScanner, up, reason, j);
        }
        if (arp) {
            arpResolve(limiter, hr, hostScanner, up, reason, j);
        }
        if (cfg.discoveryTcp) {
            // TCP-ping: reachable if a discovery port connects (OPEN) or is refused (CLOSED).
            for (int p : discPorts) {
                final int port = p;
                final Unit unit = new Unit(limiter, j);
                limiter.submit(() -> {
                    try {
                        PortScanCallback cb = new PortScanCallback(
                                nio.getScheduler(), new IPAddress(hr.host, port), to, st -> {
                            if (st == PortState.OPEN || st == PortState.CLOSED) {
                                up.set(true);
                                reason.compareAndSet(null, "tcp-ping");
                            }
                            unit.complete();
                        });
                        nio.addClientSocket(cb, to + 2);
                    } catch (Exception e) {
                        unit.complete();
                    }
                });
            }
        }
    }

    /**
     * Real ICMP echo via no-sneak-net, replacing {@code InetAddress.isReachable} — which blocks a
     * pool thread for the whole timeout and, on Windows without privilege, silently degrades to a
     * TCP-7 connect that reports a live host as down. This is non-blocking end to end: the probes
     * are pipelined, so the wall time is one timeout rather than one per probe.
     */
    private static void icmpPing(RateLimiter limiter, HostReport hr, NMapConfig cfg,
                                 HostScanner hostScanner, AtomicBoolean up,
                                 java.util.concurrent.atomic.AtomicReference<String> reason,
                                 ParallelJoin j) {
        final Unit unit = new Unit(limiter, j);
        limiter.submit(() -> {
            try {
                hostScanner.ping(hr.host, Math.max(cfg.icmpProbes, 1),
                                Duration.ofSeconds(Math.max(cfg.timeoutSec, 1)))
                        .whenComplete((res, err) -> {
                            try {
                                // observedOnWire(), not reachable(): pinging one of our own
                                // addresses answers from local configuration without a packet.
                                if (res != null && res.observedOnWire()) {
                                    up.set(true);
                                    reason.compareAndSet(null, "icmp-echo");
                                    if (res.measured()) {
                                        hr.latencyMs = res.avgRtt().toMillis();
                                    }
                                    if (hr.ip == null) {
                                        hr.ip = res.target().getHostAddress();
                                    }
                                }
                            } finally {
                                unit.complete();
                            }
                        });
            } catch (Exception e) {
                unit.complete();
            }
        });
    }

    /**
     * ARP (IPv4) / NDP (IPv6) for on-link targets — the remote MAC that no JDK API exposes, and
     * the reason {@code HostReport.mac} existed unpopulated until no-sneak-net shipped a layer-2
     * backend. A host that answers ARP but not ICMP is alive and must be reported as such.
     * Off-link targets are skipped rather than attempted: ARP and NDP are link-local by
     * definition, so asking beyond the segment would only ever return the router's MAC.
     */
    private static void arpResolve(RateLimiter limiter, HostReport hr, HostScanner hostScanner,
                                   AtomicBoolean up,
                                   java.util.concurrent.atomic.AtomicReference<String> reason,
                                   ParallelJoin j) {
        final Unit unit = new Unit(limiter, j);
        limiter.submit(() -> {
            try {
                hostScanner.lookup(hr.host)
                        .thenCompose(ip -> {
                            if (hr.ip == null && ip != null) {
                                hr.ip = ip.getHostAddress();
                            }
                            return ip != null && hostScanner.interfaceFor(ip).isPresent()
                                    ? hostScanner.resolve(ip, HostScanner.DEFAULT_RESOLVE_TIMEOUT)
                                    : CompletableFuture.completedFuture(null);
                        })
                        .whenComplete((rr, err) -> {
                            try {
                                if (rr != null && rr.resolved()) {
                                    hr.mac = rr.mac().get().toString();
                                    up.set(true);
                                    reason.compareAndSet(null, "arp-reply");
                                }
                            } finally {
                                unit.complete();
                            }
                        });
            } catch (Exception e) {
                unit.complete();
            }
        });
    }

    // ==================== Stage 1: port scan ====================

    private static void portScanStage(NIOSocket nio, RateLimiter limiter, ScanReport report,
                                      int[] ports, NMapConfig cfg, int to, Runnable onDone) {
        List<HostReport> live = new ArrayList<>();
        for (HostReport hr : report.hosts) {
            if (hr.up) {
                live.add(hr);
            }
        }
        if (live.isEmpty()) {
            onDone.run();
            return;
        }
        final ParallelJoin hostsJoin = new ParallelJoin(live.size(),
                () -> probeStage(nio, limiter, report, cfg, to, onDone));
        for (HostReport hr : live) {
            scanHostPorts(nio, limiter, hr, ports, to, hostsJoin::childDone);
        }
    }

    private static void scanHostPorts(NIOSocket nio, RateLimiter limiter, HostReport hr,
                                      int[] ports, int to, Runnable hostDone) {
        final List<PortReport> prs = new ArrayList<>();
        for (int p : ports) {
            PortReport pr = new PortReport(p, PortState.FILTERED);
            hr.ports.add(pr);
            prs.add(pr);
        }
        final ParallelJoin j = new ParallelJoin(prs.size(), hostDone);
        for (PortReport pr : prs) {
            final PortReport target = pr;
            final Unit unit = new Unit(limiter, j);
            limiter.submit(() -> {
                try {
                    PortScanCallback cb = new PortScanCallback(
                            nio.getScheduler(), new IPAddress(hr.host, target.port), to, st -> {
                        target.state = st;
                        target.reason = st == PortState.OPEN ? "syn-ack"
                                : st == PortState.CLOSED ? "conn-refused" : "no-response";
                        unit.complete();
                    });
                    nio.addClientSocket(cb, to + 2);
                } catch (Exception e) {
                    // Only classify here if the callback never got to: NIOSocket delivers
                    // exception() before rethrowing, and that path has already derived the
                    // state (FILTERED for unreachable, CLOSED for refused). Overwriting it
                    // would report a filtered port as closed.
                    if (!unit.isComplete()) {
                        target.state = PortState.FILTERED;
                        target.reason = "connect-error";
                    }
                    unit.complete();
                }
            });
        }
    }

    // ==================== Stage 2: probe (service/version/TLS) ====================

    private static void probeStage(NIOSocket nio, RateLimiter limiter, ScanReport report,
                                   NMapConfig cfg, int to, Runnable onDone) {
        if (!cfg.probeScan) {
            onDone.run();
            return;
        }
        // Collect all open host:ports.
        final List<HostReport> hostsOf = new ArrayList<>();
        final List<PortReport> openPorts = new ArrayList<>();
        for (HostReport hr : report.hosts) {
            for (PortReport pr : hr.openPorts()) {
                hostsOf.add(hr);
                openPorts.add(pr);
            }
        }
        if (openPorts.isEmpty()) {
            onDone.run();
            return;
        }
        final ProbeChecker checker = buildChecker(nio, cfg, to, report);
        final ParallelJoin j = new ParallelJoin(openPorts.size(), onDone);
        for (int i = 0; i < openPorts.size(); i++) {
            final String host = hostsOf.get(i).host;
            final PortReport pr = openPorts.get(i);
            final Unit unit = new Unit(limiter, j);
            limiter.submit(() -> {
                try {
                    checker.check(host, pr.port, new CallableConsumerTask<ProbeResult>()
                            .setConsumer(r -> {
                                pr.probe = r;
                                unit.complete();
                            })
                            .setExceptionCallback(t -> unit.complete()));
                } catch (Exception e) {
                    unit.complete();
                }
            });
        }
    }

    private static ProbeChecker buildChecker(NIOSocket nio, NMapConfig cfg, int to, ScanReport report) {
        // The catalog is bundled + caller-supplied definitions. ProbeChecker's constructor does
        // NOT sort — only withBundled() does, via loadBundled — and orderedCandidates preserves
        // input order within each tier, so the merged list has to be re-sorted here or an extra
        // probe's priority is silently ignored.
        List<ProbeDefinition> catalog = new ArrayList<>(ProbeDefinitionLoader.loadBundled());
        catalog.addAll(cfg.extraProbes);
        catalog.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));

        if (cfg.probeNames == null || cfg.probeNames.isEmpty()) {
            return new ProbeChecker(nio, catalog).timeoutInSec(to);
        }
        List<ProbeDefinition> subset = new ArrayList<>();
        Set<String> matched = new LinkedHashSet<>();
        for (ProbeDefinition d : catalog) {
            if (cfg.probeNames.contains(d.getName())) {
                subset.add(d);
                matched.add(d.getName());
            }
        }
        // A requested name that matches nothing is almost always a typo. Report it rather than
        // silently scanning with a probe set the caller did not ask for.
        for (String requested : cfg.probeNames) {
            if (!matched.contains(requested)) {
                report.warnings.add("unknown probe '" + requested + "' (ignored)");
            }
        }
        if (subset.isEmpty()) {
            report.warnings.add("no requested probe matched; falling back to all "
                    + catalog.size() + " probes");
            return new ProbeChecker(nio, catalog).timeoutInSec(to);
        }
        return new ProbeChecker(nio, subset).timeoutInSec(to);
    }

    // ==================== Target expansion (host / CIDR / range) ====================

    /** Expand hostnames, IPs, CIDR ({@code a.b.c.d/nn}) and ranges ({@code a.b.c.d-e} or
     *  {@code a.b.c.d-a.b.c.f}) into an ordered, de-duplicated target list. Non-IPv4 tokens
     *  (hostnames) pass through unchanged. Expansion is capped at 65536 addresses per token. */
    public static List<String> expand(List<String> targets) {
        Set<String> out = new LinkedHashSet<>();
        if (targets == null) {
            return new ArrayList<>();
        }
        for (String raw : targets) {
            if (raw == null) continue;
            String t = raw.trim();
            if (t.isEmpty()) continue;
            int slash = t.indexOf('/');
            long lo = -1, hi = -1;
            if (slash > 0) {
                long base = ipToLong(t.substring(0, slash));
                int bits = parseIntSafe(t.substring(slash + 1), -1);
                if (base >= 0 && bits >= 0 && bits <= 32) {
                    long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                    long network = base & mask;
                    long broadcast = network | (~mask & 0xFFFFFFFFL);
                    lo = bits >= 31 ? network : network + 1;
                    hi = bits >= 31 ? broadcast : broadcast - 1;
                }
            } else {
                int dash = t.indexOf('-');
                if (dash > 0) {
                    long l = ipToLong(t.substring(0, dash));
                    String rt = t.substring(dash + 1).trim();
                    if (l >= 0) {
                        long h = ipToLong(rt);
                        if (h < 0) { // "a.b.c.d-e" last-octet form
                            int last = parseIntSafe(rt, -1);
                            if (last >= 0 && last <= 255) {
                                h = (l & 0xFFFFFF00L) | (last & 0xFFL);
                            }
                        }
                        if (h >= 0) {
                            lo = Math.min(l, h);
                            hi = Math.max(l, h);
                        }
                    }
                }
            }
            if (lo >= 0 && hi >= lo) {
                long count = Math.min(hi - lo + 1, 65536);
                for (long i = 0; i < count; i++) {
                    out.add(longToIp(lo + i));
                }
            } else {
                out.add(t); // hostname or single IP — pass through
            }
        }
        return new ArrayList<>(out);
    }

    private static long ipToLong(String s) {
        if (s == null) return -1;
        String[] o = s.trim().split("\\.");
        if (o.length != 4) return -1;
        long v = 0;
        for (String part : o) {
            int b = parseIntSafe(part, -1);
            if (b < 0 || b > 255) return -1;
            v = (v << 8) | b;
        }
        return v;
    }

    private static String longToIp(long v) {
        return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF) + "." + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
    }

    private static int parseIntSafe(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }
}
