package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.ProbeChecker;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;

import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.tools.HostScanner;
import io.xlogistx.nosneak.result.ProbeResult;
import io.xlogistx.nosneak.runtime.ParallelJoin;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.CallableConsumer;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.net.InetAddress;
import java.net.InetSocketAddress;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Staged, fully non-blocking network scanner (the embeddable core behind {@link NMap}):
 * <ol>
 *   <li><b>host discovery</b> (optional) over the target range — TCP-ping + optional ICMP;</li>
 *   <li><b>reverse DNS</b> (unless {@code -n}) — one PTR datagram per live host (every host
 *       with {@code -R}) through the same gate, filling {@code HostReport.hostname};</li>
 *   <li><b>port scan</b> of the selected TCP ports on each live host;</li>
 *   <li><b>UDP scan</b> (when UDP ports were named) — one datagram, one retransmit, per port;</li>
 *   <li><b>probe scan</b> (optional) — run the probe engine on open ports to identify
 *       service / version / TLS / PQC (all bundled probes, or a named subset).</li>
 * </ol>
 * Everything rides the shared {@link NIOSocket} and {@link ParallelJoin} barriers, paced by a
 * {@link ScanGate} (max in-flight + per-second) that <em>every</em> socket goes through —
 * the port scans directly, the probe stage through {@link ProbeChecker}'s connection gate. No
 * blocking sockets, no per-target threads.
 */
public final class NMapScanner {

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
     * registered. Counting such a unit twice releases the {@link ScanGate} twice (driving
     * its in-flight counter negative, which disables {@code --max-inflight} entirely) and
     * decrements the {@link ParallelJoin} twice, firing the stage barrier before the remaining
     * units have answered — so the report is rendered mid-scan with ports and hosts still
     * outstanding. This guard makes the completion happen exactly once.
     */
    static final class Unit {   // package-private so UnitTest can pin the exactly-once guard
        private final AtomicBoolean fired = new AtomicBoolean(false);
        private final ScanGate limiter;
        private final ParallelJoin join;

        Unit(ScanGate limiter, ParallelJoin join) {
            this.limiter = limiter;
            this.join = join;
        }

        /**
         * A barrier-only unit: it holds no limiter slot, because what it waits for (a probe
         * sweep) admits its own sockets through the limiter. Holding a slot here as well would
         * let the per-port units fill the cap and leave no room for the connections they wait
         * on — a deadlock broken only by the connect timeouts.
         */
        Unit(ParallelJoin join) {
            this(null, join);
        }

        /** @return true when this call performed the completion, false if it already happened. */
        boolean complete() {
            if (!fired.compareAndSet(false, true)) {
                return false;
            }
            if (limiter != null) {
                limiter.release();
            }
            join.childDone();
            return true;
        }

        boolean isComplete() {
            return fired.get();
        }
    }

    /**
     * A running scan. {@link #cancel()} stops it: every stage boundary and every queued launch
     * checks the flag and completes its unit without touching the wire; every connect and
     * datagram probe in flight is aborted (its deadline cancelled, its socket closed, its port
     * reported {@code cancelled}); every probe sweep in flight is torn down and delivers a
     * {@code cancelled} result; the discovery session is closed so its sweeps, pings and
     * resolves return at once. The barriers then drain and the report is delivered exactly
     * once, with {@link ScanReport#cancelled} set and a warning stating what was skipped —
     * nothing keeps running unreferenced in the background, which is what a timed-out
     * {@code future.get} used to leave behind.
     * <p>
     * Idempotent: a second {@code cancel()} is a no-op. Nothing here blocks; an abort is a
     * flag flip plus one exactly-once completion per unit, all through the guards that already
     * make double completion impossible ({@link Unit}, the callbacks' {@code finish}).
     */
    public static final class ScanHandle {
        private final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final Set<Runnable> aborts = ConcurrentHashMap.newKeySet();
        private final List<Runnable> onCancel = new CopyOnWriteArrayList<>();
        private final CompletableFuture<ScanReport> completion = new CompletableFuture<>();

        ScanHandle() {
        }

        /** @return true if this call stopped the scan; false if it was already cancelled */
        public boolean cancel() {
            if (!cancelled.compareAndSet(false, true)) {
                return false;
            }
            for (Runnable r : onCancel) {
                try { r.run(); } catch (Exception ignored) { }
            }
            for (Runnable a : aborts) {
                try { a.run(); } catch (Exception ignored) { }
            }
            return true;
        }

        public boolean isCancelled() {
            return cancelled.get();
        }

        /** Completes with the report the scan delivered (partial when cancelled); never exceptionally. */
        public CompletableFuture<ScanReport> completion() {
            return completion;
        }

        /** An in-flight probe that {@link #cancel()} must abort; aborted at once if already cancelled. */
        void track(Runnable abort) {
            aborts.add(abort);
            if (cancelled.get()) {
                abort.run();
            }
        }

        void untrack(Runnable abort) {
            aborts.remove(abort);
        }

        /** Something to run on cancel (close the discovery session, tear down probe sweeps). */
        void onCancel(Runnable action) {
            onCancel.add(action);
            if (cancelled.get()) {
                action.run();
            }
        }

        /** @return probes registered and not yet completed (visible for tests) */
        int tracked() {
            return aborts.size();
        }

        void deliver(ScanReport report) {
            completion.complete(report);
        }
    }

    /**
     * Run the staged scan; deliver the {@link ScanReport} once every stage completes — or once
     * the returned handle is cancelled, with whatever had finished by then.
     */
    public static ScanHandle scan(NIOSocket nio, NMapConfig cfg, CallableConsumer<ScanReport> onComplete) {
        return scan(nio, cfg, onComplete, new ScanHandle());
    }

    /** Seam for tests: a handle that may already be cancelled before the first stage runs. */
    static ScanHandle scan(NIOSocket nio, NMapConfig cfg, CallableConsumer<ScanReport> onComplete,
                           ScanHandle handle) {
        final ScanReport report = new ScanReport();
        report.startTimeMs = System.currentTimeMillis();
        report.config = cfg;
        for (String h : expand(cfg.targets, report.warnings)) {
            HostReport hr = new HostReport(h);
            hr.startTimeMs = report.startTimeMs;
            if (isIpLiteral(h)) {
                hr.ip = h; // known before any packet; a hostname's ip is set by its first unit
            }
            report.hosts.add(hr);
        }
        if (report.hosts.isEmpty()) {
            report.endTimeMs = System.currentTimeMillis();
            handle.deliver(report);
            onComplete.accept(report);
            return handle;
        }
        // The scan rides the pools the caller built its NIOSocket with, rather than reaching for
        // the process-wide defaults: an embedder that supplied its own executor/scheduler gets
        // the whole pipeline — connects, deadlines, pacing, ICMP and ARP — on those pools.
        final Executor executor = nio.getExecutor();
        final ScheduledExecutorService scheduler = nio.getScheduler();
        final ScanGate limiter = new ScanGate(scheduler, cfg.maxInFlight, cfg.maxPerSec);
        final int[] ports = cfg.ports != null ? cfg.ports : NMap.DEFAULT_PORTS;
        final int[] discPorts = cfg.discoveryPorts != null ? cfg.discoveryPorts : DEFAULT_DISCOVERY_PORTS;
        final int to = cfg.timeoutSec;

        // Layer-3/2 discovery comes from no-sneak-net. Opening the session costs a pcap handle or
        // raw socket plus reader threads per interface, so it is opened once for the whole scan
        // and closed at the end (HostScanner borrows the pools — closing it does not shut them
        // down). It never throws: a box without Npcap/root still yields a usable object in a
        // degraded mode, which is recorded as a warning so a silently ICMP-less scan is visible.
        final HostScanner hostScanner = openHostScanner(cfg, report, scheduler, executor);
        if (hostScanner != null) {
            // Closing the session is what makes a sweep, ping or resolve in flight come back
            // immediately (ERROR/IO rather than a full timeout), and a queued one return at once.
            handle.onCancel(() -> { try { hostScanner.close(); } catch (Exception ignored) { } });
        }

        final AtomicBoolean finished = new AtomicBoolean(false);
        final Runnable finish = () -> {
            if (!finished.compareAndSet(false, true)) {
                return;
            }
            limiter.close();
            if (hostScanner != null) {
                try { hostScanner.close(); } catch (Exception ignored) { }
            }
            if (handle.isCancelled()) {
                report.cancelled = true;
                report.warnings.add(cancellationSummary(report));
            }
            report.endTimeMs = System.currentTimeMillis();
            for (HostReport hr : report.hosts) {
                if (hr.endTimeMs == 0) {
                    hr.endTimeMs = report.endTimeMs; // the last stage that touched it just ended
                }
            }
            handle.deliver(report);
            onComplete.accept(report);
        };
        final Runnable afterDiscovery =
                () -> reverseDnsStage(nio, limiter, report, cfg, handle,
                        () -> portScanStage(nio, limiter, report, ports, cfg, to, handle,
                                () -> udpScanStage(nio, limiter, report, cfg, to, handle,
                                        () -> probeStage(nio, limiter, report, cfg, to, handle, finish))));

        if (handle.isCancelled()) {
            // Cancelled before the first packet: nothing was learned, say so, deliver once.
            for (HostReport hr : report.hosts) {
                hr.reason = "cancelled";
            }
            finish.run();
            return handle;
        }
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
                discoverHost(nio, limiter, hr, discPorts, cfg, to, hostScanner, handle, hostsJoin::childDone);
            }
        } else {
            for (HostReport hr : report.hosts) {
                hr.up = true;
                hr.reason = "skipped";
            }
            afterDiscovery.run();
        }
        return handle;
    }

    /** How far a scan got — what a cancelled report can honestly claim. Pure. */
    public record Progress(int hostsDecided, int hostsTotal, int portsDone, int portsSkipped) {
        /** The one-line form the CLI and the app both print. */
        public String cancelledLine() {
            return "Scan cancelled: " + hostsDecided + " of " + hostsTotal + " host(s) decided, "
                    + portsDone + " port(s) completed, " + portsSkipped + " abandoned";
        }
    }

    public static Progress progress(ScanReport report) {
        int hostsDecided = 0;
        int portsDone = 0;
        int portsSkipped = 0;
        for (HostReport hr : report.hosts) {
            if (hr.reason != null && !"cancelled".equals(hr.reason)) {
                hostsDecided++;
            }
            for (PortReport pr : hr.ports) {
                if ("cancelled".equals(pr.reason)) {
                    portsSkipped++;
                } else {
                    portsDone++;
                }
            }
        }
        return new Progress(hostsDecided, report.hosts.size(), portsDone, portsSkipped);
    }

    /** The warning a cancelled report carries: what finished, what did not. Pure. */
    static String cancellationSummary(ScanReport report) {
        Progress p = progress(report);
        return "scan cancelled: " + p.hostsDecided() + " of " + p.hostsTotal()
                + " host(s) had a discovery verdict, " + p.portsDone() + " port(s) completed, "
                + p.portsSkipped() + " port(s) abandoned";
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
            if (t == null) {
                continue;
            }
            for (String piece : t.split(",")) { // a token may name several targets (expand's grammar)
                String s = piece.trim();
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

    private static void discoverHost(NIOSocket nio, ScanGate limiter, HostReport hr,
                                     int[] discPorts, NMapConfig cfg, int to,
                                     HostScanner hostScanner, ScanHandle handle, Runnable hostDone) {
        if (handle.isCancelled()) {
            hr.reason = "cancelled";
            hostDone.run();
            return;
        }
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
            if (!hr.up) {
                hr.endTimeMs = System.currentTimeMillis(); // no later stage visits a down host
            }
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
                    if (handle.isCancelled()) {
                        unit.complete();
                        return;
                    }
                    final Runnable[] abort = new Runnable[1];
                    try {
                        PortScanCallback cb = new PortScanCallback(
                                nio.getScheduler(), new IPAddress(hr.host, port), to, st -> {
                            if (abort[0] != null) {
                                handle.untrack(abort[0]);
                            }
                            if (st == PortState.OPEN || st == PortState.CLOSED) {
                                up.set(true);
                                reason.compareAndSet(null, "tcp-ping");
                            }
                            unit.complete();
                        });
                        if (hr.ip == null) {
                            hr.ip = cb.remoteIp(); // the resolved address, whatever the port says
                        }
                        abort[0] = cb::abort;
                        handle.track(abort[0]);
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
    private static void icmpPing(ScanGate limiter, HostReport hr, NMapConfig cfg,
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
    private static void arpResolve(ScanGate limiter, HostReport hr, HostScanner hostScanner,
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

    // ==================== Stage 0b: reverse DNS ====================

    /**
     * One PTR datagram per host whose address is known, through the same gate as every other
     * unit: live hosts by default, every host with {@code -R}, nobody with {@code -n}. A
     * hostname target that never resolved has no address to reverse and is skipped. The lookup
     * never blocks — see {@link ReverseDnsCallback} — and a host whose resolver stays silent
     * simply keeps a null {@code hostname}.
     */
    private static void reverseDnsStage(NIOSocket nio, ScanGate limiter, ScanReport report,
                                        NMapConfig cfg, ScanHandle handle, Runnable onDone) {
        if (cfg.reverseDns == NMapConfig.ReverseDns.NEVER || handle.isCancelled()) {
            onDone.run();
            return;
        }
        final Map<HostReport, InetAddress> wanted = new LinkedHashMap<>();
        for (HostReport hr : report.hosts) {
            if (hr.hostname != null || !(hr.up || cfg.reverseDns == NMapConfig.ReverseDns.ALL)) {
                continue;
            }
            InetAddress addr = literalAddress(hr.ip != null ? hr.ip : hr.host);
            if (addr != null) {
                wanted.put(hr, addr);
            }
        }
        if (wanted.isEmpty()) {
            onDone.run();
            return;
        }
        final InetSocketAddress server = ReverseDnsCallback.resolverAddress(cfg.dnsServer, report.warnings);
        final ParallelJoin j = new ParallelJoin(wanted.size(), onDone);
        for (Map.Entry<HostReport, InetAddress> e : wanted.entrySet()) {
            final HostReport hr = e.getKey();
            final InetAddress addr = e.getValue();
            final Unit unit = new Unit(limiter, j);
            limiter.submit(() -> {
                if (handle.isCancelled()) {
                    unit.complete();
                    return;
                }
                final Runnable[] abort = new Runnable[1];
                try {
                    ReverseDnsCallback cb = new ReverseDnsCallback(
                            nio.getScheduler(), addr, server, cfg.dnsTimeoutMs, r -> {
                        if (abort[0] != null) {
                            handle.untrack(abort[0]);
                        }
                        if (r.hostname() != null) {
                            hr.hostname = r.hostname();
                        }
                        if (!hr.up) {
                            hr.endTimeMs = System.currentTimeMillis(); // -R: this was its last unit
                        }
                        unit.complete();
                    });
                    abort[0] = cb::abort;
                    handle.track(abort[0]);
                    nio.addDatagramSocket(new InetSocketAddress(0), cb); // ephemeral local bind
                } catch (Exception ex) {
                    // The kickoff failed (bind, connect or send); the hostname stays unknown.
                    unit.complete();
                }
            });
        }
    }

    /** An {@link InetAddress} for an IP literal, built without any lookup; null for anything else. */
    static InetAddress literalAddress(String s) {
        if (!isIpLiteral(s)) {
            return null;
        }
        try {
            return InetAddress.getByName(s.trim()); // a literal never reaches the resolver
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== Stage 1: port scan ====================

    private static void portScanStage(NIOSocket nio, ScanGate limiter, ScanReport report,
                                      int[] ports, NMapConfig cfg, int to, ScanHandle handle,
                                      Runnable onDone) {
        if (handle.isCancelled()) {
            onDone.run();
            return;
        }
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
        final ParallelJoin hostsJoin = new ParallelJoin(live.size(), onDone);
        for (HostReport hr : live) {
            scanHostPorts(nio, limiter, hr, ports, to, handle, hostsJoin::childDone);
        }
    }

    private static void scanHostPorts(NIOSocket nio, ScanGate limiter, HostReport hr,
                                      int[] ports, int to, ScanHandle handle, Runnable hostDone) {
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
                if (handle.isCancelled()) {
                    // Queued behind the cap when the scan was stopped: never launched.
                    target.reason = "cancelled";
                    unit.complete();
                    return;
                }
                final Runnable[] abort = new Runnable[1];
                try {
                    // The callback carries the reason it observed; the scanner no longer guesses
                    // one from the state. A completed connect reads "connected" — it is a full
                    // handshake, not a SYN/ACK. RTT and a volunteered banner ride the same
                    // connection (PortScanCallback javadoc); TTL is unobservable here.
                    PortScanCallback cb = new PortScanCallback(
                            nio.getScheduler(), new IPAddress(hr.host, target.port), to, true, r -> {
                        if (abort[0] != null) {
                            handle.untrack(abort[0]);
                        }
                        target.state = r.state();
                        target.reason = r.reason();
                        target.rttMs = r.rttMs();
                        target.banner = r.banner();
                        unit.complete();
                    });
                    if (hr.ip == null) {
                        hr.ip = cb.remoteIp(); // -Pn: no discovery unit ran, so this is the first to know
                    }
                    abort[0] = cb::abort;
                    handle.track(abort[0]);
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

    // ==================== Stage 1b: UDP scan ====================

    /**
     * One datagram probe per named UDP port on every live host, through the same limiter as the
     * TCP connects. Runs only when UDP ports were named ({@code -sU} or {@code -p U:...}).
     */
    private static void udpScanStage(NIOSocket nio, ScanGate limiter, ScanReport report,
                                     NMapConfig cfg, int to, ScanHandle handle, Runnable onDone) {
        final int[] udpPorts = cfg.udpPorts;
        if (udpPorts == null || udpPorts.length == 0 || handle.isCancelled()) {
            onDone.run();
            return;
        }
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
        final ParallelJoin hostsJoin = new ParallelJoin(live.size(), onDone);
        for (HostReport hr : live) {
            scanHostUdpPorts(nio, limiter, hr, udpPorts, to, handle, hostsJoin::childDone);
        }
    }

    private static void scanHostUdpPorts(NIOSocket nio, ScanGate limiter, HostReport hr,
                                         int[] ports, int to, ScanHandle handle, Runnable hostDone) {
        final List<PortReport> prs = new ArrayList<>();
        for (int p : ports) {
            // Pre-seeded with UDP's honest default: nothing heard yet is open|filtered.
            PortReport pr = new PortReport(p, PortState.OPEN_FILTERED);
            pr.protocol = "udp";
            pr.reason = "no-response";
            hr.ports.add(pr);
            prs.add(pr);
        }
        final ParallelJoin j = new ParallelJoin(prs.size(), hostDone);
        for (PortReport pr : prs) {
            final PortReport target = pr;
            final Unit unit = new Unit(limiter, j);
            limiter.submit(() -> {
                if (handle.isCancelled()) {
                    target.state = PortState.FILTERED;
                    target.reason = "cancelled";
                    unit.complete();
                    return;
                }
                final Runnable[] abort = new Runnable[1];
                try {
                    UdpScanCallback cb = new UdpScanCallback(
                            nio.getScheduler(), udpTarget(hr, target.port),
                            UdpProbePayloads.forPort(target.port), to, r -> {
                        if (abort[0] != null) {
                            handle.untrack(abort[0]);
                        }
                        target.state = r.state();
                        target.reason = r.reason();
                        target.rttMs = r.rttMs();
                        target.banner = r.banner();
                        unit.complete();
                    });
                    abort[0] = cb::abort;
                    handle.track(abort[0]);
                    nio.addDatagramSocket(new InetSocketAddress(0), cb); // ephemeral local bind
                } catch (Exception e) {
                    // The kickoff (connect + first send) failed before the callback could
                    // classify anything: the connect-time error is the verdict.
                    if (!unit.isComplete()) {
                        UdpScanCallback.Classification c = UdpScanCallback.classify(e);
                        target.state = c.state();
                        target.reason = c.reason();
                    }
                    unit.complete();
                }
            });
        }
    }

    /** The datagram socket's remote: the discovered IP when there is one, else the target as named. */
    private static InetSocketAddress udpTarget(HostReport hr, int port) throws Exception {
        if (hr.ip != null) {
            return new InetSocketAddress(InetAddress.getByName(hr.ip), port);
        }
        return new InetSocketAddress(hr.host, port);
    }

    // ==================== Stage 2: probe (service/version/TLS) ====================

    /**
     * Which ports the probe stage visits. TCP: anything potentially open (the connect scan's
     * OPEN, and the nmap states the model allows). UDP: only a port that actually answered — an
     * open|filtered UDP port is one nobody spoke to, and running the UDP probes against every
     * silent port would cost a full timeout each for no evidence.
     */
    static boolean probeable(PortReport pr) {
        if (pr.state == null) {
            return false;
        }
        if ("udp".equalsIgnoreCase(pr.protocol)) {
            return pr.state == PortState.OPEN;
        }
        return pr.state.isPotentiallyOpen();
    }

    private static void probeStage(NIOSocket nio, ScanGate limiter, ScanReport report,
                                   NMapConfig cfg, int to, ScanHandle handle, Runnable onDone) {
        if (!cfg.probeScan || handle.isCancelled()) {
            onDone.run();
            return;
        }
        // Collect all open host:ports.
        final List<HostReport> hostsOf = new ArrayList<>();
        final List<PortReport> openPorts = new ArrayList<>();
        for (HostReport hr : report.hosts) {
            for (PortReport pr : hr.ports) {
                if (probeable(pr)) {
                    hostsOf.add(hr);
                    openPorts.add(pr);
                }
            }
        }
        if (openPorts.isEmpty()) {
            onDone.run();
            return;
        }
        // The checker admits every socket it opens — each candidate's connection and the
        // enumeration children of a deep TLS probe — through the scan's limiter (P4). The
        // per-port unit below is therefore a barrier only; it must NOT hold a limiter slot of
        // its own, or the ports would fill the cap and starve the connections they wait for.
        final ProbeChecker checker = buildChecker(nio, cfg, to, report, limiter);
        // A cancel tears every sweep down; each delivers a "cancelled" result, so the units
        // below complete and the barrier drains.
        handle.onCancel(checker::cancelAll);
        final ParallelJoin j = new ParallelJoin(openPorts.size(), onDone);
        for (int i = 0; i < openPorts.size(); i++) {
            final String host = hostsOf.get(i).host;
            final PortReport pr = openPorts.get(i);
            final String transport = "udp".equalsIgnoreCase(pr.protocol) ? "udp" : "tcp";
            final Unit unit = new Unit(j);
            if (handle.isCancelled()) {
                unit.complete();
                continue;
            }
            try {
                checker.check(host, pr.port, transport, new CallableConsumerTask<ProbeResult>()
                        .setConsumer(r -> {
                            pr.probe = r;
                            unit.complete();
                        })
                        .setExceptionCallback(t -> unit.complete()));
            } catch (Exception e) {
                unit.complete();
            }
        }
    }

    /** The probe catalog for this scan; {@code gate} null means unpaced (tests only). */
    private static ProbeChecker buildChecker(NIOSocket nio, NMapConfig cfg, int to, ScanReport report,
                                             ScanGate gate) {
        // The catalog is bundled + caller-supplied definitions. ProbeChecker's constructor does
        // NOT sort — only withBundled() does, via loadBundled — and orderedCandidates preserves
        // input order within each tier, so the merged list has to be re-sorted here or an extra
        // probe's priority is silently ignored.
        // ONE definition per name. A stored (subject-authored) probe that shares a bundled
        // probe's name REPLACES it — the subject wrote it deliberately, and running both was
        // two connections per open port for one answer (PENDING-ISSUES P22). Among stored
        // duplicates the first wins. Both cases are reported, never silent.
        java.util.Map<String, ProbeDefinition> byName = new LinkedHashMap<>();
        for (ProbeDefinition d : ProbeDefinitionLoader.loadBundled()) {
            byName.put(d.getName(), d);
        }
        Set<String> storedNames = new java.util.HashSet<>();
        for (ProbeDefinition d : cfg.extraProbes) {
            if (d == null || d.getName() == null) {
                continue;
            }
            if (!storedNames.add(d.getName())) {
                report.warnings.add("duplicate stored probe '" + d.getName()
                        + "' ignored; the first definition with that name is used");
                continue;
            }
            if (byName.containsKey(d.getName())) {
                report.warnings.add("stored probe '" + d.getName()
                        + "' shadows the bundled probe of the same name");
            }
            byName.put(d.getName(), d);
        }
        List<ProbeDefinition> catalog = new ArrayList<>(byName.values());
        catalog.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));

        if (cfg.probeNames == null || cfg.probeNames.isEmpty()) {
            return new ProbeChecker(nio, catalog, gate).timeoutInSec(to);
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
            return new ProbeChecker(nio, catalog, gate).timeoutInSec(to);
        }
        return new ProbeChecker(nio, subset, gate).timeoutInSec(to);
    }

    // ==================== Target expansion (host / CIDR / range) ====================

    /** Most addresses one spec may expand to; beyond it the spec is cut short and a warning says so. */
    public static final int MAX_EXPANSION = 65536;

    /**
     * Expand a target list into an ordered, de-duplicated address list. Each token may be:
     * <ul>
     *   <li>a hostname or single IP — passed through unchanged;</li>
     *   <li>a CIDR, {@code a.b.c.d/nn} (network and broadcast excluded below /31);</li>
     *   <li>a full range, {@code a.b.c.d-w.x.y.z};</li>
     *   <li>a per-octet range, {@code 192.168.1-5.1-254}, each octet {@code n} or {@code a-b}
     *     (which subsumes the last-octet form {@code 10.0.0.5-7}; a reversed bound is
     *     normalised);</li>
     *   <li>a comma-separated list of any of the above inside one token.</li>
     * </ul>
     * Expansion is capped at {@link #MAX_EXPANSION} addresses per spec; the spec is cut short
     * and, when {@code warnings} is given, a warning names it. Anything unparseable stays a
     * literal target (a hostname with a dash, a malformed CIDR), never a silent sweep.
     *
     * @param warnings receives the cap warning; may be null
     */
    public static List<String> expand(List<String> targets, List<String> warnings) {
        Set<String> out = new LinkedHashSet<>();
        if (targets == null) {
            return new ArrayList<>();
        }
        for (String raw : targets) {
            if (raw == null) continue;
            for (String piece : raw.split(",")) {
                String t = piece.trim();
                if (t.isEmpty()) continue;
                expandOne(t, out, warnings);
            }
        }
        return new ArrayList<>(out);
    }

    /** {@link #expand(List, List)} without a warning sink. */
    public static List<String> expand(List<String> targets) {
        return expand(targets, null);
    }

    private static void expandOne(String t, Set<String> out, List<String> warnings) {
        int slash = t.indexOf('/');
        if (slash > 0) {
            long base = ipToLong(t.substring(0, slash));
            int bits = parseIntSafe(t.substring(slash + 1), -1);
            if (base >= 0 && bits >= 0 && bits <= 32) {
                long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                long network = base & mask;
                long broadcast = network | (~mask & 0xFFFFFFFFL);
                long lo = bits >= 31 ? network : network + 1;
                long hi = bits >= 31 ? broadcast : broadcast - 1;
                emitRange(t, lo, hi, out, warnings);
                return;
            }
            out.add(t); // malformed CIDR: literal
            return;
        }
        int dash = t.indexOf('-');
        if (dash > 0) {
            long l = ipToLong(t.substring(0, dash));
            long h = ipToLong(t.substring(dash + 1));
            if (l >= 0 && h >= 0) {
                emitRange(t, Math.min(l, h), Math.max(l, h), out, warnings);
                return;
            }
            int[][] octets = parseOctetRanges(t);
            if (octets != null) {
                emitOctets(t, octets, out, warnings);
                return;
            }
        }
        out.add(t); // hostname or single IP — pass through
    }

    private static void emitRange(String spec, long lo, long hi, Set<String> out, List<String> warnings) {
        long count = hi - lo + 1;
        if (count > MAX_EXPANSION) {
            capped(spec, warnings);
            count = MAX_EXPANSION;
        }
        for (long i = 0; i < count; i++) {
            out.add(longToIp(lo + i));
        }
    }

    /**
     * {@code a.b.c.d} where each part is {@code n} or {@code n-m} within 0..255, as
     * {@code [4][2]} normalised bounds; null when the token is not of that shape.
     */
    private static int[][] parseOctetRanges(String t) {
        String[] parts = t.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        int[][] bounds = new int[4][2];
        for (int i = 0; i < 4; i++) {
            String p = parts[i].trim();
            int d = p.indexOf('-');
            int a, b;
            if (d > 0) {
                a = parseIntSafe(p.substring(0, d), -1);
                b = parseIntSafe(p.substring(d + 1), -1);
            } else {
                a = b = parseIntSafe(p, -1);
            }
            if (a < 0 || a > 255 || b < 0 || b > 255) {
                return null;
            }
            bounds[i][0] = Math.min(a, b);
            bounds[i][1] = Math.max(a, b);
        }
        return bounds;
    }

    private static void emitOctets(String spec, int[][] o, Set<String> out, List<String> warnings) {
        long total = 1;
        for (int[] b : o) {
            total *= (b[1] - b[0] + 1);
        }
        if (total > MAX_EXPANSION) {
            capped(spec, warnings);
        }
        long emitted = 0;
        for (int a = o[0][0]; a <= o[0][1]; a++) {
            for (int b = o[1][0]; b <= o[1][1]; b++) {
                for (int c = o[2][0]; c <= o[2][1]; c++) {
                    for (int d = o[3][0]; d <= o[3][1]; d++) {
                        if (emitted++ >= MAX_EXPANSION) {
                            return;
                        }
                        out.add(a + "." + b + "." + c + "." + d);
                    }
                }
            }
        }
    }

    private static void capped(String spec, List<String> warnings) {
        if (warnings != null) {
            warnings.add("target expansion capped at " + MAX_EXPANSION + " addresses for '" + spec + "'");
        }
    }

    /**
     * True for an IPv4 dotted quad or an IPv6 literal (optionally with a zone index) — an
     * address that needs no lookup. Anything else is treated as a hostname.
     */
    public static boolean isIpLiteral(String s) {
        if (s == null) {
            return false;
        }
        String t = s.trim();
        if (ipToLong(t) >= 0) {
            return true;
        }
        if (t.startsWith("[") && t.endsWith("]")) {
            t = t.substring(1, t.length() - 1);
        }
        int pct = t.indexOf('%');
        if (pct > 0) {
            t = t.substring(0, pct);
        }
        return t.indexOf(':') >= 0 && t.matches("[0-9A-Fa-f:.]+");
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
