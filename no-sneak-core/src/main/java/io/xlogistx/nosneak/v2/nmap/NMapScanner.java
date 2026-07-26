package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.ProbeChecker;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;

import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.runtime.ParallelJoin;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.CallableConsumer;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
        final RateLimiter limiter = new RateLimiter(cfg.maxInFlight, cfg.maxPerSec);
        final int[] ports = cfg.ports != null ? cfg.ports : NMap.DEFAULT_PORTS;
        final int[] discPorts = cfg.discoveryPorts != null ? cfg.discoveryPorts : DEFAULT_DISCOVERY_PORTS;
        final int to = cfg.timeoutSec;

        final Runnable finish = () -> {
            limiter.close();
            report.endTimeMs = System.currentTimeMillis();
            onComplete.accept(report);
        };
        final Runnable afterDiscovery = () -> portScanStage(nio, limiter, report, ports, cfg, to, finish);

        if (cfg.discovery) {
            ParallelJoin hostsJoin = new ParallelJoin(report.hosts.size(), afterDiscovery);
            for (HostReport hr : report.hosts) {
                discoverHost(nio, limiter, hr, discPorts, cfg, to, hostsJoin::childDone);
            }
        } else {
            for (HostReport hr : report.hosts) {
                hr.up = true;
                hr.reason = "skipped";
            }
            afterDiscovery.run();
        }
    }

    // ==================== Stage 0: discovery ====================

    private static void discoverHost(NIOSocket nio, RateLimiter limiter, HostReport hr,
                                     int[] discPorts, NMapConfig cfg, int to, Runnable hostDone) {
        final AtomicBoolean up = new AtomicBoolean(false);
        final java.util.concurrent.atomic.AtomicReference<String> reason =
                new java.util.concurrent.atomic.AtomicReference<>();
        final int units = discPorts.length + (cfg.discoveryIcmp ? 1 : 0);
        final ParallelJoin j = new ParallelJoin(units, () -> {
            hr.up = up.get();
            hr.reason = up.get() ? reason.get() : "no-response";
            hostDone.run();
        });
        // TCP-ping: reachable if a discovery port connects (OPEN) or is refused (CLOSED).
        for (int p : discPorts) {
            final int port = p;
            limiter.submit(() -> {
                try {
                    PortScanCallback cb = new PortScanCallback(new IPAddress(hr.host, port), to, st -> {
                        if (st == PortState.OPEN || st == PortState.CLOSED) {
                            up.set(true);
                            reason.compareAndSet(null, "tcp-ping");
                        }
                        limiter.release();
                        j.childDone();
                    });
                    nio.addClientSocket(cb, to + 2);
                } catch (Exception e) {
                    limiter.release();
                    j.childDone();
                }
            });
        }
        // ICMP echo (best-effort, blocking → runs on the executor; often blocked by firewalls).
        if (cfg.discoveryIcmp) {
            limiter.submit(() -> TaskUtil.defaultTaskProcessor().execute(() -> {
                try {
                    if (InetAddress.getByName(hr.host).isReachable(Math.max(to, 1) * 1000)) {
                        up.set(true);
                        reason.compareAndSet(null, "icmp-echo");
                    }
                } catch (Exception ignored) {
                } finally {
                    limiter.release();
                    j.childDone();
                }
            }));
        }
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
            limiter.submit(() -> {
                try {
                    PortScanCallback cb = new PortScanCallback(new IPAddress(hr.host, target.port), to, st -> {
                        target.state = st;
                        target.reason = st == PortState.OPEN ? "syn-ack"
                                : st == PortState.CLOSED ? "conn-refused" : "no-response";
                        limiter.release();
                        j.childDone();
                    });
                    nio.addClientSocket(cb, to + 2);
                } catch (Exception e) {
                    target.state = PortState.CLOSED;
                    limiter.release();
                    j.childDone();
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
            limiter.submit(() -> {
                try {
                    checker.check(host, pr.port, new CallableConsumerTask<ProbeResult>()
                            .setConsumer(r -> {
                                pr.probe = r;
                                limiter.release();
                                j.childDone();
                            })
                            .setExceptionCallback(t -> {
                                limiter.release();
                                j.childDone();
                            }));
                } catch (Exception e) {
                    limiter.release();
                    j.childDone();
                }
            });
        }
    }

    private static ProbeChecker buildChecker(NIOSocket nio, NMapConfig cfg, int to, ScanReport report) {
        if (cfg.probeNames == null || cfg.probeNames.isEmpty()) {
            return ProbeChecker.withBundled(nio).timeoutInSec(to);
        }
        List<ProbeDefinition> bundled = ProbeDefinitionLoader.loadBundled();
        List<ProbeDefinition> subset = new ArrayList<>();
        Set<String> matched = new LinkedHashSet<>();
        for (ProbeDefinition d : bundled) {
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
                    + bundled.size() + " bundled probes");
            return ProbeChecker.withBundled(nio).timeoutInSec(to);
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
