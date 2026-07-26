package io.xlogistx.nosneak.v2;

import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.runtime.Fanout;
import io.xlogistx.nosneak.v2.runtime.ParallelJoin;
import io.xlogistx.nosneak.v2.runtime.ProbeContext;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.CallableConsumer;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Identifies what protocol/version is behind a {@code host:port} by running JSON-defined
 * probes against it on the shared {@link NIOSocket} event loop.
 * <p>
 * Candidates are ordered in two tiers: probes whose declared {@code ports} include the
 * target (highest priority first), then the remaining transport-compatible probes as a
 * fallback (so a service on a nonstandard port is still detected) — {@code portScoped}
 * probes are excluded from the fallback tier. <b>match-first</b> ({@link #check}) delivers
 * the first probe that reaches a clean {@code done}; <b>match-all</b>
 * ({@link #checkAll}) runs every candidate and returns all successes.
 */
public class ProbeChecker {

    public static final LogWrapper log = new LogWrapper(ProbeChecker.class).setEnabled(false);

    private final NIOSocket nioSocket;
    private final List<ProbeDefinition> probes; // sorted by descending priority
    private int timeoutSec = 10;
    private boolean matchPorts = true;

    public ProbeChecker(NIOSocket nioSocket, List<ProbeDefinition> probes) {
        this.nioSocket = nioSocket;
        this.probes = probes;
    }

    /** A checker over the bundled probe definitions. */
    public static ProbeChecker withBundled(NIOSocket nioSocket) {
        return new ProbeChecker(nioSocket, ProbeDefinitionLoader.loadBundled());
    }

    public ProbeChecker timeoutInSec(int seconds) {
        this.timeoutSec = seconds > 0 ? seconds : 10;
        return this;
    }

    /**
     * {@code true} (default): tier-1 = declared-port matches, tier-2 = fallback.
     * {@code false}: run every provided probe of the matching transport in priority order.
     */
    public ProbeChecker matchPorts(boolean enabled) {
        this.matchPorts = enabled;
        return this;
    }

    public void check(String host, int port, CallableConsumer<ProbeResult> callback) {
        check(host, port, "tcp", callback);
    }

    /**
     * Async check over {@code transport}, match-first: the <b>highest-priority</b> probe that
     * reaches a clean {@code done} wins. Candidates run <b>concurrently</b>; because they are
     * priority-ordered (index 0 = highest), the winner is delivered the instant no higher-priority
     * candidate can still complete — index {@code k} wins once indices {@code 0..k-1} have all
     * resolved as incomplete and {@code k} has completed (fast-path short-circuit). The remaining
     * in-flight candidates are then torn down. The selection is identical to a sequential
     * priority-ordered sweep; only the latency (bounded by the winner, not the sum) and the
     * concurrency (one connection per candidate) differ.
     */
    public void check(String host, int port, String transport, CallableConsumer<ProbeResult> callback) {
        List<ProbeDefinition> candidates = orderedCandidates(port, transport);
        if (candidates.isEmpty()) {
            callback.accept(noneIdentified(host, port, transport, candidates));
            return;
        }
        new FirstSweep(host, port, transport, candidates, callback).start();
    }

    /**
     * Async check over {@code transport}, match-all: every candidate runs concurrently and all
     * completed results are returned (priority order). Wall-clock is bounded by the slowest single
     * candidate rather than their sum.
     */
    public void checkAll(String host, int port, String transport, CallableConsumer<List<ProbeResult>> callback) {
        List<ProbeDefinition> candidates = orderedCandidates(port, transport);
        if (candidates.isEmpty()) {
            callback.accept(Collections.singletonList(noneIdentified(host, port, transport, candidates)));
            return;
        }
        new AllSweep(host, port, transport, candidates, callback).start();
    }

    /** Two-tier candidate ordering (declared-port matches first, then non-portScoped fallback). */
    private List<ProbeDefinition> orderedCandidates(int port, String transport) {
        List<ProbeDefinition> tier1 = new ArrayList<>();
        List<ProbeDefinition> tier2 = new ArrayList<>();
        for (ProbeDefinition def : probes) {
            if (!def.getTransport().equalsIgnoreCase(transport)) {
                continue;
            }
            if (!matchPorts) {
                tier2.add(def);
            } else if (def.matches(port, transport)) {
                tier1.add(def);
            } else if (!def.isPortScoped()) {
                tier2.add(def);
            }
        }
        List<ProbeDefinition> out = new ArrayList<>(tier1.size() + tier2.size());
        out.addAll(tier1);
        out.addAll(tier2);
        return out;
    }

    /**
     * Concurrent match-first sweep with a priority-aware fast-path short-circuit. Every candidate
     * is launched at once; each reports its result (complete or not) into a slot. Because
     * candidates are priority-ordered, we can deliver as soon as the lowest index that is either
     * still-in-flight or complete turns out to be complete — no higher-priority candidate can then
     * overtake it. If every candidate resolves incomplete, none-identified is delivered.
     */
    private final class FirstSweep {
        private final String host;
        private final int port;
        private final String transport;
        private final List<ProbeDefinition> candidates;
        private final CallableConsumer<ProbeResult> callback;
        private final ProbeResult[] results;
        private final boolean[] resolved;
        private final ProbeContext[] ctxs;
        private final AtomicBoolean delivered = new AtomicBoolean(false);
        private final Object lock = new Object();

        FirstSweep(String host, int port, String transport, List<ProbeDefinition> candidates,
                   CallableConsumer<ProbeResult> callback) {
            this.host = host;
            this.port = port;
            this.transport = transport;
            this.candidates = candidates;
            this.callback = callback;
            int n = candidates.size();
            this.results = new ProbeResult[n];
            this.resolved = new boolean[n];
            this.ctxs = new ProbeContext[n];
        }

        void start() {
            int n = candidates.size();
            // Construct every context up front (cheap, no I/O) so the ctxs[] array is fully
            // populated before any async resolution can run the election — that lets the election
            // cancel a superseded candidate even if it has not started connecting yet
            // (ProbeContext.start() no-ops once cancelled). Then launch the starts concurrently
            // through the native StateMachine parallel dispatch.
            List<Runnable> starts = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                final int idx = i;
                ProbeContext ctx = null;
                try {
                    ctx = new ProbeContext(nioSocket, new IPAddress(host, port),
                            candidates.get(i), timeoutSec, r -> onResolve(idx, r));
                } catch (Exception e) {
                    if (log.isEnabled()) log.getLogger().info("probe launch error: " + e.getMessage());
                }
                ctxs[i] = ctx;
                if (ctx != null) {
                    final ProbeContext c = ctx;
                    starts.add(c::start);
                } else {
                    starts.add(() -> onResolve(idx, null)); // launch failure = incomplete resolution
                }
            }
            Fanout.dispatch(starts);
        }

        private void onResolve(int i, ProbeResult r) {
            int winnerIdx = -1;
            boolean none = false;
            List<ProbeContext> toCancel = null;
            synchronized (lock) {
                if (delivered.get()) return;
                results[i] = r;
                resolved[i] = true;
                for (int k = 0; k < results.length; k++) {
                    if (!resolved[k]) {
                        return; // a higher-priority candidate is still in flight — wait for it
                    }
                    if (results[k] != null && results[k].isComplete()) {
                        winnerIdx = k;
                        break;
                    }
                }
                none = winnerIdx < 0; // every candidate resolved incomplete
                delivered.set(true);
                toCancel = new ArrayList<>();
                for (int k = 0; k < ctxs.length; k++) {
                    if (k != winnerIdx && ctxs[k] != null) {
                        toCancel.add(ctxs[k]);
                    }
                }
            }
            // Cancel losers OUTSIDE the lock to avoid a lock/monitor ordering hazard with their
            // own synchronized deliver()/cancel().
            for (ProbeContext c : toCancel) {
                c.cancel();
            }
            callback.accept(none ? noneIdentified(host, port, transport, candidates) : results[winnerIdx]);
        }
    }

    /**
     * Concurrent match-all sweep: launch every candidate at once and, once all have resolved,
     * return every completed result in priority order (or none-identified if there were none).
     */
    private final class AllSweep {
        private final String host;
        private final int port;
        private final String transport;
        private final List<ProbeDefinition> candidates;
        private final CallableConsumer<List<ProbeResult>> callback;
        private final ProbeResult[] results;
        private final Object lock = new Object();

        AllSweep(String host, int port, String transport, List<ProbeDefinition> candidates,
                 CallableConsumer<List<ProbeResult>> callback) {
            this.host = host;
            this.port = port;
            this.transport = transport;
            this.candidates = candidates;
            this.callback = callback;
            this.results = new ProbeResult[candidates.size()];
        }

        void start() {
            // One concurrent child per candidate on the native StateMachine parallel dispatch;
            // the ParallelJoin barrier fires deliverAll() once every child has resolved.
            List<Consumer<ParallelJoin>> children = new ArrayList<>(candidates.size());
            for (int i = 0; i < candidates.size(); i++) {
                final int idx = i;
                children.add(join -> {
                    try {
                        ProbeContext ctx = new ProbeContext(nioSocket, new IPAddress(host, port),
                                candidates.get(idx), timeoutSec, r -> {
                            synchronized (lock) {
                                results[idx] = r;
                            }
                            join.childDone();
                        });
                        ctx.start();
                    } catch (Exception e) {
                        if (log.isEnabled()) log.getLogger().info("probe launch error: " + e.getMessage());
                        join.childDone();
                    }
                });
            }
            Fanout.run(children, this::deliverAll);
        }

        private void deliverAll() {
            List<ProbeResult> found = new ArrayList<>();
            synchronized (lock) {
                for (ProbeResult pr : results) {
                    if (pr != null && pr.isComplete()) {
                        found.add(pr);
                    }
                }
            }
            callback.accept(found.isEmpty()
                    ? Collections.singletonList(noneIdentified(host, port, transport, candidates))
                    : found);
        }
    }

    /** Blocking convenience for CLI/tests: match-first. */
    public ProbeResult checkBlocking(String host, int port, String transport, long maxWaitMs) {
        CompletableFuture<ProbeResult> future = new CompletableFuture<>();
        check(host, port, transport, new CallableConsumerTask<ProbeResult>()
                .setConsumer(future::complete)
                .setExceptionCallback(t -> {
                    if (log.isEnabled()) log.getLogger().info("probe exception: " + t);
                }));
        try {
            return future.get(maxWaitMs, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            return unknown(host, port, transport, "checker-timeout");
        }
    }

    /** Blocking convenience for CLI/tests: match-all. */
    public List<ProbeResult> checkBlockingAll(String host, int port, String transport, long maxWaitMs) {
        CompletableFuture<List<ProbeResult>> future = new CompletableFuture<>();
        checkAll(host, port, transport, new CallableConsumerTask<List<ProbeResult>>()
                .setConsumer(future::complete)
                .setExceptionCallback(t -> {
                    if (log.isEnabled()) log.getLogger().info("probe exception: " + t);
                }));
        try {
            return future.get(maxWaitMs, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            return Collections.singletonList(unknown(host, port, transport, "checker-timeout"));
        }
    }

    /** Delivered when no probe identified the port: complete=false, lists every probe tried. */
    private ProbeResult noneIdentified(String host, int port, String transport, List<ProbeDefinition> tried) {
        StringBuilder names = new StringBuilder();
        for (ProbeDefinition d : tried) {
            if (names.length() > 0) names.append(", ");
            names.append(d.getName());
        }
        String note = "no-probe-identified; " + tried.size() + " probe(s) tried: "
                + (names.length() > 0 ? names.toString() : "(none applicable)");
        return ProbeResult.builder(host, port, transport)
                .service(wellKnownService(port))
                .complete(false)
                .fact("probes-tried", names.toString())
                .note(note)
                .build();
    }

    private ProbeResult unknown(String host, int port, String transport, String note) {
        return ProbeResult.builder(host, port, transport)
                .service(wellKnownService(port))
                .complete(false)
                .note(note)
                .build();
    }

    // Minimal well-known-port guess for the fallback label. Superseded by the full
    // ServiceMatch table once the nmap subsystem is copied into v2 (Phase 8).
    private static final Map<Integer, String> WELL_KNOWN = new java.util.HashMap<>();
    static {
        WELL_KNOWN.put(21, "ftp"); WELL_KNOWN.put(22, "ssh"); WELL_KNOWN.put(25, "smtp");
        WELL_KNOWN.put(53, "dns"); WELL_KNOWN.put(80, "http"); WELL_KNOWN.put(110, "pop3");
        WELL_KNOWN.put(143, "imap"); WELL_KNOWN.put(443, "https"); WELL_KNOWN.put(465, "smtps");
        WELL_KNOWN.put(587, "smtp"); WELL_KNOWN.put(993, "imaps"); WELL_KNOWN.put(995, "pop3s");
        WELL_KNOWN.put(3306, "mysql"); WELL_KNOWN.put(5432, "postgresql"); WELL_KNOWN.put(6379, "redis");
        WELL_KNOWN.put(8080, "http"); WELL_KNOWN.put(8443, "https"); WELL_KNOWN.put(27017, "mongodb");
    }

    private static String wellKnownService(int port) {
        return WELL_KNOWN.get(port);
    }

    // ==================== CLI ====================

    public static void usage() {
        System.out.println("Usage: ProbeChecker <host> <port> [timeoutSec] [--all|--first] [probe1.json ...]");
        System.out.println("  Identifies the protocol/version on host:port (v2 engine).");
        System.out.println("  --first (default): stop at the first probe that identifies the port.");
        System.out.println("  --all: run every candidate and report each successful result.");
    }

    public static void main(String... args) {
        if (args.length < 2) {
            usage();
            return;
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);

        int timeoutSec = 10;
        boolean allMode = false;
        String transport = "tcp";
        List<String> probeFiles = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            String a = args[i];
            if (a.matches("\\d+")) {
                timeoutSec = Integer.parseInt(a);
            } else if ("--all".equalsIgnoreCase(a)) {
                allMode = true;
            } else if ("--first".equalsIgnoreCase(a)) {
                allMode = false;
            } else if ("--udp".equalsIgnoreCase(a)) {
                transport = "udp";
            } else if ("--tcp".equalsIgnoreCase(a)) {
                transport = "tcp";
            } else {
                probeFiles.add(a);
            }
        }

        NIOSocket nioSocket = null;
        try {
            boolean explicitFiles = !probeFiles.isEmpty();
            List<ProbeDefinition> probes = explicitFiles
                    ? ProbeDefinitionLoader.loadFiles(probeFiles)
                    : ProbeDefinitionLoader.loadBundled();
            System.out.println("Loaded " + probes.size() + " probe(s): "
                    + (explicitFiles ? probeFiles : "bundled"));

            // Non-blocking NIO stack wired to the shared processor + scheduler.
            nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            ProbeChecker checker = new ProbeChecker(nioSocket, probes)
                    .timeoutInSec(timeoutSec)
                    .matchPorts(!explicitFiles);

            long perTry = timeoutSec * 6L + 15L;
            if (allMode) {
                long maxWaitMs = (perTry + (long) probes.size() * timeoutSec) * 1000L;
                List<ProbeResult> results = checker.checkBlockingAll(host, port, transport, maxWaitMs);
                long identified = results.stream().filter(ProbeResult::isComplete).count();
                System.out.println(identified == 0
                        ? "No probe identified " + host + ":" + port + ":"
                        : "Identified " + identified + " result(s):");
                for (ProbeResult r : results) {
                    System.out.println(r);
                    if (r.getTlsState() != ProbeResult.TlsState.NONE) {
                        System.out.println("  " + io.xlogistx.nosneak.v2.grade.Grade.of(r));
                    }
                    System.out.println(GSONUtil.toJSONDefault(r.toNVGenericMap(), true));
                }
            } else {
                // Match-first sweeps candidates sequentially, each bounded by ~timeoutSec, so the
                // global wait must scale with the candidate count too (mirroring match-all) — otherwise
                // a port that is open-but-silent to every probe trips the backstop with a misleading
                // "checker-timeout" instead of returning a clean "no-probe-identified" verdict.
                long maxWaitMs = (perTry + (long) probes.size() * timeoutSec) * 1000L;
                ProbeResult result = checker.checkBlocking(host, port, transport, maxWaitMs);
                System.out.println(result);
                if (result.getTlsState() != ProbeResult.TlsState.NONE) {
                    System.out.println("  " + io.xlogistx.nosneak.v2.grade.Grade.of(result));
                }
                System.out.println(GSONUtil.toJSONDefault(result.toNVGenericMap(), true));
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            usage();
            e.printStackTrace();
        } finally {
            SharedIOUtil.close(nioSocket);
        }
        // Superseded probes release their connections and scheduler appointments at teardown
        // (ProbeContext.closeCurrent → NIOSocket.abortClientSocket), so nothing lingers server-side.
        // The only threads left for a one-shot CLI are the shared non-daemon pools (DE/TSP); exit
        // promptly rather than wait on their idle shutdown.
        System.exit(0);
    }
}
