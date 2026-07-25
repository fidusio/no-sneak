package io.xlogistx.nosneak.probe;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.probe.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.CallableConsumer;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Identifies what protocol is behind a {@code host:port} by running a list of
 * JSON-defined probes against it. For a given port it takes the probe definitions
 * whose port/transport match (highest priority first) and runs them one at a time
 * on the shared {@link NIOSocket} event loop; the first probe that reaches a clean
 * {@code done} terminal (its protocol-specific gate passed) identifies the port,
 * and its {@link ProbeResult} — service name, TLS state, PQC status, cert facts —
 * is returned. If none match/identify, a minimal facts result is returned
 * (well-known-port guess, incomplete).
 *
 * <p>Usage (library):
 * <pre>{@code
 * NIOSocket nio = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
 * ProbeChecker checker = ProbeChecker.withBundled(nio).timeoutInSec(10);
 * checker.check("mail.example.com", 993, new CallableConsumerTask<ProbeResult>()
 *         .setConsumer(System.out::println)                  // async result
 *         .setExceptionCallback(Throwable::printStackTrace)); // captured exception
 * }</pre>
 *
 * <p>Usage (CLI): {@code java ... ProbeChecker <host> <port> [timeoutSec]}.
 */
public class ProbeChecker {

    public static final LogWrapper log = new LogWrapper(ProbeChecker.class).setEnabled(false);

    private final NIOSocket nioSocket;
    private final List<ProbeDefinition> probes; // expected sorted by descending priority
    private int timeoutSec = 10;
    // When true, only probes whose declared "ports" list includes the target port are run.
    // When false, EVERY provided probe of the right transport is run against the port
    // (regardless of its declared ports) — a "try them all to identify the port" mode.
    private boolean matchPorts = true;

    public ProbeChecker(NIOSocket nioSocket, List<ProbeDefinition> probes) {
        this.nioSocket = nioSocket;
        this.probes = probes;
    }

    /** A checker over the bundled probe definitions (https, imaps, smtp, imap, mongodb, ...). */
    public static ProbeChecker withBundled(NIOSocket nioSocket) {
        return new ProbeChecker(nioSocket, ProbeDefinitionLoader.loadBundled());
    }

    public ProbeChecker timeoutInSec(int seconds) {
        this.timeoutSec = seconds > 0 ? seconds : 10;
        return this;
    }

    /**
     * Control port matching. {@code true} (default): run only probes whose declared
     * {@code ports} include the target port. {@code false}: run every provided probe
     * of the matching transport against the port regardless of its declared ports
     * (useful for identifying a service on a nonstandard port).
     */
    public ProbeChecker matchPorts(boolean enabled) {
        this.matchPorts = enabled;
        return this;
    }

    /**
     * Async TCP check. {@code callback.accept(result)} receives the identifying (or
     * best/unknown) result; {@code callback.exception(t)} captures any probe-launch
     * exception (the check still advances to the next probe).
     */
    public void check(String host, int port, CallableConsumer<ProbeResult> callback) {
        check(host, port, "tcp", callback);
    }

    /**
     * Async check over {@code transport}, <b>match-first</b>: the first probe that
     * reaches a clean {@code done} identifies the port and its {@link ProbeResult}
     * is delivered. Probes are tried in {@linkplain #orderedCandidates candidate
     * order} — declared-port matches first (highest priority), then the remaining
     * transport-compatible probes as a fallback — so a service on a nonstandard port
     * (e.g. HTTPS on 4443/8123) is still identified.
     */
    public void check(String host, int port, String transport, CallableConsumer<ProbeResult> callback) {
        List<ProbeDefinition> candidates = orderedCandidates(port, transport);
        if (candidates.isEmpty()) {
            callback.accept(noneIdentified(host, port, transport, candidates));
            return;
        }
        runFrom(host, port, transport, candidates, 0, null, callback);
    }

    /**
     * Async check over {@code transport}, <b>match-all</b>: every candidate probe is
     * run and each one that reaches a clean {@code done} is collected. The callback
     * receives all successful results (or a single {@code unknown} facts result if
     * none identified), ordered by {@linkplain #orderedCandidates candidate order}.
     */
    public void checkAll(String host, int port, String transport, CallableConsumer<List<ProbeResult>> callback) {
        List<ProbeDefinition> candidates = orderedCandidates(port, transport);
        if (candidates.isEmpty()) {
            callback.accept(java.util.Collections.singletonList(noneIdentified(host, port, transport, candidates)));
            return;
        }
        runAll(host, port, transport, candidates, 0, new ArrayList<>(), callback);
    }

    /**
     * Build the ordered probe candidate list for a port. Tier 1 = probes whose
     * declared {@code ports} include {@code port} (when {@link #matchPorts}); tier 2
     * = the remaining transport-compatible probes as a fallback. Each tier preserves
     * the descending-priority order of {@link #probes}. When {@code matchPorts} is
     * false (e.g. explicit CLI files) every transport-compatible probe is a single
     * priority-ordered tier.
     */
    private List<ProbeDefinition> orderedCandidates(int port, String transport) {
        List<ProbeDefinition> tier1 = new ArrayList<>();
        List<ProbeDefinition> tier2 = new ArrayList<>();
        for (ProbeDefinition def : probes) {
            if (!def.getTransport().equalsIgnoreCase(transport)) {
                continue;
            }
            if (!matchPorts) {
                // Explicit-files mode: run every provided probe against the port.
                tier2.add(def);
            } else if (def.matches(port, transport)) {
                tier1.add(def);
            } else if (!def.isPortScoped()) {
                // Fallback tier — but a port-scoped probe (ungated any-TLS catch-all) is skipped
                // here so it can't mislabel an unrelated port (e.g. Postgres-over-TLS as https).
                tier2.add(def);
            }
        }
        List<ProbeDefinition> out = new ArrayList<>(tier1.size() + tier2.size());
        out.addAll(tier1);
        out.addAll(tier2);
        return out;
    }

    /**
     * Run matching[idx]; on a completed result deliver it, else advance to the next. When every
     * candidate has run without identifying the port, deliver a clear <em>no-probe-identified</em>
     * result that lists all probes tried — never the last probe's (misleading) incomplete result.
     */
    private void runFrom(String host, int port, String transport, List<ProbeDefinition> matching,
                         int idx, ProbeResult last, CallableConsumer<ProbeResult> callback) {
        if (idx >= matching.size()) {
            callback.accept(noneIdentified(host, port, transport, matching));
            return;
        }
        ProbeDefinition def = matching.get(idx);
        IPAddress target = new IPAddress(host, port);
        try {
            ProbeSession session = new ProbeSession(nioSocket, target, def, timeoutSec, result -> {
                if (result != null && result.isComplete()) {
                    callback.accept(result);
                } else {
                    runFrom(host, port, transport, matching, idx + 1, result, callback);
                }
            });
            session.start();
        } catch (Exception e) {
            // Capture the launch exception, then keep going with the remaining probes.
            if (log.isEnabled()) log.getLogger().info("probe launch error: " + e.getMessage());
            callback.exception(e);
            runFrom(host, port, transport, matching, idx + 1, last, callback);
        }
    }

    /**
     * The result delivered when <em>no</em> probe identified the port: a facts-only,
     * {@code complete=false} result whose note states plainly that nothing matched and lists every
     * probe that was tried (so a failure is unambiguous, not the last probe's partial result).
     * The tried-probe list is also exposed as the {@code probes-tried} service fact.
     */
    private ProbeResult noneIdentified(String host, int port, String transport, List<ProbeDefinition> tried) {
        StringBuilder names = new StringBuilder();
        for (ProbeDefinition d : tried) {
            if (names.length() > 0) names.append(", ");
            names.append(d.getName());
        }
        String note = "no-probe-identified; " + tried.size() + " probe(s) tried: "
                + (names.length() > 0 ? names.toString() : "(none applicable)");
        return ProbeResult.builder(host, port, transport)
                .service(ServiceMatch.getWellKnownService(port, transport))
                .tlsState(ProbeResult.TlsState.NONE)
                .pqcStatus(ProbeResult.PqcStatus.UNKNOWN)
                .complete(false)
                .fact("probes-tried", names.toString())
                .note(note)
                .build();
    }

    /** Run every candidate; collect each completed result. Advances regardless of success. */
    private void runAll(String host, int port, String transport, List<ProbeDefinition> candidates,
                        int idx, List<ProbeResult> found, CallableConsumer<List<ProbeResult>> callback) {
        if (idx >= candidates.size()) {
            callback.accept(found.isEmpty()
                    ? java.util.Collections.singletonList(noneIdentified(host, port, transport, candidates))
                    : found);
            return;
        }
        ProbeDefinition def = candidates.get(idx);
        IPAddress target = new IPAddress(host, port);
        try {
            ProbeSession session = new ProbeSession(nioSocket, target, def, timeoutSec, result -> {
                if (result != null && result.isComplete()) {
                    found.add(result);
                }
                runAll(host, port, transport, candidates, idx + 1, found, callback);
            });
            session.start();
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("probe launch error: " + e.getMessage());
            callback.exception(e);
            runAll(host, port, transport, candidates, idx + 1, found, callback);
        }
    }

    /** Blocking convenience for CLI/tests: waits up to {@code maxWaitMs} for a result. */
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

    /** Blocking convenience for CLI/tests: match-all, returns every completed result. */
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
            return java.util.Collections.singletonList(unknown(host, port, transport, "checker-timeout"));
        }
    }

    private ProbeResult unknown(String host, int port, String transport, String note) {
        return ProbeResult.builder(host, port, transport)
                .service(ServiceMatch.getWellKnownService(port, transport))
                .tlsState(ProbeResult.TlsState.NONE)
                .pqcStatus(ProbeResult.PqcStatus.UNKNOWN)
                .complete(false)
                .note(note)
                .build();
    }

    // ==================== CLI ====================

    public static void usage()
    {
        System.out.println("Usage: ProbeChecker <host> <port> [timeoutSec] [--all|--first] [probe1.json probe2.json ...]");
        System.out.println("  Identifies the protocol on host:port and detects its service version where possible.");
        System.out.println("  Probes are tried declared-port-first, then the rest as a fallback (so a service on a");
        System.out.println("  nonstandard port, e.g. HTTPS on 4443, is still detected).");
        System.out.println("  --first (default): stop at the first probe that identifies the port.");
        System.out.println("  --all: run every candidate and report each successful result.");
        System.out.println("  With no probe files it uses the bundled JSON probes; if one or more");
        System.out.println("  *.json files are given, those are loaded/validated and used instead.");
    }
    public static void main(String... args) {
        if (args.length < 2) {
            usage();
            return;
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);

        // Remaining args: an integer is the timeout (seconds); --all/--first select the match mode;
        // anything else is a probe JSON file path.
        int timeoutSec = 10;
        boolean allMode = false;
        List<String> probeFiles = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            String a = args[i];
            if (a.matches("\\d+")) {
                timeoutSec = Integer.parseInt(a);
            } else if ("--all".equalsIgnoreCase(a)) {
                allMode = true;
            } else if ("--first".equalsIgnoreCase(a)) {
                allMode = false;
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
                    + (explicitFiles ? probeFiles : "bundled")
                    + (explicitFiles ? " (running ALL against " + port + ", ignoring declared ports)"
                                     : " (matching declared ports)"));

            nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            ProbeChecker checker = new ProbeChecker(nioSocket, probes)
                    .timeoutInSec(timeoutSec)
                    // Explicit probe files → try them all regardless of declared ports;
                    // bundled probes → keep the port-matched dispatcher behavior.
                    .matchPorts(!explicitFiles);

            // Generous wait: match-all runs every candidate sequentially, so scale by count.
            long perTry = timeoutSec * 6L + 15L;
            if (allMode) {
                long maxWaitMs = (perTry + (long) probes.size() * timeoutSec) * 1000L;
                List<ProbeResult> results = checker.checkBlockingAll(host, port, "tcp", maxWaitMs);
                long identified = results.stream().filter(ProbeResult::isComplete).count();
                System.out.println(identified == 0
                        ? "No probe identified " + host + ":" + port + ":"
                        : "Identified " + identified + " result(s):");
                for (ProbeResult r : results) {
                    System.out.println(r);
                    System.out.println(GSONUtil.toJSONDefault(r.toNVGenericMap(), true));
                }
            } else {
                long maxWaitMs = perTry * 1000L;
                ProbeResult result = checker.checkBlocking(host, port, "tcp", maxWaitMs);
                System.out.println(result);
                System.out.println(GSONUtil.toJSONDefault(result.toNVGenericMap(), true));
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.out.println("Usage: ProbeChecker <host> <port> [timeoutSec] [probe1.json probe2.json ...]");
            System.out.println("  Identifies the protocol on host:port.");
            System.out.println("  With no probe files it uses the bundled JSON probes; if one or more");
            System.out.println("  *.json files are given, those are loaded/validated and used instead.");
            e.printStackTrace();
        } finally {
            SharedIOUtil.close(nioSocket);
            TaskUtil.waitIfBusyThenClose(100);
        }
    }
}
