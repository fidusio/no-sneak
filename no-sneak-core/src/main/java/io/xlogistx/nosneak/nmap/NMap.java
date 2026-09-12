package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.nmap.output.NormalFormatter;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * NIO-native, staged network scanner CLI (host discovery → port scan → optional probe scan),
 * a thin wrapper over the embeddable {@link NMapScanner}. Fully non-blocking. Renders to five
 * output formats (Normal/JSON/XML/CSV/Grepable).
 *
 * <pre>
 * Usage: NMap &lt;target...&gt; [options]
 *   target        host | IP | CIDR (10.0.0.0/24) | range (10.0.0.1-50, 192.168.1-5.1-254) | a,b,c
 *   -p &lt;spec&gt;      ports: 22,80,443 or 1-1024; T:/U: prefixes  (default: 1-1024)
 *   -sU           UDP scan (common UDP ports, or the U: half of -p); UDP-only unless T: ports given
 *   --top-ports N scan nmap's N most common TCP ports (max 100)
 *   --open        report only open ports
 *   -sV           probe scan: service/version/TLS/PQC on open ports
 *   --probes a,b  restrict the probe scan to named probes
 *   -Pn / -PN     skip host discovery (treat every target as up)
 *   -sn / -sP     discovery only (no port scan)
 *   -PR           ARP/NDP discovery only (on-link; yields the remote MAC)
 *   -PE           ICMP-echo discovery only
 *   --no-icmp / --no-arp / --no-tcp-ping   turn one discovery method off
 *   --icmp-probes N   echo requests per host (pipelined; default 2)
 *   -n / -R       never / always reverse-resolve (default: live hosts only)
 *   --dns-servers ip   resolver for the PTR lookups (default: the system resolver)
 *   -T0..-T5, -T &lt;n|name&gt;   timing template (default T3 = 256 in flight, 2000/s, 5 s timeout)
 *   --max-inflight N / --max-parallelism N / -P N / --max-rate N   rate limits (0 = unlimited)
 *   -t &lt;sec&gt; / --timeout &lt;sec&gt;   per-connection timeout (default 5)
 *   -v            verbose Normal output
 *   -oN/-oX/-oG/-oJ/-oC &lt;file&gt;   write Normal/XML/Grepable/JSON/CSV ("-" = stdout)
 *   -oA &lt;base&gt;    write all formats to base.&lt;ext&gt;
 * </pre>
 * Raw and evasive scan types ({@code -sS -sF -sX -sN -sA -sW -sM}, {@code -O}, {@code --stealth})
 * are rejected by name: this is assessment tooling and implements the TCP connect scan only
 * (repo root {@code CLAUDE.md}, <i>Operating scope</i>).
 */
public final class NMap {

    /**
     * The TCP ports scanned when {@code -p} is absent: {@code 1-1024}, nmap's classic
     * well-known range and what the v1 scanner defaulted to. {@code --top-ports N} is the
     * cheaper alternative when a thousand connects per host is too many.
     */
    public static final int[] DEFAULT_PORTS = range(1, 1024);

    /**
     * Scan types this tool will never implement, with the reason spelled out at the point of
     * refusal rather than as a generic "unknown option". The list is the legacy nmap vocabulary
     * the repo-root {@code CLAUDE.md} names under <i>No evasion</i>.
     */
    static final List<String> REJECTED_SCAN_FLAGS = List.of(
            "-sS", "-sF", "-sX", "-sN", "-sA", "-sW", "-sM", "-O", "--stealth");

    /**
     * Thrown by {@link #parseArgs} on {@code -h}/{@code --help}/{@code -?}: not an error, but
     * the parse cannot continue. Its message is the usage text, so a caller that treats it like
     * any other {@link IllegalArgumentException} still shows the right thing; {@link #main}
     * prints it and exits 0.
     */
    public static final class HelpRequested extends IllegalArgumentException {
        public HelpRequested() {
            super(usageText());
        }
    }

    private NMap() {
    }

    private static int[] range(int from, int to) {
        int[] out = new int[to - from + 1];
        for (int i = 0; i < out.length; i++) out[i] = from + i;
        return out;
    }

    /** The two halves of a {@code -p} spec: what {@code T:} named (or bare tokens) and what {@code U:} named. */
    public record PortSpec(int[] tcp, int[] udp) {
    }

    /**
     * Parse a port spec like {@code "22,80,443"} or {@code "1-1024"} into a TCP port array.
     * {@code T:}/{@code U:} prefixes are accepted; only the TCP half is returned here — use
     * {@link #parsePortSpec} to see both.
     */
    public static int[] parsePorts(String spec) {
        if (spec == null || spec.isEmpty()) {
            return DEFAULT_PORTS;
        }
        return parsePortSpec(spec).tcp();
    }

    /**
     * Parse a port spec with optional nmap-style protocol prefixes. A prefix applies to every
     * token after it until the next prefix; bare tokens are TCP. {@code "T:22,80,U:53,161"}
     * yields TCP {22, 80} and UDP {53, 161}. Ranges are clamped to 1..65535 before iterating,
     * so {@code 1-2000000000} cannot look like a hang. A port named twice ({@code 80,80} or
     * {@code 22,20-25}) is scanned once, in first-seen order.
     */
    public static PortSpec parsePortSpec(String spec) {
        Set<Integer> tcp = new LinkedHashSet<>();
        Set<Integer> udp = new LinkedHashSet<>();
        if (spec == null || spec.isEmpty()) {
            return new PortSpec(DEFAULT_PORTS.clone(), new int[0]);
        }
        Set<Integer> current = tcp;
        for (String token : spec.split(",")) {
            token = token.trim();
            if (token.isEmpty()) continue;
            if (token.length() >= 2 && token.charAt(1) == ':') {
                char proto = Character.toUpperCase(token.charAt(0));
                if (proto == 'T') {
                    current = tcp;
                } else if (proto == 'U') {
                    current = udp;
                } else {
                    throw new IllegalArgumentException("bad port spec '" + spec + "': unknown protocol prefix '"
                            + token.substring(0, 2) + "' (use T: or U:)");
                }
                token = token.substring(2).trim();
                if (token.isEmpty()) continue;
            }
            int dash = token.indexOf('-');
            if (dash > 0) {
                int lo = port(token.substring(0, dash), spec);
                int hi = port(token.substring(dash + 1), spec);
                // Clamp to the legal range before iterating: "-p 1-2000000000" would otherwise
                // spin through two billion values appending nothing and look like a hang.
                int from = Math.max(1, Math.min(lo, hi));
                int upto = Math.min(65535, Math.max(lo, hi));
                for (int p = from; p <= upto; p++) {
                    current.add(p);
                }
            } else {
                int p = port(token, spec);
                if (p >= 1 && p <= 65535) current.add(p);
            }
        }
        return new PortSpec(toArray(tcp), toArray(udp));
    }

    private static int[] toArray(Set<Integer> ports) {
        int[] out = new int[ports.size()];
        int i = 0;
        for (int p : ports) out[i++] = p;
        return out;
    }

    /** {@code --top-ports N}: nmap's N most common TCP ports, clamped to the table's size. */
    public static int[] topPorts(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("--top-ports expects a number >= 1, got " + n);
        }
        return WellKnownPorts.topTcp(n);
    }

    /**
     * The refusal message for a scan type this tool does not implement. One place, so the CLI,
     * the app's command box and the tests all say the same thing.
     */
    public static String rejectionMessage(String flag) {
        return flag + " is not supported: no-sneak is assessment-only and does not implement raw, "
                + "SYN, FIN/Xmas/NULL/ACK/Window, OS-fingerprint or evasive scans (see CLAUDE.md, "
                + "Operating scope). Use the default TCP connect scan.";
    }

    /**
     * A timing template by digit ({@code 4}), by enum name ({@code T4}) or by nmap's word
     * ({@code aggressive}): paranoid/sneaky/polite/normal/aggressive/insane = T0..T5.
     */
    public static NMapConfig.Timing timingOf(String value, String flag) {
        String v = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        switch (v) {
            case "0": case "t0": case "paranoid":   return NMapConfig.Timing.T0;
            case "1": case "t1": case "sneaky":     return NMapConfig.Timing.T1;
            case "2": case "t2": case "polite":     return NMapConfig.Timing.T2;
            case "3": case "t3": case "normal":     return NMapConfig.Timing.T3;
            case "4": case "t4": case "aggressive": return NMapConfig.Timing.T4;
            case "5": case "t5": case "insane":     return NMapConfig.Timing.T5;
            default:
                throw new IllegalArgumentException(flag + " expects 0..5 or "
                        + "paranoid|sneaky|polite|normal|aggressive|insane, got '" + value + "'");
        }
    }

    private static int port(String token, String spec) {
        try {
            return Integer.parseInt(token.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad port spec '" + spec + "': '" + token.trim()
                    + "' is not a number");
        }
    }

    /** The value after a flag, or a clear error instead of an ArrayIndexOutOfBoundsException. */
    private static String argOf(String[] args, int i, String flag) {
        if (i >= args.length) {
            throw new IllegalArgumentException(flag + " requires a value");
        }
        return args[i];
    }

    private static int intArg(String[] args, int i, String flag) {
        return intOf(argOf(args, i, flag), flag);
    }

    private static int intOf(String v, String flag) {
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(flag + " expects a number, got '" + v + "'");
        }
    }

    public static NMapConfig parseArgs(Map<OutputFormat, String> outputs, String... args) {
        NMapConfig cfg = new NMapConfig();
        boolean discoveryOnly = false;
        boolean tcpSpecified = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (REJECTED_SCAN_FLAGS.contains(a)) {
                throw new IllegalArgumentException(rejectionMessage(a));
            }
            switch (a) {
                case "-p": {
                    PortSpec spec = parsePortSpec(argOf(args, ++i, a));
                    cfg.ports(spec.tcp());
                    tcpSpecified = spec.tcp().length > 0;
                    if (spec.udp().length > 0) {
                        cfg.udpPorts(spec.udp());
                    }
                    break;
                }
                case "--top-ports":    cfg.ports(topPorts(intArg(args, ++i, a))); tcpSpecified = true; break;
                case "-sU":            cfg.udpScan(true); break;
                case "--open":         cfg.openOnly(true); break;
                case "-T":             cfg.timing(timingOf(argOf(args, ++i, a), a)); break;
                case "-sV":            cfg.probeScan(true); break;
                case "--probes":       for (String n : argOf(args, ++i, a).split(",")) cfg.probe(n.trim()); break;
                case "-Pn": case "-PN": cfg.discovery(false); break;
                case "-sn": case "-sP": discoveryOnly = true; break;
                case "--no-icmp":      cfg.discoveryIcmp(false); break;
                case "--no-arp":       cfg.discoveryArp(false); break;
                case "--no-tcp-ping":  cfg.discoveryTcp(false); break;
                case "-PR":            cfg.discoveryTcp(false).discoveryIcmp(false).discoveryArp(true); break;
                case "-PE":            cfg.discoveryTcp(false).discoveryArp(false).discoveryIcmp(true); break;
                case "--icmp-probes":  cfg.icmpProbes(intArg(args, ++i, a)); break;
                case "-n":             cfg.reverseDns(NMapConfig.ReverseDns.NEVER); break;
                case "-R":             cfg.reverseDns(NMapConfig.ReverseDns.ALL); break;
                case "--dns-servers":  cfg.dnsServer(argOf(args, ++i, a).split(",")[0].trim()); break;
                case "--max-inflight": case "--max-parallelism": case "-P":
                                       cfg.maxInFlight = intArg(args, ++i, a); break;
                case "--max-rate":     cfg.maxPerSec = intArg(args, ++i, a); break;
                case "-t": case "--timeout":
                                       cfg.timeoutInSec(intArg(args, ++i, a)); break;
                case "-v": case "--verbose":
                                       cfg.verbose(true); break;
                case "-h": case "--help": case "-?":
                                       throw new HelpRequested();
                case "-oN":            outputs.put(OutputFormat.NORMAL, argOf(args, ++i, a)); break;
                case "-oX":            outputs.put(OutputFormat.XML, argOf(args, ++i, a)); break;
                case "-oG":            outputs.put(OutputFormat.GREPABLE, argOf(args, ++i, a)); break;
                case "-oJ":            outputs.put(OutputFormat.JSON, argOf(args, ++i, a)); break;
                case "-oC":            outputs.put(OutputFormat.CSV, argOf(args, ++i, a)); break;
                case "-oA": {
                    String base = argOf(args, ++i, a);
                    for (OutputFormat f : OutputFormat.values()) {
                        outputs.put(f, base + "." + f.extension());
                    }
                    break;
                }
                default:
                    if (a.startsWith("-p") && a.length() > 2) {
                        // attached form: -p22,80 / -p1-1024 / -pT:22,U:53
                        PortSpec spec = parsePortSpec(a.substring(2));
                        cfg.ports(spec.tcp());
                        tcpSpecified = spec.tcp().length > 0;
                        if (spec.udp().length > 0) {
                            cfg.udpPorts(spec.udp());
                        }
                    } else if (a.startsWith("-T") && a.length() > 2) {
                        cfg.timing(timingOf(a.substring(2), "-T"));       // -T4, -Taggressive
                    } else if (a.startsWith("host=")) {
                        cfg.target(a.substring("host=".length()));         // v1 legacy key=value
                    } else if (a.startsWith("range=")) {
                        String[] lh = a.substring("range=".length()).split(",");
                        if (lh.length != 2) {
                            throw new IllegalArgumentException("range= expects two ports, range=<from>,<to>");
                        }
                        cfg.ports(parsePortSpec(intOf(lh[0], "range=") + "-" + intOf(lh[1], "range=")).tcp());
                        tcpSpecified = true;
                    } else if (a.startsWith("timeout=")) {
                        cfg.timeoutInSec(intOf(a.substring("timeout=".length()), "timeout="));
                    } else if (a.startsWith("-")) {
                        throw new IllegalArgumentException("unknown option: " + a);
                    } else {
                        cfg.target(a);
                    }
            }
        }
        if (cfg.targets.isEmpty()) {
            throw new IllegalArgumentException("at least one target is required");
        }
        if (cfg.udpScan) {
            // nmap semantics: -sU alone is a UDP-only scan of the common UDP ports; TCP ports
            // are scanned alongside only when T: ports or --top-ports were named too.
            if (cfg.udpPorts == null || cfg.udpPorts.length == 0) {
                cfg.udpPorts(WellKnownPorts.TOP_20_UDP.clone());
            }
            if (!tcpSpecified) {
                cfg.ports(new int[0]);
            }
        }
        if (discoveryOnly) {
            cfg.ports(new int[0]);    // no ports → discovery only
            cfg.udpPorts(new int[0]);
        }
        return cfg;
    }

    public static NMapConfig parseCommand(String command) {
        String trimmed = command != null ? command.trim() : "";
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("at least one target is required");
        }
        return parseArgs(new UnwritableOutputs(), trimmed.split("\\s+"));
    }

    private static final class UnwritableOutputs extends LinkedHashMap<OutputFormat, String> {
        @Override
        public String put(OutputFormat key, String value) {
            throw new IllegalArgumentException("output-file options are not supported here");
        }
    }

    /** Hidden test hook: {@code --cancel-after-ms N} stops the scan N ms in, from a runner that cannot send Ctrl-C. */
    static final String CANCEL_AFTER_FLAG = "--cancel-after-ms";

    public static void main(String... args) {
        if (args.length < 1) {
            usage();
            return;
        }
        // The hidden cancel hook is stripped before parsing so it never reaches the config.
        long cancelAfterMs = -1;
        List<String> kept = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if (CANCEL_AFTER_FLAG.equals(args[i]) && i + 1 < args.length) {
                cancelAfterMs = Long.parseLong(args[++i]);
            } else {
                kept.add(args[i]);
            }
        }
        args = kept.toArray(new String[0]);
        NMapConfig cfg;
        Map<OutputFormat, String> outputs = new LinkedHashMap<>();
        try {
            cfg = parseArgs(outputs, args);
        } catch (HelpRequested h) {
            usage();
            System.exit(0);
            return;
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(2);
            return;
        }

        NIOSocket nio = null;
        int exitCode = 0;
        // Ctrl-C stops the scan and still prints what completed: the hook cancels, then waits
        // (bounded) for the main thread to finish printing before the JVM halts. Cancelling is a
        // flag flip plus exactly-once completions, so the report arrives within a read tick.
        final java.util.concurrent.atomic.AtomicReference<NMapScanner.ScanHandle> running =
                new java.util.concurrent.atomic.AtomicReference<>();
        final java.util.concurrent.CountDownLatch printed = new java.util.concurrent.CountDownLatch(1);
        Thread hook = new Thread(() -> {
            NMapScanner.ScanHandle h = running.get();
            if (h != null && h.cancel()) {
                System.err.println("Cancelling scan (interrupt)...");
                try {
                    printed.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "nmap-cancel");
        Runtime.getRuntime().addShutdownHook(hook);
        try {
            // Composition root: this is the one place the process-wide pools are chosen. Everything
            // downstream takes the executor/scheduler from the NIOSocket it is handed.
            nio = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            CompletableFuture<ScanReport> future = new CompletableFuture<>();
            NMapScanner.ScanHandle handle = NMapScanner.scan(nio, cfg,
                    new CallableConsumerTask<ScanReport>().setConsumer(future::complete));
            running.set(handle);
            if (cancelAfterMs >= 0) {
                nio.getScheduler().schedule(handle::cancel, cancelAfterMs, TimeUnit.MILLISECONDS);
            }
            ScanReport report;
            try {
                report = future.get(maxWaitMs(cfg), TimeUnit.MILLISECONDS);
            } catch (java.util.concurrent.TimeoutException te) {
                // The wait budget ran out. Stop the scan rather than leave it running behind a
                // report that says nothing about it, and print what had completed.
                System.err.println("Wait budget of " + maxWaitMs(cfg) + " ms exhausted; cancelling scan");
                handle.cancel();
                report = future.get(10, TimeUnit.SECONDS);
            }
            report.commandLine = String.join(" ", args);
            if (report.cancelled) {
                System.out.println(NMapScanner.progress(report).cancelledLine());
            }

            System.out.print(new NormalFormatter().render(report)); // console = normal
            for (Map.Entry<OutputFormat, String> e : outputs.entrySet()) {
                if ("-".equals(e.getValue())) { // nmap convention: "-" means stdout
                    try {
                        OutputFormat.formatter(e.getKey()).formatTo(report, System.out);
                    } catch (Exception w) {
                        System.err.println("Failed writing " + e.getKey() + " to stdout: " + w.getMessage());
                        exitCode = 1;
                    }
                    continue;
                }
                try (OutputStream out = Files.newOutputStream(Paths.get(e.getValue()))) {
                    OutputFormat.formatter(e.getKey()).formatTo(report, out);
                    System.out.println("Wrote " + e.getKey() + " -> " + e.getValue());
                } catch (Exception w) {
                    System.err.println("Failed writing " + e.getValue() + ": " + w.getMessage());
                    exitCode = 1; // an unwritten output file must not report success
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e);
            exitCode = 1;
        } finally {
            printed.countDown();
            SharedIOUtil.close(nio);
        }
        try {
            Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
            // already shutting down: the hook is running or done
        }
        System.exit(exitCode);
    }

    /**
     * Generous upper bound: (waves through the rate/parallelism cap) × per-connection budget.
     * With the bounded defaults (256 / 2000) both terms are finite for any range; {@code 0}
     * on either knob falls back to the historical 64-wide wave estimate.
     */
    public static long maxWaitMs(NMapConfig cfg) {
        int hosts = Math.max(1, NMapScanner.expand(cfg.targets).size());
        // A silent UDP port costs the full timeout (one retransmit inside it), like a filtered
        // TCP port, so UDP ports are units of the same size. The PTR lookup is one more unit
        // per host.
        int ports = (cfg.ports != null ? cfg.ports.length : DEFAULT_PORTS.length)
                + (cfg.udpPorts != null ? cfg.udpPorts.length : 0)
                + NMapScanner.DEFAULT_DISCOVERY_PORTS.length + 2;
        long units = (long) hosts * ports * (cfg.probeScan ? 2 : 1);
        long par = cfg.maxInFlight > 0 ? cfg.maxInFlight : 64;
        long waves = units / par + 1;
        long byPar = waves * (cfg.timeoutSec + 2L) * 1000L + 30000L;
        long byRate = cfg.maxPerSec > 0
                ? (units / cfg.maxPerSec) * 1000L + (cfg.timeoutSec + 2L) * 2000L : 0;
        return Math.max(byPar, byRate);
    }

    public static String usageText() {
        return """
                Usage: NMap <target...> [options]
                  target         host | IP | CIDR (10.0.0.0/24) | range (10.0.0.1-50, 10.0.0.1-10.0.1.9,
                                 192.168.1-5.1-254) | comma-separated list (10.0.0.1,10.0.0.5,example.com)
                                 (expansion is capped at 65536 addresses per spec, with a warning)
                  -p <spec>      ports: 22,80,443 or 1-1024 (default: 1-1024); -p22,80 also accepted
                                 T:/U: prefixes accepted (T:22,80,U:53); U: ports get a UDP probe
                  -sU            UDP scan: common UDP ports, or the U: ports of -p; UDP-only unless
                                 T: ports or --top-ports are named too (open / closed / open|filtered)
                  --top-ports N  scan nmap's N most common TCP ports (1..100)
                  --open         report only open ports
                  -sV            probe scan: service/version/TLS/PQC on open ports
                  --probes a,b   restrict probe scan to named probes
                  -Pn / -PN      skip host discovery (all targets up)
                  -sn / -sP      discovery only (no port scan)
                  -PR            ARP/NDP discovery only (on-link; yields remote MAC)
                  -PE            ICMP-echo discovery only
                  --no-icmp / --no-arp / --no-tcp-ping   turn one method off
                  --icmp-probes N   echo requests per host (pipelined; default 2)
                  -n / -R        never / always reverse-resolve hostnames (default: live hosts only)
                  --dns-servers <ip>   resolver for the PTR lookups (default: system resolver, else 8.8.8.8)
                  -T0..-T5       timing template: in-flight / per-second / timeout
                                 also -T <n>, -T4, -T aggressive (paranoid|sneaky|polite|normal|aggressive|insane)
                                 T0 1/1/15s  T1 4/10/15s  T2 16/50/10s  T3 256/2000/5s (default)
                                 T4 512/5000/3s  T5 1024/10000/2s
                  --max-inflight N / --max-parallelism N / -P N   concurrent-connection cap (default 256; 0 = unlimited)
                  --max-rate N   new connections per second (default 2000; 0 = unlimited)
                  -t <sec> / --timeout <sec>   per-connection timeout (default 5)
                  -v / --verbose run header and per-host scanned-port counts in Normal output
                  -h / --help    this text
                  -oN/-oX/-oG/-oJ/-oC <file>   write Normal/XML/Grepable/JSON/CSV ("-" = stdout)
                  -oA <base>     write all formats to base.<ext>
                  legacy (v1):   host=<target>  range=<from>,<to>  timeout=<sec>
                Not supported, by design: -sS -sF -sX -sN -sA -sW -sM -O --stealth
                  (assessment-only tooling: TCP connect scan, no raw or evasive scans)""";
    }

    private static void usage() {
        System.out.println(usageText());
    }
}
