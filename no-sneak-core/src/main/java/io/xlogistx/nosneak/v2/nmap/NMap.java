package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.nmap.output.NormalFormatter;
import io.xlogistx.nosneak.v2.nmap.output.OutputFormat;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * NIO-native, staged network scanner CLI (host discovery → port scan → optional probe scan),
 * a thin wrapper over the embeddable {@link NMapScanner}. Fully non-blocking. Renders to five
 * output formats (Normal/JSON/XML/CSV/Grepable).
 *
 * <pre>
 * Usage: NMap &lt;target...&gt; [options]
 *   target        host | IP | CIDR (10.0.0.0/24) | range (10.0.0.1-50)
 *   -p &lt;spec&gt;      ports: 22,80,443 or 1-1024      (default: common ports)
 *   -sV           probe scan: service/version/TLS/PQC on open ports
 *   --probes a,b  restrict the probe scan to named probes
 *   -Pn           skip host discovery (treat every target as up)
 *   -sn           discovery only (no port scan)
 *   -PR           ARP/NDP discovery only (on-link; yields the remote MAC)
 *   -PE           ICMP-echo discovery only
 *   --no-icmp / --no-arp / --no-tcp-ping   turn one discovery method off
 *   --icmp-probes N   echo requests per host (pipelined; default 2)
 *   --max-inflight N / --max-rate N   rate limits
 *   -t &lt;sec&gt;      per-connection timeout (default 5)
 *   -oN/-oX/-oG/-oJ/-oC &lt;file&gt;   write Normal/XML/Grepable/JSON/CSV
 *   -oA &lt;base&gt;    write all formats to base.&lt;ext&gt;
 * </pre>
 */
public final class NMap {

    public static final int[] DEFAULT_PORTS = {
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            3306, 3389, 5432, 6379, 8080, 8443, 27017
    };

    private NMap() {
    }

    /** Parse a port spec like {@code "22,80,443"} or {@code "1-1024"} into a port array. */
    public static int[] parsePorts(String spec) {
        if (spec == null || spec.isEmpty()) {
            return DEFAULT_PORTS;
        }
        List<Integer> ports = new ArrayList<>();
        for (String token : spec.split(",")) {
            token = token.trim();
            if (token.isEmpty()) continue;
            int dash = token.indexOf('-');
            if (dash > 0) {
                int lo = port(token.substring(0, dash), spec);
                int hi = port(token.substring(dash + 1), spec);
                // Clamp to the legal range before iterating: "-p 1-2000000000" would otherwise
                // spin through two billion values appending nothing and look like a hang.
                int from = Math.max(1, Math.min(lo, hi));
                int upto = Math.min(65535, Math.max(lo, hi));
                for (int p = from; p <= upto; p++) {
                    ports.add(p);
                }
            } else {
                int p = port(token, spec);
                if (p >= 1 && p <= 65535) ports.add(p);
            }
        }
        int[] out = new int[ports.size()];
        for (int i = 0; i < out.length; i++) out[i] = ports.get(i);
        return out;
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
        String v = argOf(args, i, flag);
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(flag + " expects a number, got '" + v + "'");
        }
    }

    public static void main(String... args) {
        if (args.length < 1) {
            usage();
            return;
        }
        NMapConfig cfg = new NMapConfig();
        boolean discoveryOnly = false;
        Map<OutputFormat, String> outputs = new LinkedHashMap<>();
        try {
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "-p":             cfg.ports(parsePorts(argOf(args, ++i, a))); break;
                    case "-sV":            cfg.probeScan(true); break;
                    case "--probes":       for (String n : argOf(args, ++i, a).split(",")) cfg.probe(n.trim()); break;
                    case "-Pn":            cfg.discovery(false); break;
                    case "-sn":            discoveryOnly = true; break;
                    case "--no-icmp":      cfg.discoveryIcmp(false); break;
                    case "--no-arp":       cfg.discoveryArp(false); break;
                    case "--no-tcp-ping":  cfg.discoveryTcp(false); break;
                    case "-PR":            cfg.discoveryTcp(false).discoveryIcmp(false).discoveryArp(true); break;
                    case "-PE":            cfg.discoveryTcp(false).discoveryArp(false).discoveryIcmp(true); break;
                    case "--icmp-probes":  cfg.icmpProbes(intArg(args, ++i, a)); break;
                    case "--max-inflight": cfg.maxInFlight = intArg(args, ++i, a); break;
                    case "--max-rate":     cfg.maxPerSec = intArg(args, ++i, a); break;
                    case "-t":             cfg.timeoutInSec(intArg(args, ++i, a)); break;
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
                        if (a.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + a);
                        }
                        cfg.target(a);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(2);
            return;
        }
        if (cfg.targets.isEmpty()) {
            usage();
            System.exit(2);
            return;
        }
        if (discoveryOnly) {
            cfg.ports(new int[0]); // no ports → discovery only
        }

        NIOSocket nio = null;
        int exitCode = 0;
        try {
            // Composition root: this is the one place the process-wide pools are chosen. Everything
            // downstream takes the executor/scheduler from the NIOSocket it is handed.
            nio = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            CompletableFuture<ScanReport> future = new CompletableFuture<>();
            NMapScanner.scan(nio, cfg,
                    new CallableConsumerTask<ScanReport>().setConsumer(future::complete));
            ScanReport report = future.get(maxWaitMs(cfg), TimeUnit.MILLISECONDS);
            report.commandLine = String.join(" ", args);

            System.out.print(new NormalFormatter().render(report)); // console = normal
            for (Map.Entry<OutputFormat, String> e : outputs.entrySet()) {
                try {
                    String content = OutputFormat.formatter(e.getKey()).render(report);
                    Files.write(Paths.get(e.getValue()), content.getBytes(StandardCharsets.UTF_8));
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
            SharedIOUtil.close(nio);
        }
        System.exit(exitCode);
    }

    /** Generous upper bound: (waves through the rate/parallelism cap) × per-connection budget. */
    private static long maxWaitMs(NMapConfig cfg) {
        int hosts = Math.max(1, NMapScanner.expand(cfg.targets).size());
        int ports = (cfg.ports != null ? cfg.ports.length : DEFAULT_PORTS.length)
                + NMapScanner.DEFAULT_DISCOVERY_PORTS.length + 1;
        long units = (long) hosts * ports * (cfg.probeScan ? 2 : 1);
        long par = cfg.maxInFlight > 0 ? cfg.maxInFlight : 64;
        long waves = units / par + 1;
        long byPar = waves * (cfg.timeoutSec + 2L) * 1000L + 30000L;
        long byRate = cfg.maxPerSec > 0
                ? (units / cfg.maxPerSec) * 1000L + (cfg.timeoutSec + 2L) * 2000L : 0;
        return Math.max(byPar, byRate);
    }

    private static void usage() {
        System.out.println("Usage: NMap <target...> [options]");
        System.out.println("  target         host | IP | CIDR (10.0.0.0/24) | range (10.0.0.1-50)");
        System.out.println("  -p <spec>      ports: 22,80,443 or 1-1024 (default: common ports)");
        System.out.println("  -sV            probe scan: service/version/TLS/PQC on open ports");
        System.out.println("  --probes a,b   restrict probe scan to named probes");
        System.out.println("  -Pn            skip host discovery (all targets up)");
        System.out.println("  -sn            discovery only (no port scan)");
        System.out.println("  -PR            ARP/NDP discovery only (on-link; yields remote MAC)");
        System.out.println("  -PE            ICMP-echo discovery only");
        System.out.println("  --no-icmp / --no-arp / --no-tcp-ping   turn one method off");
        System.out.println("  --icmp-probes N   echo requests per host (pipelined; default 2)");
        System.out.println("  --max-inflight N / --max-rate N   rate limits");
        System.out.println("  -t <sec>       per-connection timeout (default 5)");
        System.out.println("  -oN/-oX/-oG/-oJ/-oC <file>   write Normal/XML/Grepable/JSON/CSV");
        System.out.println("  -oA <base>     write all formats to base.<ext>");
    }
}
