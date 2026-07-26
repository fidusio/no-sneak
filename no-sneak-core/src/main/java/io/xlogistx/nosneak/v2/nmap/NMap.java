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
 *   --no-icmp     TCP-ping discovery only
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
                int lo = Integer.parseInt(token.substring(0, dash).trim());
                int hi = Integer.parseInt(token.substring(dash + 1).trim());
                for (int p = Math.min(lo, hi); p <= Math.max(lo, hi); p++) {
                    if (p >= 1 && p <= 65535) ports.add(p);
                }
            } else {
                int p = Integer.parseInt(token);
                if (p >= 1 && p <= 65535) ports.add(p);
            }
        }
        int[] out = new int[ports.size()];
        for (int i = 0; i < out.length; i++) out[i] = ports.get(i);
        return out;
    }

    public static void main(String... args) {
        if (args.length < 1) {
            usage();
            return;
        }
        NMapConfig cfg = new NMapConfig();
        boolean discoveryOnly = false;
        Map<OutputFormat, String> outputs = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-p":             cfg.ports(parsePorts(args[++i])); break;
                case "-sV":            cfg.probeScan(true); break;
                case "--probes":       for (String n : args[++i].split(",")) cfg.probe(n.trim()); break;
                case "-Pn":            cfg.discovery(false); break;
                case "-sn":            discoveryOnly = true; break;
                case "--no-icmp":      cfg.discoveryIcmp(false); break;
                case "--max-inflight": cfg.maxInFlight = Integer.parseInt(args[++i]); break;
                case "--max-rate":     cfg.maxPerSec = Integer.parseInt(args[++i]); break;
                case "-t":             cfg.timeoutInSec(Integer.parseInt(args[++i])); break;
                case "-oN":            outputs.put(OutputFormat.NORMAL, args[++i]); break;
                case "-oX":            outputs.put(OutputFormat.XML, args[++i]); break;
                case "-oG":            outputs.put(OutputFormat.GREPABLE, args[++i]); break;
                case "-oJ":            outputs.put(OutputFormat.JSON, args[++i]); break;
                case "-oC":            outputs.put(OutputFormat.CSV, args[++i]); break;
                case "-oA": {
                    String base = args[++i];
                    for (OutputFormat f : OutputFormat.values()) {
                        outputs.put(f, base + "." + f.extension());
                    }
                    break;
                }
                default:
                    if (a.startsWith("-")) {
                        System.err.println("unknown option: " + a);
                    } else {
                        cfg.target(a);
                    }
            }
        }
        if (cfg.targets.isEmpty()) {
            usage();
            return;
        }
        if (discoveryOnly) {
            cfg.ports(new int[0]); // no ports → discovery only
        }

        NIOSocket nio = null;
        try {
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
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            SharedIOUtil.close(nio);
        }
        System.exit(0);
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
        System.out.println("  --no-icmp      TCP-ping discovery only");
        System.out.println("  --max-inflight N / --max-rate N   rate limits");
        System.out.println("  -t <sec>       per-connection timeout (default 5)");
        System.out.println("  -oN/-oX/-oG/-oJ/-oC <file>   write Normal/XML/Grepable/JSON/CSV");
        System.out.println("  -oA <base>     write all formats to base.<ext>");
    }
}
