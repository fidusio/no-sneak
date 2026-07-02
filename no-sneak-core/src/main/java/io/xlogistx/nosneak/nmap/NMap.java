package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.config.PortSpecification;
import io.xlogistx.nosneak.nmap.config.TimingTemplate;
import io.xlogistx.nosneak.nmap.output.*;
import io.xlogistx.nosneak.nmap.scan.tcp.TCPConnectScanEngine;
import io.xlogistx.nosneak.nmap.scan.udp.UDPScanEngine;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.net.NIOChannelMonitor;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.Const;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line interface for NMap scanner.
 * Provides nmap-like command-line options.
 *
 * Usage:
 *   nmap [Scan Type] [Options] target
 *
 * Scan Types:
 *   -sT  TCP Connect scan (default)
 *   -sU  UDP scan
 *   -sS  TCP SYN scan (requires privileges)
 *   -sV  Enable service/version detection
 *
 * Options:
 *   -p <ports>      Port specification (e.g., -p22,80,443 or -p1-1024)
 *   --top-ports <n> Scan n most common ports
 *   -T<0-5>         Timing template (0=paranoid, 5=insane)
 *   --timeout <sec> Connection timeout in seconds
 *   -v              Verbose output
 *   -oN <file>      Normal output to file
 *   -oX <file>      XML output to file
 *   -oG <file>      Grepable output to file
 *   -oJ <file>      JSON output to file
 *   -oC <file>      CSV output to file
 *   -oA <basename>  Output in all formats
 */
public class NMap {
    public static void main(String... args) {
        TaskUtil.setTaskProcessorThreadCount(64);
        TaskUtil.setMaxTasksQueue(4096);
//        TaskProcessor.log.setEnabled(true);
        NMapScanner.log.setEnabled(true);
        try {
            if (args.length == 0 || containsHelp(args)) {
                printUsage();
                return;
            }

            // Parse arguments
            ParsedArgs parsed = parseArgs(args);

            if (parsed.targets.isEmpty()) {
                System.err.println("Error: No target specified");
                printUsage();
                return;
            }

            // Configure logging
            NIOChannelMonitor.logger.setEnabled(parsed.verbose);
            NMapScanner.log.setEnabled(parsed.verbose);

            // Build configuration
            NMapConfig.Builder configBuilder = NMapConfig.builder()
                    .targets(parsed.targets.toArray(new String[0]))
                    .scanType(parsed.scanType)
                    .timing(parsed.timing)
                    .timeout(parsed.timeout)
                    .serviceDetection(parsed.serviceDetection)
                    .maxParallelism(parsed.parallelism)
                    .skipHostDiscovery(parsed.skipHostDiscovery)
                    .pingScanOnly(parsed.pingScanOnly)
                    .verbose(parsed.verbose);

            if (parsed.ports != null) {
                configBuilder.ports(parsed.ports);
            } else if (parsed.topPorts > 0) {
                configBuilder.topPorts(parsed.topPorts);
            }

            for (OutputFormat format : parsed.outputFormats) {
                configBuilder.outputFormat(format);
            }

            NMapConfig config = configBuilder.build();

            // Create NIOSocket for efficient callback-based scanning
            NIOSocket nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());

            // Create and configure scanner with NIOSocket
            NMapScanner scanner = NMapScanner.create(TaskUtil.defaultTaskProcessor(), config, nioSocket);

            // Register engines based on scan type
            if (parsed.scanType == ScanType.TCP_CONNECT || parsed.scanType.isTcp()) {
                scanner.registerEngine(new TCPConnectScanEngine());
            }
            if (parsed.scanType == ScanType.UDP) {
                scanner.registerEngine(new UDPScanEngine());
            }

            // Run scan
            long startTime = System.currentTimeMillis();
            System.out.println("Starting " + ScanReport.SCANNER_NAME + " " +
                    ScanReport.SCANNER_VERSION + " at " + java.time.LocalDateTime.now());

            ScanReport report = scanner.scan();

            System.out.println("After " + ScanReport.SCANNER_NAME + " " +
                    ScanReport.SCANNER_VERSION + " at " + java.time.LocalDateTime.now());
            // Output results
            outputResults(report, parsed);

            // Cleanup
            SharedIOUtil.close(scanner);




            System.out.println("Finished " + ScanReport.SCANNER_NAME + " at " + java.time.LocalDateTime.now() + " it took " + Const.TimeInMillis.toString(System.currentTimeMillis() - startTime));
            //System.out.println("Finished " + GSONUtil.toJSONDefault(TaskUtil.info(), true));

            TaskUtil.waitIfBusyThenClose(100);
            SharedIOUtil.close(nioSocket);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            if (containsVerbose(args)) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }

    private static ParsedArgs parseArgs(String[] args) {
        ParsedArgs parsed = new ParsedArgs();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            // Scan types
            if (arg.equals("-sT")) {
                parsed.scanType = ScanType.TCP_CONNECT;
            } else if (arg.equals("-sU")) {
                parsed.scanType = ScanType.UDP;
            } else if (arg.equals("-sS")) {
                parsed.scanType = ScanType.SYN;
            } else if (arg.equals("-sV")) {
                parsed.serviceDetection = true;
            } else if (arg.equals("-sn") || arg.equals("-sP")) {
                // Ping scan only - no port scan
                parsed.pingScanOnly = true;
            }
            // Host discovery options
            else if (arg.equals("-Pn") || arg.equals("-PN")) {
                // Skip host discovery - treat all hosts as online
                parsed.skipHostDiscovery = true;
            }
            // Timing
            else if (arg.startsWith("-T")) {
                parsed.timing = TimingTemplate.parse(arg.substring(2));
            }
            // Ports
            else if (arg.equals("-p") && i + 1 < args.length) {
                parsed.ports = PortSpecification.parse(args[++i]);
            } else if (arg.startsWith("-p")) {
                parsed.ports = PortSpecification.parse(arg.substring(2));
            } else if (arg.equals("--top-ports") && i + 1 < args.length) {
                parsed.topPorts = Integer.parseInt(args[++i]);
            }
            // Timeout
            else if (arg.equals("--timeout") && i + 1 < args.length) {
                parsed.timeout = Integer.parseInt(args[++i]);
            }
            // Parallelism
            else if ((arg.equals("--max-parallelism") || arg.equals("-P")) && i + 1 < args.length) {
                parsed.parallelism = Integer.parseInt(args[++i]);
            }
            // Verbose
            else if (arg.equals("-v") || arg.equals("--verbose")) {
                parsed.verbose = true;
            }
            // Output files
            else if (arg.equals("-oN") && i + 1 < args.length) {
                parsed.outputFormats.add(OutputFormat.NORMAL);
                parsed.normalFile = args[++i];
            } else if (arg.equals("-oX") && i + 1 < args.length) {
                parsed.outputFormats.add(OutputFormat.XML);
                parsed.xmlFile = args[++i];
            } else if (arg.equals("-oG") && i + 1 < args.length) {
                parsed.outputFormats.add(OutputFormat.GREPABLE);
                parsed.grepFile = args[++i];
            } else if (arg.equals("-oJ") && i + 1 < args.length) {
                parsed.outputFormats.add(OutputFormat.JSON);
                parsed.jsonFile = args[++i];
            } else if (arg.equals("-oC") && i + 1 < args.length) {
                parsed.outputFormats.add(OutputFormat.CSV);
                parsed.csvFile = args[++i];
            } else if (arg.equals("-oA") && i + 1 < args.length) {
                String base = args[++i];
                parsed.outputFormats.add(OutputFormat.NORMAL);
                parsed.outputFormats.add(OutputFormat.XML);
                parsed.outputFormats.add(OutputFormat.GREPABLE);
                parsed.outputFormats.add(OutputFormat.JSON);
                parsed.normalFile = base + ".txt";
                parsed.xmlFile = base + ".xml";
                parsed.grepFile = base + ".gnmap";
                parsed.jsonFile = base + ".json";
            }
            // Legacy format: host=value
            else if (arg.startsWith("host=")) {
                parsed.targets.add(arg.substring(5));
            } else if (arg.startsWith("range=")) {
                parsed.ports = PortSpecification.parse(arg.substring(6));
            } else if (arg.startsWith("timeout=")) {
                parsed.timeout = Integer.parseInt(arg.substring(8));
            } else if (arg.startsWith("logs=")) {
                parsed.verbose = Boolean.parseBoolean(arg.substring(5));
            }
            // Target (not starting with -)
            else if (!arg.startsWith("-") && !arg.contains("=")) {
                parsed.targets.add(arg);
            }
        }

        return parsed;
    }

    private static void outputResults(ScanReport report, ParsedArgs parsed) throws Exception {
        // Always output to console
        NormalFormatter normalFormatter = new NormalFormatter();
        System.out.println(normalFormatter.format(report));

        // Output to files if specified
        if (parsed.normalFile != null) {
            try (FileWriter writer = new FileWriter(parsed.normalFile)) {
                normalFormatter.formatTo(report, writer);
            }
            System.out.println("Normal output written to: " + parsed.normalFile);
        }

        if (parsed.xmlFile != null) {
            try (FileWriter writer = new FileWriter(parsed.xmlFile)) {
                new XMLFormatter().formatTo(report, writer);
            }
            System.out.println("XML output written to: " + parsed.xmlFile);
        }

        if (parsed.grepFile != null) {
            try (FileWriter writer = new FileWriter(parsed.grepFile)) {
                new GrepableFormatter().formatTo(report, writer);
            }
            System.out.println("Grepable output written to: " + parsed.grepFile);
        }

        if (parsed.jsonFile != null) {
            try (FileWriter writer = new FileWriter(parsed.jsonFile)) {
                new JSONFormatter().formatTo(report, writer);
            }
            System.out.println("JSON output written to: " + parsed.jsonFile);
        }

        if (parsed.csvFile != null) {
            try (FileWriter writer = new FileWriter(parsed.csvFile)) {
                new CSVFormatter().formatTo(report, writer);
            }
            System.out.println("CSV output written to: " + parsed.csvFile);
        }
    }

    private static boolean containsHelp(String[] args) {
        for (String arg : args) {
            if (arg.equals("-h") || arg.equals("--help") || arg.equals("-?")) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsVerbose(String[] args) {
        for (String arg : args) {
            if (arg.equals("-v") || arg.equals("--verbose")) {
                return true;
            }
        }
        return false;
    }

    private static void printUsage() {
        System.out.println("XNMap - Network Scanner");
        System.out.println();
        System.out.println("Usage: nmap [Scan Type] [Options] <target>");
        System.out.println();
        System.out.println("TARGET SPECIFICATION:");
        System.out.println("  Can pass hostnames, IP addresses, networks, etc.");
        System.out.println("  Ex: scanme.nmap.org, 192.168.0.1, 10.0.0.0/24, 192.168.1.1-254");
        System.out.println();
        System.out.println("SCAN TYPES:");
        System.out.println("  -sT             TCP Connect scan (default)");
        System.out.println("  -sU             UDP scan");
        System.out.println("  -sS             TCP SYN scan (requires privileges)");
        System.out.println("  -sn             Ping scan only - disable port scan");
        System.out.println();
        System.out.println("HOST DISCOVERY:");
        System.out.println("  -Pn             Skip host discovery (treat all hosts as online)");
        System.out.println("  -sn             Ping scan - just discover hosts, no port scan");
        System.out.println();
        System.out.println("SERVICE/VERSION DETECTION:");
        System.out.println("  -sV             Probe open ports for service/version info");
        System.out.println();
        System.out.println("PORT SPECIFICATION:");
        System.out.println("  -p <ports>      Port ranges (e.g., -p22,80,443 or -p1-1024)");
        System.out.println("  --top-ports <n> Scan n most common ports");
        System.out.println();
        System.out.println("TIMING AND PERFORMANCE:");
        System.out.println("  -T<0-5>             Timing template (0=paranoid, 5=insane)");
        System.out.println("  --timeout <sec>     Connection timeout in seconds");
        System.out.println("  --max-parallelism <n>  Maximum concurrent scans (default: 1024)");
        System.out.println("  -P <n>              Alias for --max-parallelism");
        System.out.println();
        System.out.println("OUTPUT:");
        System.out.println("  -v              Verbose output");
        System.out.println("  -oN <file>      Normal output to file");
        System.out.println("  -oX <file>      XML output to file");
        System.out.println("  -oG <file>      Grepable output to file");
        System.out.println("  -oJ <file>      JSON output to file");
        System.out.println("  -oC <file>      CSV output to file");
        System.out.println("  -oA <basename>  Output in all formats");
        System.out.println();
        System.out.println("EXAMPLES:");
        System.out.println("  nmap 192.168.1.1");
        System.out.println("  nmap -sT -p22,80,443 192.168.1.1");
        System.out.println("  nmap -sU --top-ports 20 192.168.1.0/24");
        System.out.println("  nmap -T4 -sV -p1-1024 example.com");
        System.out.println("  nmap -oA scan_results 192.168.1.1");
        System.out.println("  nmap -sn 192.168.1.0/24           # Discover hosts on network");
        System.out.println("  nmap -Pn 192.168.1.1              # Skip host discovery");
        System.out.println("  nmap 192.168.1.1-254              # Scan IP range");
        System.out.println();
        System.out.println("LEGACY FORMAT (still supported):");
        System.out.println("  nmap host=192.168.1.1 range=[1,1024] timeout=5");
    }

    private static class ParsedArgs {
        List<String> targets = new ArrayList<>();
        ScanType scanType = ScanType.TCP_CONNECT;
        PortSpecification ports = null;
        int topPorts = 0;
        TimingTemplate timing = TimingTemplate.T3;
        int timeout = 5;
        int parallelism = 1024;
        boolean serviceDetection = false;
        boolean skipHostDiscovery = false;
        boolean pingScanOnly = false;
        boolean verbose = false;
        List<OutputFormat> outputFormats = new ArrayList<>();
        String normalFile;
        String xmlFile;
        String grepFile;
        String jsonFile;
        String csvFile;
    }
}
