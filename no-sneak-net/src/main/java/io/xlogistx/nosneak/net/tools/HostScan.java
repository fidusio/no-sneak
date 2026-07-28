package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.HostDiscovery;
import io.xlogistx.nosneak.net.common.HostDiscoveryFactory;
import io.xlogistx.nosneak.net.common.HostRecord;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.common.ObservedNeighbor;
import io.xlogistx.nosneak.net.common.PingResult;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.Subscription;
import io.xlogistx.nosneak.net.common.SweepOptions;
import io.xlogistx.nosneak.net.common.SweepSummary;
import io.xlogistx.nosneak.net.util.NSNetUtil;
import org.zoxweb.shared.util.SUS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Command line over {@link HostScanner} — the fastest way to see the subsystem
 * working, and how the Windows and Linux backends were actually verified.
 *
 * <pre>
 *   hostscan                            interactive shell: many commands, one open session
 *   hostscan list                       interfaces, backend devices, capabilities
 *   hostscan resolve 10.0.0.1 10.0.0.2  ARP/NDP - the MAC, and where it came from
 *   hostscan ping    10.0.0.1 -c 4      ICMP echo, pipelined
 *   hostscan sweep   10.0.0.0/24        ARP + ICMP across a range
 *   hostscan observe 30                 passive neighbours for 30 seconds
 * </pre>
 * <p>
 * Every command takes one or more targets and runs them together: several pings
 * or resolves go out concurrently, several sweeps run one after another so the
 * per-sweep packet rate still bounds what hits the segment.
 * <p>
 * <b>The session is opened once</b> and reused for every command in the run — which
 * is the whole point of the shell. Repeatedly opening the factory around single
 * commands costs a pcap handle or a raw socket plus two reader threads per
 * interface each time.
 * <p>
 * The one thing this class does that a library must never do is call
 * {@code TaskUtil.close()} on exit: zoxweb's pool threads are not daemons, so the
 * process would otherwise hang after the work is done. That is legitimate only
 * because {@code HostScan} owns the process — {@link HostScanner#close()}
 * deliberately leaves the pools alone.
 */
public final class HostScan {

    private static final Duration AWAIT_SLACK = Duration.ofSeconds(10);
    private static final Duration LOOKUP_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration SWEEP_BUDGET = Duration.ofMinutes(10);

    private HostScan() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Current version:" + NSNetUtil.VERSION);
        System.out.println("Current OS: " + SUS.toCanonicalID(',', System.getProperty("os.name"), System.getProperty("os.arch"),System.getProperty("os.version")));
        if (args.length > 0 && isHelp(args[0])) {
            usage(System.out);
            return;
        }
        int exit = 0;
        try (HostScanner scanner = HostScanner.open()) {
            if (args.length == 0 || args[0].equalsIgnoreCase("shell")) {
                System.out.println("session : " + scanner.mode() + " - " + scanner.diagnostic());
                shell(scanner, System.out);
            } else {
                exit = runOnce(scanner, args, System.out);
            }
        } finally {
            shutdownSharedPools();
        }
        if (exit != 0) {
            System.exit(exit);
        }
    }

    private static int runOnce(HostScanner scanner, String[] argv, PrintStream out) {
        try {
            return execute(scanner, argv, out);
        } catch (Exception e) {
            printFailure(e, out);
            return 1;
        }
    }

    /**
     * Reads commands until EOF or {@code quit}, against the one open session.
     * <p>
     * A failing command reports and returns to the prompt: a timed-out sweep is no
     * reason to tear down handles that took real work to open.
     */
    private static void shell(HostScanner scanner, PrintStream out) throws IOException {
        out.println("Interactive mode - one command per line, 'help' for the list, "
                    + "'quit' to exit.");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            out.print("hostscan> ");
            out.flush();
            String line = in.readLine();
            if (line == null) {
                out.println();
                return;
            }
            String[] argv = tokenize(line);
            if (argv.length == 0) {
                continue;
            }
            String command = argv[0].toLowerCase(Locale.ROOT);
            if (command.equals("quit") || command.equals("exit")) {
                return;
            }
            try {
                execute(scanner, argv, out);
            } catch (Exception e) {
                printFailure(e, out);
            }
            out.println();
        }
    }

    /** Dispatch, shared by the shell and the one-shot path. */
    private static int execute(HostScanner scanner, String[] argv, PrintStream out)
            throws Exception {
        String command = argv[0].toLowerCase(Locale.ROOT);
        switch (command) {
            case "list" -> list(scanner, out);
            case "status" -> status(scanner, out);
            case "reopen" -> {
                scanner.reopen();
                out.println("session : " + scanner.mode() + " - " + scanner.diagnostic());
            }
            case "ping" -> {
                return ping(scanner, Args.parse(argv, HostScanner.DEFAULT_PING_COUNT,
                                                HostScanner.DEFAULT_PING_TIMEOUT, true), out);
            }
            case "resolve" -> {
                return resolve(scanner, Args.parse(argv, 1,
                                                   HostScanner.DEFAULT_RESOLVE_TIMEOUT, false), out);
            }
            case "sweep" -> {
                return sweep(scanner, Args.parse(argv, SweepOptions.defaults().pingCount(),
                                                 SweepOptions.defaults().perHostTimeout(), false), out);
            }
            case "segment" -> {
                return segment(scanner, Args.parse(argv, SweepOptions.defaults().pingCount(),
                                                   SweepOptions.defaults().perHostTimeout(), false), out);
            }
            case "observe" -> observe(scanner, argv, out);
            case "help" -> usage(out);
            default -> {
                out.println("Unknown command: " + command);
                usage(out);
                return 2;
            }
        }
        return 0;
    }

    // -------------------------------------------------------------- commands

    private static void list(HostScanner scanner, PrintStream out) {
        List<HostDiscovery> nics = scanner.interfaces();
        if (nics.isEmpty()) {
            out.println("No layer-2 interfaces are bound (" + scanner.diagnostic() + ").");
            listFromJavaNet(out);
        } else {
            out.println(HostScanFormat.nicHeader());
            for (HostDiscovery h : nics) {
                out.println(HostScanFormat.nic(h));
            }
        }
        status(scanner, out);
    }

    /**
     * What {@code list} can still say with no layer-2 backend: the interfaces as
     * java.net sees them. Needs no native access at all.
     */
    private static void listFromJavaNet(PrintStream out) {
        try {
            for (java.net.NetworkInterface nif : HostDiscoveryFactory.usableInterfaces()) {
                byte[] mac = nif.getHardwareAddress();
                out.printf("%-16s %-8d %s%n", nif.getName(), nif.getIndex(),
                           mac == null ? "-" : new MacAddress(mac));
                for (var a : nif.getInterfaceAddresses()) {
                    out.println("    " + a.getAddress().getHostAddress()
                                + "/" + a.getNetworkPrefixLength());
                }
            }
        } catch (Exception e) {
            out.println("  (could not enumerate interfaces: " + e.getMessage() + ")");
        }
    }

    private static void status(HostScanner scanner, PrintStream out) {
        out.println("\nsession : " + scanner.mode() + " - " + scanner.diagnostic());
        scanner.pinger().ifPresent(p -> out.println("pinger  : " + p.getClass().getSimpleName()
                                                    + "  " + HostScanFormat.capabilities(p.capabilities())));
    }

    /**
     * Pings every target concurrently. Names are looked up first so the off-link
     * warning and any DNS failure are reported before probes go out.
     */
    private static int ping(HostScanner scanner, Args args, PrintStream out) throws Exception {
        args.requireTargets("an IP address or hostname");
        int failures = 0;
        List<InetAddress> addresses = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (String target : args.targets()) {
            try {
                InetAddress ip = await(scanner.lookup(target), LOOKUP_TIMEOUT);
                if (!ip.getHostAddress().equals(target)) {
                    out.println(target + " resolved to " + ip.getHostAddress());
                }
                warnIfOffLinkUnsupported(scanner, ip, out);
                addresses.add(ip);
                names.add(target);
            } catch (Exception e) {
                out.println("FAILED " + target + ": " + rootMessage(e));
                failures++;
            }
        }
        List<CompletableFuture<PingResult>> pending = new ArrayList<>(addresses.size());
        for (InetAddress ip : addresses) {
            pending.add(scanner.ping(ip, args.count(), args.timeout()));
        }
        Duration budget = args.timeout().multipliedBy(args.count()).plus(AWAIT_SLACK);
        for (int i = 0; i < pending.size(); i++) {
            try {
                out.println(HostScanFormat.ping(await(pending.get(i), budget)));
            } catch (Exception e) {
                out.println("FAILED " + names.get(i) + ": " + rootMessage(e));
                failures++;
            }
            out.println();
        }
        return failures == 0 ? 0 : 1;
    }

    /** Resolves every target concurrently — they are independent ARP/NDP exchanges. */
    private static int resolve(HostScanner scanner, Args args, PrintStream out) throws Exception {
        args.requireTargets("an IP address or hostname");
        int failures = 0;
        List<String> names = new ArrayList<>();
        List<CompletableFuture<ResolveResult>> pending = new ArrayList<>();
        for (String target : args.targets()) {
            names.add(target);
            pending.add(scanner.resolve(target, args.timeout()));
        }
        out.printf("%-39s %-19s %-14s %s%n", "TARGET", "MAC", "OUTCOME", "DETAIL");
        Duration budget = args.timeout().plus(AWAIT_SLACK);
        for (int i = 0; i < pending.size(); i++) {
            try {
                out.println(HostScanFormat.resolve(await(pending.get(i), budget)));
            } catch (Exception e) {
                out.println("FAILED " + names.get(i) + ": " + rootMessage(e));
                failures++;
            }
        }
        return failures == 0 ? 0 : 1;
    }

    /**
     * Sweeps each range in turn. Sequential on purpose: the packet-rate cap bounds
     * one sweep, so running ranges together would multiply the load on the segment.
     */
    private static int sweep(HostScanner scanner, Args args, PrintStream out) throws Exception {
        args.requireTargets("a CIDR range");
        SweepOptions options = args.sweepOptions();
        int failures = 0;
        for (String cidr : args.targets()) {
            try {
                CidrRange range = CidrRange.parse(cidr);
                String via = args.iface() != null ? args.iface() : chosenInterface(scanner, range);
                out.println("sweeping " + range + " via " + via);
                AtomicInteger seen = new AtomicInteger();
                CompletableFuture<SweepSummary> future = args.iface() != null
                        ? scanner.sweepVia(args.iface(), range, options, h -> printHost(h, seen, out))
                        : scanner.sweep(range, options, h -> printHost(h, seen, out));
                out.println("\n" + HostScanFormat.sweep(await(future, SWEEP_BUDGET)) + "\n");
            } catch (Exception e) {
                out.println("FAILED " + cidr + ": " + rootMessage(e));
                failures++;
            }
        }
        return failures == 0 ? 0 : 1;
    }

    /** IPv6 neighbours on one segment — CIDR expansion is meaningless for a /64. */
    private static int segment(HostScanner scanner, Args args, PrintStream out) throws Exception {
        String iface = args.iface() != null ? args.iface()
                : args.targets().isEmpty() ? null : args.targets().get(0);
        if (iface == null) {
            out.println("Expected an interface name, e.g. 'segment eth0'. Bound: "
                        + scanner.bindings().stream().map(NicBinding::javaName).toList());
            return 2;
        }
        AtomicInteger seen = new AtomicInteger();
        out.println("discovering IPv6 neighbours on " + iface);
        SweepSummary s = await(scanner.discoverIpv6Segment(iface, args.sweepOptions(),
                                                           h -> printHost(h, seen, out)),
                               SWEEP_BUDGET);
        out.println("\n" + HostScanFormat.sweep(s));
        return 0;
    }

    /** Passive neighbours for a while — nothing is transmitted. */
    private static void observe(HostScanner scanner, String[] argv, PrintStream out)
            throws InterruptedException {
        int seconds = argv.length > 1 ? Integer.parseInt(argv[1]) : 30;
        boolean supported = scanner.interfaces().stream()
                                   .anyMatch(h -> h.capabilities().passiveObservation());
        if (!supported) {
            out.println("No bound interface supports passive observation; "
                        + "this will register and never fire.");
        }
        out.println("observing for " + seconds + "s (broadcast ARP, gratuitous ARP, NS/NA)");
        AtomicInteger seen = new AtomicInteger();
        try (Subscription sub = scanner.observe(n -> printNeighbor(n, seen, out))) {
            TimeUnit.SECONDS.sleep(seconds);
        }
        out.println("\n" + seen.get() + " observation(s)");
    }

    // -------------------------------------------------------------- plumbing

    /**
     * Explains an unreachable off-link target BEFORE sending probes that cannot
     * arrive, rather than leaving the user with a bare {@code NETWORK_UNREACHABLE}.
     * <p>
     * pcap injects at layer 2 and bypasses OS routing, so an off-link destination
     * needs the gateway's MAC. Windows now gets that from {@code GetBestRoute2}, so
     * this fires only when that binding will not load; Linux and macOS send through
     * the kernel and route normally.
     */
    private static void warnIfOffLinkUnsupported(HostScanner scanner, InetAddress ip,
                                                 PrintStream out) {
        DiscoveryCapabilities caps = scanner.capabilities().orElse(null);
        if (caps == null || caps.offLinkIcmp()) {
            return;
        }
        if (scanner.interfaceFor(ip).isPresent()) {
            return;
        }
        out.println("""
                NOTE: %s is not on any local subnet, and this backend (%s) cannot
                      reach off-link targets - it injects at layer 2 and bypasses
                      routing, so it would need the gateway's MAC to get there.
                      Expect NETWORK_UNREACHABLE. Only on-link addresses work here;
                      Linux and macOS route through the kernel and do not have this
                      limit.""".formatted(ip.getHostAddress(), caps.backend()));
    }

    /** Which interface {@link HostScanner#sweep} will pick, so the CLI can name it up front. */
    private static String chosenInterface(HostScanner scanner, CidrRange range) {
        return scanner.interfaceFor(range.networkAddress())
                      .or(() -> scanner.interfaces().stream().findFirst())
                      .map(h -> h.binding().javaName())
                      .orElse("(none)");
    }

    private static synchronized void printHost(HostRecord h, AtomicInteger seen, PrintStream out) {
        seen.incrementAndGet();
        out.println(HostScanFormat.host(h));
    }

    private static synchronized void printNeighbor(ObservedNeighbor n, AtomicInteger seen,
                                                   PrintStream out) {
        seen.incrementAndGet();
        out.println(HostScanFormat.neighbor(n));
    }

    /** Waits on a future and unwraps the completion cause into something readable. */
    private static <T> T await(CompletableFuture<T> future, Duration budget) throws Exception {
        try {
            return future.get(budget.toMillis(), TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw e;
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null && cause.getMessage() == null) {
            cause = cause.getCause();
        }
        return cause.getMessage() == null ? cause.toString() : cause.getMessage();
    }

    private static void printFailure(Exception e, PrintStream out) {
        out.println("FAILED: " + rootMessage(e));
        if (e.getCause() != null) {
            out.println("  cause: " + e.getCause());
        }
    }

    private static boolean isHelp(String arg) {
        String a = arg.toLowerCase(Locale.ROOT);
        return a.equals("help") || a.equals("-h") || a.equals("--help");
    }

    /**
     * Splits a shell line. Strips a leading byte-order mark: piping a command file
     * into the shell on Windows routinely prepends one, and it would otherwise turn
     * {@code status} into an unknown command whose name looks identical to the real
     * one.
     */
    static String[] tokenize(String line) {
        String trimmed = line.trim();
        if (!trimmed.isEmpty() && trimmed.charAt(0) == 0xFEFF) {
            trimmed = trimmed.substring(1).trim();
        }
        return trimmed.isEmpty() ? new String[0] : trimmed.split("\\s+");
    }

    /**
     * Shuts down zoxweb's process-wide pools so the JVM can exit — their threads are
     * not daemons. Legitimate ONLY because this class is the whole application; a
     * library must never do it.
     */
    private static void shutdownSharedPools() {
        try {
            org.zoxweb.server.task.TaskUtil.close();
        } catch (RuntimeException ignored) {
            // exiting anyway
        }
    }

    private static void usage(PrintStream out) {
        out.println("""
                no-sneak host discovery

                  hostscan                        interactive shell (one session, many commands)
                  hostscan list                   interfaces, devices, capabilities
                  hostscan status                 backend mode and why it is what it is
                  hostscan resolve <ip> [ip...]   ARP/NDP lookup, targets run concurrently
                  hostscan ping    <ip> [ip...]   ICMP echo, pipelined, targets concurrent
                  hostscan sweep   <cidr> [...]   ARP + ICMP across a range, ranges in turn
                  hostscan segment <iface>        IPv6 neighbours on one segment
                  hostscan observe [seconds]      passive neighbours, transmits nothing
                  hostscan reopen                 rebuild the session after a NIC change

                Options
                  -c, --count N       probes per host (ping), or per host in a sweep
                  -w, --timeout MS    per-probe timeout in milliseconds
                  -i, --iface NAME    force the interface for sweep/segment
                  A bare trailing number still means the ping count: 'ping 10.0.0.1 4'.

                Windows needs Npcap installed (https://npcap.com/).
                Linux needs root for layer 2; ICMP alone does not.""");
    }

    /**
     * One command's arguments: the targets plus the shared options.
     * <p>
     * Package-private and parsed in one place so the shell and the one-shot path
     * cannot drift apart, and so the parsing is testable without a network.
     */
    record Args(List<String> targets, int count, Duration timeout, String iface) {

        /**
         * @param trailingCount accept a bare trailing integer as the count, which is
         *                      what {@code ping 10.0.0.1 4} has always meant. Off for
         *                      sweep, where a bare integer is simply not a CIDR and
         *                      swallowing it would hide the mistake.
         */
        static Args parse(String[] argv, int defaultCount, Duration defaultTimeout,
                          boolean trailingCount) {
            List<String> targets = new ArrayList<>();
            int count = defaultCount;
            Duration timeout = defaultTimeout;
            String iface = null;
            boolean explicitCount = false;
            for (int i = 1; i < argv.length; i++) {
                String arg = argv[i];
                switch (arg) {
                    case "-c", "--count" -> {
                        count = Integer.parseInt(need(argv, ++i, arg));
                        explicitCount = true;
                    }
                    case "-w", "--timeout" ->
                            timeout = Duration.ofMillis(Long.parseLong(need(argv, ++i, arg)));
                    case "-i", "--iface" -> iface = need(argv, ++i, arg);
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("Unknown option: " + arg);
                        }
                        targets.add(arg);
                    }
                }
            }
            if (trailingCount && !explicitCount && targets.size() > 1
                && targets.get(targets.size() - 1).matches("\\d+")) {
                count = Integer.parseInt(targets.remove(targets.size() - 1));
            }
            if (count < 1) {
                throw new IllegalArgumentException("count must be >= 1, got " + count);
            }
            if (timeout.isZero() || timeout.isNegative()) {
                throw new IllegalArgumentException("timeout must be positive, got " + timeout);
            }
            return new Args(List.copyOf(targets), count, timeout, iface);
        }

        private static String need(String[] argv, int index, String option) {
            if (index >= argv.length) {
                throw new IllegalArgumentException(option + " needs a value");
            }
            return argv[index];
        }

        void requireTargets(String what) {
            if (targets.isEmpty()) {
                throw new IllegalArgumentException("Expected " + what);
            }
        }

        /** Sweep tuning with the command's count and timeout folded in. */
        SweepOptions sweepOptions() {
            SweepOptions d = SweepOptions.defaults();
            return new SweepOptions(d.maxInFlight(), d.maxPacketsPerSecond(), timeout,
                                    d.doIcmp(), d.doMac(), count, d.maxHosts());
        }
    }
}
