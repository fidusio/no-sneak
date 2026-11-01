package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskProcessor;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The whole {@link NMapScanner#scan} pipeline against a loopback listener: one port that
 * accepts and volunteers a banner, one that refuses. This is the one nmap test that owns real
 * pools and a real {@link NIOSocket}; they are built per test and torn down after it. Discovery
 * is skipped ({@code -Pn}) and reverse DNS is off ({@code -n}) so no packet leaves the loopback
 * interface, and no probe stage runs, so nothing here depends on the probe catalog.
 */
public class NMapScannerEndToEndTest {

    private static final String BANNER = "SSH-2.0-test\r\n";

    private ServerSocketChannel listener;
    private int openPort;
    private int closedPort;
    private Thread acceptor;
    private final List<SocketChannel> accepted = new CopyOnWriteArrayList<>();
    private TaskProcessor executor;
    private TaskSchedulerProcessor scheduler;
    private NIOSocket nio;

    @BeforeEach
    public void listen() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        listener = ServerSocketChannel.open();
        listener.bind(new InetSocketAddress(loopback, 0));
        openPort = ((InetSocketAddress) listener.getLocalAddress()).getPort();
        // A port that was just bound and released refuses connections: the kernel hands it
        // out once and nothing else is listening on it for the milliseconds this test lasts.
        try (ServerSocketChannel probe = ServerSocketChannel.open()) {
            probe.bind(new InetSocketAddress(loopback, 0));
            closedPort = ((InetSocketAddress) probe.getLocalAddress()).getPort();
        }
        acceptor = new Thread(() -> {
            try {
                while (listener.isOpen()) {
                    SocketChannel c = listener.accept();
                    accepted.add(c);
                    c.write(ByteBuffer.wrap(BANNER.getBytes(StandardCharsets.ISO_8859_1)));
                    // Stay open: the probe completes on the banner, and a close racing the
                    // read would only ever make the port look open-without-banner.
                }
            } catch (Exception ignored) {
                // the listener was closed by tearDown
            }
        }, "e2e-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        // The one place in the nmap tests that builds pools: small, private, closed below.
        executor = new TaskProcessor("e2e", 64, 4, Thread.NORM_PRIORITY, false);
        scheduler = new TaskSchedulerProcessor(executor);
        nio = new NIOSocket(executor, scheduler);
    }

    @AfterEach
    public void tearDown() throws Exception {
        try { nio.close(); } catch (Exception ignored) { }
        try { scheduler.close(); } catch (Exception ignored) { }
        try { executor.close(); } catch (Exception ignored) { }
        try { listener.close(); } catch (Exception ignored) { }
        for (SocketChannel c : accepted) {
            try { c.close(); } catch (Exception ignored) { }
        }
        acceptor.interrupt();
    }

    @Test
    public void scansALoopbackListenerAndRendersEveryFormat() throws Exception {
        NMapConfig cfg = new NMapConfig()
                .target("127.0.0.1")
                .discovery(false)                                  // -Pn
                .reverseDns(NMapConfig.ReverseDns.NEVER)           // -n: no resolver traffic
                .ports(new int[]{openPort, closedPort})
                .timeoutInSec(3);

        CompletableFuture<ScanReport> done = new CompletableFuture<>();
        NMapScanner.ScanHandle handle = NMapScanner.scan(nio, cfg,
                new CallableConsumerTask<ScanReport>().setConsumer(done::complete));
        ScanReport report = done.get(5, TimeUnit.SECONDS);       // test wrapper: allowed to block
        assertTrue(handle.completion().isDone());
        assertFalse(report.cancelled);
        assertTrue(report.warnings.isEmpty(), "no warnings on a clean loopback scan: " + report.warnings);
        assertTrue(report.endTimeMs >= report.startTimeMs);

        assertEquals(1, report.hosts.size());
        HostReport h = report.hosts.getFirst();
        assertTrue(h.up);
        assertEquals("skipped", h.reason);
        assertEquals("127.0.0.1", h.ip, "a literal target carries its ip from expansion");
        assertNull(h.hostname, "-n: the reverse lookup never ran");
        assertTrue(h.startTimeMs > 0 && h.endTimeMs >= h.startTimeMs, "per-host times are set");
        assertEquals(2, h.ports.size());

        PortReport open = h.ports.stream().filter(p -> p.port == openPort).findFirst().orElseThrow();
        assertEquals(PortState.OPEN, open.state);
        assertEquals("connected", open.reason);
        assertEquals("SSH-2.0-test", open.banner, "the volunteered banner, CR/LF trimmed");
        assertTrue(open.rttMs >= 0, "a completed connect has an RTT");

        PortReport closed = h.ports.stream().filter(p -> p.port == closedPort).findFirst().orElseThrow();
        assertEquals(PortState.CLOSED, closed.state);
        assertEquals("conn-refused", closed.reason);
        assertNull(closed.banner);

        assertEquals(1, h.openPorts().size());
        assertEquals(1, h.countState(PortState.CLOSED));

        report.commandLine = "e2e -Pn -n -p " + openPort + "," + closedPort + " 127.0.0.1";
        for (OutputFormat f : OutputFormat.values()) {
            String out = OutputFormat.formatter(f).render(report);
            assertNotNull(out, f.name());
            assertTrue(out.contains(String.valueOf(openPort)), f + " must name the open port:\n" + out);
        }
        String xml = OutputFormat.formatter(OutputFormat.XML).render(report);
        assertTrue(xml.contains("<port protocol=\"tcp\" portid=\"" + openPort + "\""), xml);
        assertTrue(xml.contains("<hosts up=\"1\" down=\"0\" total=\"1\"/>"), xml);
        String normal = OutputFormat.formatter(OutputFormat.NORMAL).render(report);
        assertTrue(normal.contains(openPort + "/tcp") && normal.contains("SSH-2.0-test"), normal);
        assertTrue(normal.contains(closedPort + "/tcp") && normal.contains("conn-refused"), normal);
        org.zoxweb.shared.util.NVGenericMap json = org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(
                OutputFormat.formatter(OutputFormat.JSON).render(report).getBytes(StandardCharsets.UTF_8));
        Object up = json.getValue("up"); // through Object: getValue is generic and String.valueOf has a char[] overload
        assertEquals("1", up.toString());
    }

    /**
     * {@code -sV --probes ssh}: the open port is identified by the probe launched <em>from its
     * connect callback</em>. The probe stage proper now handles UDP only, so a non-null
     * {@code probe} on a TCP port is proof the streamed path ran and the host barrier waited
     * for it; the closed port is never probed.
     */
    @Test
    public void anOpenPortIsProbedAsItConnectsNotAfterTheStage() throws Exception {
        NMapConfig cfg = new NMapConfig()
                .target("127.0.0.1")
                .discovery(false)
                .reverseDns(NMapConfig.ReverseDns.NEVER)
                .ports(new int[]{openPort, closedPort})
                .probeScan(true)
                .probe("ssh")
                .timeoutInSec(3);

        CompletableFuture<ScanReport> done = new CompletableFuture<>();
        NMapScanner.scan(nio, cfg, new CallableConsumerTask<ScanReport>().setConsumer(done::complete));
        ScanReport report = done.get(10, TimeUnit.SECONDS);
        assertFalse(report.cancelled);
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());

        HostReport h = report.hosts.getFirst();
        PortReport open = h.ports.stream().filter(p -> p.port == openPort).findFirst().orElseThrow();
        assertEquals(PortState.OPEN, open.state);
        assertNotNull(open.probe, "the streamed probe must have delivered before the report");
        assertTrue(open.probe.isComplete(), "ssh probe: " + open.probe);
        assertEquals("ssh", open.probe.getService());
        assertEquals("ssh", open.serviceName());

        PortReport closed = h.ports.stream().filter(p -> p.port == closedPort).findFirst().orElseThrow();
        assertEquals(PortState.CLOSED, closed.state);
        assertNull(closed.probe, "a closed port is not probeable");
        assertTrue(accepted.size() >= 2, "the connect and the probe each opened a connection: " + accepted.size());
    }

    /** A connect-then-done probe declared on one port, under a name and a priority. */
    private static ProbeDefinition declaredOn(String name, int priority, int port) {
        return ProbeDefinitionLoader.parse("""
                {
                  "name": "%s",
                  "service": "custom-%s",
                  "transport": "tcp",
                  "ports": [%d],
                  "priority": %d,
                  "start": "hello",
                  "states": {
                    "hello":  { "action": "connect", "on": { "connected": "finish", "error": "stop" } },
                    "finish": { "action": "done" },
                    "stop":   { "action": "fail" }
                  }
                }
                """.formatted(name, name, port, priority), name);
    }

    private ScanReport scanProbesOnly(NMapConfig.ProbeMatch match) throws Exception {
        // no -p: the two named probes decide the ports, and they both declare the open one
        NMapConfig cfg = new NMapConfig()
                .target("127.0.0.1")
                .discovery(false)
                .reverseDns(NMapConfig.ReverseDns.NEVER)
                .probeScan(true)
                .extraProbe(declaredOn("alpha", 90, openPort)).probe("alpha")
                .extraProbe(declaredOn("beta", 80, openPort)).probe("beta")
                .probeMatch(match)
                .timeoutInSec(3);
        CompletableFuture<ScanReport> done = new CompletableFuture<>();
        NMapScanner.scan(nio, cfg, new CallableConsumerTask<ScanReport>().setConsumer(done::complete));
        ScanReport report = done.get(10, TimeUnit.SECONDS);
        assertFalse(report.cancelled);
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());
        return report;
    }

    /**
     * 2026-10-31: probes named and no ports typed — the scan covers the ports the probes declare
     * and nothing else ({@code tcpPortsScanned}, one port report per host); match-first keeps
     * the higher-priority identification alone.
     */
    @Test
    public void namedProbesWithoutPortsScanTheirDeclaredPortsAndTheFirstWins() throws Exception {
        ScanReport report = scanProbesOnly(NMapConfig.ProbeMatch.FIRST);
        assertEquals(List.of(openPort), List.of(report.tcpPortsScanned[0]));
        assertEquals(1, report.tcpPortsScanned.length, "only the declared port");
        HostReport h = report.hosts.getFirst();
        assertEquals(1, h.ports.size(), "one port scanned: " + h.ports);
        PortReport open = h.ports.getFirst();
        assertEquals(openPort, open.port);
        assertEquals(PortState.OPEN, open.state);
        assertNotNull(open.probe);
        assertEquals("alpha", open.probe.getProbeName(), "the higher priority wins");
        assertNull(open.probes, "match-first keeps one identification");
    }

    /** {@code --probe-match all}: every probe that identifies the port is kept, priority order, the first also as the port's probe. */
    @Test
    public void probeMatchAllKeepsEveryIdentification() throws Exception {
        ScanReport report = scanProbesOnly(NMapConfig.ProbeMatch.ALL);
        PortReport open = report.hosts.getFirst().ports.getFirst();
        assertEquals(PortState.OPEN, open.state);
        assertNotNull(open.probes, "match-all records the list");
        assertEquals(2, open.probes.size(), open.probes.toString());
        assertEquals("alpha", open.probes.get(0).getProbeName());
        assertEquals("beta", open.probes.get(1).getProbeName());
        assertEquals("alpha", open.probe.getProbeName(), "the first of them is the port's probe");
        // and the JSON carries both under "probes"
        String json = OutputFormat.formatter(OutputFormat.JSON).render(report);
        assertTrue(json.contains("\"probes\""), json);
        assertTrue(json.contains("custom-beta"), json);
    }
}
