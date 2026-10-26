package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.nmap.NMapConfig;
import io.xlogistx.nosneak.nmap.NMapScanner;
import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.result.ProbeResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.task.TaskProcessor;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.task.CallableConsumerTask;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code tls-upgrade} path end to end (2026-10-26), through the bundled {@code postgres-tls}
 * against a loopback server that speaks PostgreSQL's TLS negotiation: it reads the 8-byte
 * SSLRequest, answers {@code S}, runs a server-side JSSE handshake on the same socket, reads the
 * StartupMessage over TLS and answers a {@code ParameterStatus} carrying {@code server_version}.
 * The probe must come back complete, with the version captured and the TLS state recorded as an
 * upgrade. Nothing leaves the loopback interface.
 */
public class TlsUpgradeEndToEndTest {

    static {
        try {
            Class.forName(SecUtil.class.getName()); // the application's provider registration
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final byte[] SSL_REQUEST = {0, 0, 0, 8, 0x04, (byte) 0xd2, 0x16, 0x2f};
    private static final String VERSION = "16.3 (loopback)";

    private ServerSocket listener;
    private int port;
    private Thread acceptor;
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();
    private volatile String serverSaw = "";
    private TaskProcessor executor;
    private TaskSchedulerProcessor scheduler;
    private NIOSocket nio;

    @BeforeEach
    public void listen() throws Exception {
        ScriptedTls.Ca ca = ScriptedTls.ca("tls-upgrade loopback");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", ca.key.getPrivate(), new char[0], new Certificate[]{ca.cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext server = SSLContext.getInstance("TLS");
        server.init(kmf.getKeyManagers(), null, null);

        listener = new ServerSocket();
        listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        port = listener.getLocalPort();
        acceptor = new Thread(() -> {
            try {
                while (!listener.isClosed()) {
                    Socket plain = listener.accept();
                    accepted.add(plain);
                    new Thread(() -> serve(plain, server), "pg-session").start();
                }
            } catch (Exception ignored) {
                // closed by tearDown
            }
        }, "pg-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        executor = new TaskProcessor("tls-upgrade", 64, 4, Thread.NORM_PRIORITY, false);
        scheduler = new TaskSchedulerProcessor(executor);
        nio = new NIOSocket(executor, scheduler);
    }

    /** One PostgreSQL-style session: SSLRequest, S, TLS, StartupMessage, ParameterStatus. */
    private void serve(Socket plain, SSLContext server) {
        try {
            InputStream in = plain.getInputStream();
            byte[] req = in.readNBytes(8);
            if (!java.util.Arrays.equals(req, SSL_REQUEST)) {
                serverSaw = "not an SSLRequest: " + java.util.Arrays.toString(req);
                plain.close();
                return;
            }
            serverSaw = "SSLRequest";
            OutputStream out = plain.getOutputStream();
            out.write('S');
            out.flush();
            SSLSocket tls = (SSLSocket) server.getSocketFactory()
                    .createSocket(plain, plain.getInetAddress().getHostAddress(), plain.getPort(), true);
            tls.setUseClientMode(false);
            tls.startHandshake();
            serverSaw = "handshake " + tls.getSession().getProtocol();
            InputStream tin = tls.getInputStream();
            byte[] len = tin.readNBytes(4);
            int n = ((len[0] & 0xff) << 24) | ((len[1] & 0xff) << 16) | ((len[2] & 0xff) << 8) | (len[3] & 0xff);
            byte[] startup = tin.readNBytes(n - 4);
            String user = new String(startup, StandardCharsets.ISO_8859_1);
            serverSaw = "startup over tls: " + user.replace('\0', '|');
            ByteArrayOutputStream ps = new ByteArrayOutputStream();
            byte[] body = ("server_version\0" + VERSION + "\0").getBytes(StandardCharsets.ISO_8859_1);
            int plen = 4 + body.length;
            ps.write('S');
            ps.write((plen >>> 24) & 0xff);
            ps.write((plen >>> 16) & 0xff);
            ps.write((plen >>> 8) & 0xff);
            ps.write(plen & 0xff);
            ps.write(body);
            tls.getOutputStream().write(ps.toByteArray());
            tls.getOutputStream().flush();
            // stay open: the probe completes on the version
            Thread.sleep(3000);
            tls.close();
        } catch (Exception e) {
            serverSaw = serverSaw + " then " + e;
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        try { nio.close(); } catch (Exception ignored) { }
        try { scheduler.close(); } catch (Exception ignored) { }
        try { executor.close(); } catch (Exception ignored) { }
        try { listener.close(); } catch (Exception ignored) { }
        for (Socket s : accepted) {
            try { s.close(); } catch (Exception ignored) { }
        }
        acceptor.interrupt();
    }

    @Test
    public void postgresTlsUpgradesInPlaceAndReadsTheVersionOverTls() throws Exception {
        NMapConfig cfg = new NMapConfig()
                .target("127.0.0.1")
                .discovery(false)
                .reverseDns(NMapConfig.ReverseDns.NEVER)
                .ports(new int[]{port})
                .probeScan(true)
                .probe("postgres-tls")
                .timeoutInSec(5);

        CompletableFuture<ScanReport> done = new CompletableFuture<>();
        NMapScanner.scan(nio, cfg, new CallableConsumerTask<ScanReport>().setConsumer(done::complete));
        ScanReport report = done.get(20, TimeUnit.SECONDS);
        assertFalse(report.cancelled);
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());

        ScanReport.PortReport open = report.hosts.getFirst().ports.stream()
                .filter(p -> p.port == port).findFirst().orElseThrow();
        ProbeResult probe = open.probe;
        assertNotNull(probe, "the port was open and probed; server saw: " + serverSaw);
        assertTrue(probe.isComplete(), "postgres-tls must complete; server saw: " + serverSaw + "; probe: " + probe);
        assertEquals("postgresql", probe.getService());
        assertEquals(VERSION, probe.getServiceVersion(), "the version captured over TLS; server saw: " + serverSaw);
        assertEquals(ProbeResult.TlsState.STARTTLS_UPGRADED, probe.getTlsState(), "an in-place upgrade, not a direct session");
        assertNotNull(probe.getTlsVersion(), "the negotiated protocol is recorded");
        assertNotNull(probe.getCipherSuite(), "the negotiated suite is recorded");
        assertTrue(serverSaw.startsWith("startup over tls"), "the StartupMessage must have travelled inside TLS: " + serverSaw);
    }
}
