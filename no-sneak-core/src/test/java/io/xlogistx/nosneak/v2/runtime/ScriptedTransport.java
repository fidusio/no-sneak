package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;

/**
 * A {@link ProbeTransport} that never touches a socket. It records every connection a context
 * opens and every byte it writes, and lets a test push the peer's side of the conversation —
 * connected, bytes, close, error — straight into the context's ingress. TLS starts are recorded
 * and return an empty session, so a handshake state can only end by timeout or cancel.
 */
public final class ScriptedTransport implements ProbeTransport {

    /** One opened connection, as the context sees it. */
    public static final class Conn {
        public final TCPSessionCallback cb;
        public final int timeoutSec;
        public final List<byte[]> written = new ArrayList<>();

        Conn(TCPSessionCallback cb, int timeoutSec) {
            this.cb = cb;
            this.timeoutSec = timeoutSec;
        }

        public ProbeContext context() {
            return ((ProbeTCPCallback) cb).context();
        }

        public String probeName() {
            return context().probeName();
        }

        public int port() {
            return context().currentPort();
        }

        public String writtenText() {
            StringBuilder sb = new StringBuilder();
            for (byte[] b : written) {
                sb.append(new String(b, StandardCharsets.ISO_8859_1));
            }
            return sb.toString();
        }
    }

    public static final class TlsStart {
        public final ProbeTCPCallback cb;
        public final InetSocketAddress sni;
        public final boolean classicalOnly;

        TlsStart(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly) {
            this.cb = cb;
            this.sni = sni;
            this.classicalOnly = classicalOnly;
        }
    }

    public final List<Conn> connections = new ArrayList<>();
    public final List<TCPSessionCallback> analysisOpens = new ArrayList<>();
    public final List<UDPSessionCallback> datagrams = new ArrayList<>();
    public final List<TlsStart> tlsStarts = new ArrayList<>();
    public final List<ProbeResult> delivered = new ArrayList<>();
    /** When set, every {@code open} throws it — a launch failure. */
    public RuntimeException failOpen;
    /** When true, every write throws — a dead channel. */
    public boolean failWrite;

    // ---- ProbeTransport ----

    @Override
    public SelectionKey open(TCPSessionCallback cb, int timeoutSec) {
        if (failOpen != null) {
            throw failOpen;
        }
        connections.add(new Conn(cb, timeoutSec));
        return null;
    }

    @Override
    public SelectionKey open(TCPSessionCallback cb) {
        analysisOpens.add(cb);
        return null;
    }

    @Override
    public SelectionKey openDatagram(UDPSessionCallback cb) {
        datagrams.add(cb);
        return null;
    }

    @Override
    public void write(ProbeTCPCallback cb, byte[] data) throws IOException {
        if (failWrite) {
            throw new IOException("scripted write failure");
        }
        for (Conn c : connections) {
            if (c.cb == cb) {
                c.written.add(data);
                return;
            }
        }
        throw new IOException("write on a connection this transport never opened");
    }

    @Override
    public TlsSession startTls(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                               Consumer<PQCSessionConfig> onTransition) {
        tlsStarts.add(new TlsStart(cb, sni, classicalOnly));
        return new TlsSession(null, null);
    }

    @Override
    public void abort(SelectionKey key) {
        // keys are never issued by this transport
    }

    // ---- building contexts ----

    /** A context on this transport that records what it delivers into {@link #delivered}. */
    public ProbeContext newContext(ScheduledExecutorService scheduler, IPAddress target,
                                   ProbeDefinition definition, int timeoutSec) {
        return newContext(scheduler, target, definition, timeoutSec, delivered::add);
    }

    public ProbeContext newContext(ScheduledExecutorService scheduler, IPAddress target,
                                   ProbeDefinition definition, int timeoutSec,
                                   Consumer<ProbeResult> callback) {
        Executor inline = Runnable::run;
        return new ProbeContext(this, scheduler, inline, target, definition, timeoutSec, callback);
    }

    public Conn last() {
        return connections.get(connections.size() - 1);
    }

    public Conn connFor(String probeName) {
        for (Conn c : connections) {
            if (probeName.equals(c.probeName())) {
                return c;
            }
        }
        throw new IllegalStateException("no connection for probe " + probeName);
    }

    // ---- the peer's side of the conversation ----

    public static void connected(Conn c) {
        ProbeTCPCallback cb = (ProbeTCPCallback) c.cb;
        cb.context().onConnected(cb);
    }

    public static void inbound(Conn c, String text) {
        inbound(c, text.getBytes(StandardCharsets.ISO_8859_1));
    }

    public static void inbound(Conn c, byte[] bytes) {
        ProbeTCPCallback cb = (ProbeTCPCallback) c.cb;
        cb.context().onInbound(cb, bytes);
    }

    /** What {@link ProbeTCPCallback} reports when {@code read()} returns -1. */
    public static void peerClosed(Conn c) {
        ProbeTCPCallback cb = (ProbeTCPCallback) c.cb;
        cb.context().onException(cb, new IOException("Connection closed by peer"));
    }

    public static void error(Conn c, Throwable t) {
        ProbeTCPCallback cb = (ProbeTCPCallback) c.cb;
        cb.context().onException(cb, t);
    }
}
