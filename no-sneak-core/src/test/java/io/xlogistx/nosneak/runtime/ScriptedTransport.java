package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.result.ProbeResult;
import io.xlogistx.nosneak.tls.PQCSessionConfig;
import org.zoxweb.server.http.HTTPNIOSocket;
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
        /** The context's transition hook — what a scripted handshake completes through. */
        public final Consumer<PQCSessionConfig> onTransition;

        TlsStart(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                 Consumer<PQCSessionConfig> onTransition) {
            this.cb = cb;
            this.sni = sni;
            this.classicalOnly = classicalOnly;
            this.onTransition = onTransition;
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
    /**
     * When set, {@code startTls} hands this session to the context as the live handshake, so a
     * test scripts what the "server" negotiated (see {@code ScriptedTls}) and completes it with
     * {@link #handshaked}. Null (the default) keeps the empty session: a handshake state then
     * ends only by timeout or cancel.
     */
    public PQCSessionConfig scriptedTls;

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
        tlsStarts.add(new TlsStart(cb, sni, classicalOnly, onTransition));
        return new TlsSession(scriptedTls, null);
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

    /** A context with an HTTP client for {@code revocation-check} supplied (a capturing fake in tests). */
    public ProbeContext newContext(ScheduledExecutorService scheduler, HTTPNIOSocket http, IPAddress target,
                                   ProbeDefinition definition, int timeoutSec) {
        Executor inline = Runnable::run;
        return new ProbeContext(this, scheduler, inline, http, target, definition, timeoutSec, delivered::add);
    }

    /** The scripted handshake completed: the "server" side of a {@code tls-handshake} state. */
    public static void handshaked(TlsStart start, PQCSessionConfig session) {
        session.handshakeComplete.set(true);
        start.onTransition.accept(session);
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
