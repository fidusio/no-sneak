package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.result.ProbeResult;
import io.xlogistx.nosneak.tls.PQCSessionConfig;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.common.ConnectionCallback;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Pacing for the probe engine, so a {@code -sV} scan's sockets count against the same in-flight
 * cap as the port scan (PENDING-ISSUES P4). Two things are counted, in two different ways:
 * <ul>
 *   <li><b>A candidate probe</b> holds one slot from the moment its {@code start()} is admitted
 *       until it delivers or is cancelled — see {@link Registry#start}. Its own connection (and a
 *       {@code reconnect}, which replaces it) rides that slot; the transport passes those opens
 *       straight through. A candidate the gate cannot admit yet is simply <em>not started</em>:
 *       none of its timers run, so it cannot time out while waiting, and it still elects normally
 *       once it does start.</li>
 *   <li><b>An enumeration child</b> (a version or cipher handshake a deep TLS probe opens for
 *       itself) is admitted at once through {@link ConnectionGate#submitNow} and counted until it
 *       is aborted or its parent finishes — a probe never waits on itself, and while its children
 *       are counted no new candidate is admitted.</li>
 * </ul>
 * Nothing blocks: the gate runs a launch inline or keeps it; a start cancelled before it ran
 * releases its slot the moment the gate reaches it.
 */
public final class GatedProbeTransport implements ProbeTransport {

    /** One child socket the context asked for. */
    static final class Slot {
        private final AtomicBoolean released = new AtomicBoolean();
        volatile SelectionKey key;
    }

    private final ProbeTransport delegate;
    private final ConnectionGate gate;
    private final List<Slot> children = new CopyOnWriteArrayList<>();
    private final Map<SelectionKey, Slot> byKey = new ConcurrentHashMap<>();
    private volatile boolean finished;

    public GatedProbeTransport(ProbeTransport delegate, ConnectionGate gate) {
        this.delegate = delegate;
        this.gate = gate == null ? ConnectionGate.UNLIMITED : gate;
    }

    /** Child sockets counted and not yet handed back — for tests. */
    public int outstanding() {
        int n = 0;
        for (Slot s : children) {
            if (!s.released.get()) {
                n++;
            }
        }
        return n;
    }

    // ---- ProbeTransport ----

    /** The candidate's own connection: covered by the slot its start was admitted on. */
    @Override
    public SelectionKey open(TCPSessionCallback cb, int timeoutSec) throws Exception {
        return delegate.open(cb, timeoutSec);
    }

    /** An enumeration child: admitted now, counted until aborted or the parent finishes. */
    @Override
    public SelectionKey open(TCPSessionCallback cb) throws Exception {
        if (finished) {
            throw new IOException("probe already finished; no further sockets may be opened");
        }
        Slot slot = new Slot();
        children.add(slot);
        gate.submitNow(() -> {
            try {
                SelectionKey k = delegate.open(cb);
                slot.key = k;
                if (k != null) {
                    byKey.put(k, slot);
                }
            } catch (Exception e) {
                release(slot);
                report(cb, e);
            }
        });
        return slot.key;
    }

    @Override
    public SelectionKey openDatagram(UDPSessionCallback cb) throws Exception {
        return delegate.openDatagram(cb);
    }

    @Override
    public void write(ProbeTCPCallback cb, byte[] data) throws Exception {
        delegate.write(cb, data);
    }

    @Override
    public TlsSession startTls(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                               Consumer<PQCSessionConfig> onTransition) throws Exception {
        return delegate.startTls(cb, sni, classicalOnly, onTransition);
    }

    @Override
    public void abort(SelectionKey key) {
        Slot slot = key == null ? null : byKey.remove(key);
        try {
            delegate.abort(key);
        } finally {
            if (slot != null) {
                release(slot);
            }
        }
    }

    // ---- accounting ----

    /** The probe delivered or was cancelled: every child still counted is handed back. */
    public void releaseAll() {
        finished = true;
        for (Slot s : children) {
            release(s);
        }
    }

    private void release(Slot slot) {
        if (slot.released.compareAndSet(false, true)) {
            gate.release();
        }
    }

    private static void report(ConnectionCallback<?> cb, Exception e) {
        try {
            cb.exception(e);              // the shape NIOSocket itself uses before rethrowing
        } catch (RuntimeException ignored) {
            // the callback's own handling failed; the slot is already back
        }
    }

    /**
     * Creates gated contexts, admits their starts through the gate, and remembers each one so a
     * context that is <em>cancelled</em> — which delivers nothing — still hands its slot and its
     * children back. One registry per {@code ProbeChecker}.
     */
    public static final class Registry {

        private static final class Entry {
            final GatedProbeTransport transport;
            final AtomicBoolean launched = new AtomicBoolean();
            final AtomicBoolean released = new AtomicBoolean();
            volatile boolean cancelled;

            Entry(GatedProbeTransport transport) {
                this.transport = transport;
            }
        }

        private final ConnectionGate gate;
        private final Map<ProbeContext, Entry> live = new ConcurrentHashMap<>();

        public Registry(ConnectionGate gate) {
            this.gate = gate == null ? ConnectionGate.UNLIMITED : gate;
        }

        /** Production: a context over the injected {@link NIOSocket}. */
        public ProbeContext create(NIOSocket nio, IPAddress target, ProbeDefinition definition,
                                   int timeoutSec, Consumer<ProbeResult> callback) {
            return create(new NioProbeTransport(nio), nio.getScheduler(), nio.getExecutor(),
                          target, definition, timeoutSec, callback);
        }

        /** The seam: any transport (a scripted one in tests), injected executors. */
        public ProbeContext create(ProbeTransport delegate, ScheduledExecutorService scheduler,
                                   Executor executor, IPAddress target, ProbeDefinition definition,
                                   int timeoutSec, Consumer<ProbeResult> callback) {
            GatedProbeTransport gated = new GatedProbeTransport(delegate, gate);
            Entry entry = new Entry(gated);
            ProbeContext[] self = new ProbeContext[1];
            ProbeContext ctx = new ProbeContext(gated, scheduler, executor, target, definition,
                                                timeoutSec, r -> {
                // The user callback runs FIRST: for a match-first sweep that callback is the
                // election, which cancels the losing candidates — including any whose start is
                // still queued in the gate. Handing this probe's slot back before that would let
                // the gate start a loser in the gap, only for the cancel to tear it down.
                try {
                    callback.accept(r);
                } finally {
                    live.remove(self[0]);
                    finish(entry);
                }
            });
            self[0] = ctx;
            live.put(ctx, entry);
            return ctx;
        }

        /**
         * Admits {@code ctx}'s start through the gate. Runs it at once when a slot is free;
         * otherwise the context stays unstarted — no timer of its arms — until one is.
         */
        public void start(ProbeContext ctx) {
            Entry entry = live.get(ctx);
            if (entry == null) {
                ctx.start();                       // not one of ours: nothing to count
                return;
            }
            gate.submit(() -> {
                entry.launched.set(true);          // set BEFORE the cancelled check (see cancelled)
                if (entry.cancelled) {
                    finish(entry);
                    return;
                }
                try {
                    ctx.start();
                } catch (RuntimeException e) {
                    live.remove(ctx);
                    finish(entry);
                    throw e;
                }
            });
        }

        /** The sweep cancelled {@code ctx}: it will never deliver, so its slot and children come back. */
        public void cancelled(ProbeContext ctx) {
            Entry entry = ctx == null ? null : live.remove(ctx);
            if (entry == null) {
                return;
            }
            entry.cancelled = true;                // set BEFORE the launched check (see start)
            finish(entry);
        }

        /** Contexts created and neither delivered nor cancelled yet — for tests. */
        public int liveCount() {
            return live.size();
        }

        private void finish(Entry entry) {
            // A start that has not run holds nothing — the gate never counted it. It sees
            // `cancelled` when it runs and hands its slot back then. Both sides set their flag
            // before reading the other's, so whichever order they run in, exactly one releases.
            entry.transport.releaseAll();
            if (entry.launched.get() && entry.released.compareAndSet(false, true)) {
                gate.release();
            }
        }
    }
}
