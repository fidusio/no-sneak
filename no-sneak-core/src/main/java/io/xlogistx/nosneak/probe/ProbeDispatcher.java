package io.xlogistx.nosneak.probe;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.probe.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.probe.runtime.ProbeSession;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;

import java.util.List;
import java.util.function.Consumer;

/**
 * The seam between nmap's discovered open {@code ip:port}s and the probe
 * framework. Given a target it selects the best-matching {@link ProbeDefinition}
 * (by port/transport, highest priority) and runs a {@link ProbeSession},
 * emitting a facts-only {@link ProbeResult} the deferred rules/record layer
 * consumes. Takes the shared {@link NIOSocket} the same way nmap engines do, so
 * probes run on the existing event loop (no thread-per-target).
 */
public class ProbeDispatcher {

    public static final LogWrapper log = new LogWrapper(ProbeDispatcher.class).setEnabled(false);

    private final NIOSocket nioSocket;
    private final List<ProbeDefinition> definitions;
    private int timeoutSec = 10;

    public ProbeDispatcher(NIOSocket nioSocket, List<ProbeDefinition> definitions) {
        this.nioSocket = nioSocket;
        this.definitions = definitions; // expected pre-sorted by descending priority
    }

    /** Create a dispatcher with the bundled probe definitions loaded/validated. */
    public static ProbeDispatcher withBundledDefinitions(NIOSocket nioSocket) {
        return new ProbeDispatcher(nioSocket, ProbeDefinitionLoader.loadBundled());
    }

    public ProbeDispatcher timeoutInSec(int seconds) {
        this.timeoutSec = seconds;
        return this;
    }

    /** Select the highest-priority definition matching this port/transport, or null. */
    public ProbeDefinition select(int port, String transport) {
        for (ProbeDefinition def : definitions) {
            if (def.matches(port, transport)) {
                return def;
            }
        }
        return null;
    }

    /** Dispatch a TCP probe. */
    public void dispatch(IPAddress target, Consumer<ProbeResult> callback) {
        dispatch(target, "tcp", callback);
    }

    /**
     * Select a definition for {@code target}'s port/transport and run it. If no
     * definition matches, emit a minimal facts result (well-known service name,
     * {@code tls-state:none}, incomplete) so the caller always gets a result.
     */
    public void dispatch(IPAddress target, String transport, Consumer<ProbeResult> callback) {
        int port = target.getPort();
        ProbeDefinition def = select(port, transport);
        if (def == null) {
            String service = ServiceMatch.getWellKnownService(port, transport);
            ProbeResult r = ProbeResult.builder(target.getInetAddress(), port, transport)
                    .service(service)
                    .tlsState(ProbeResult.TlsState.NONE)
                    .pqcStatus(ProbeResult.PqcStatus.UNKNOWN)
                    .complete(false)
                    .note("no-probe-definition")
                    .build();
            callback.accept(r);
            return;
        }
        try {
            ProbeSession session = new ProbeSession(nioSocket, target, def, timeoutSec, callback);
            session.start();
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("dispatch error: " + e.getMessage());
            ProbeResult r = ProbeResult.builder(target.getInetAddress(), port, transport)
                    .service(def.getService())
                    .probeName(def.getName())
                    .complete(false)
                    .note("dispatch-error:" + e.getMessage())
                    .build();
            callback.accept(r);
        }
    }
}
