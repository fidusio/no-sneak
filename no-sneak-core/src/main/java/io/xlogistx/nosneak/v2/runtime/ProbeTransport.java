package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.tls.PQCHandshakeStateMachine;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.common.UDPSessionCallback;

import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.util.function.Consumer;

/**
 * The seam between a {@link ProbeContext} and the wire. Everything the context does that
 * touches a socket or a TLS engine goes through here, so the state machine can be driven by a
 * scripted transport in a test with no network, no selector thread and no real timers
 * ({@code ProbeContextTest}). Production uses {@link NioProbeTransport} over the injected
 * {@code NIOSocket}; the executors are injected separately so a test can hand the context a
 * manual scheduler.
 * <p>
 * Package-private on purpose: it is a test seam, not an extension point. Nothing here may
 * block — every method starts asynchronous work and returns.
 */
interface ProbeTransport {

    /** Connect {@code cb} with a connect timeout; returns the registration key. */
    SelectionKey open(TCPSessionCallback cb, int timeoutSec) throws Exception;

    /** Connect an analysis child that carries its own timeout (version / cipher probes). */
    SelectionKey open(TCPSessionCallback cb) throws Exception;

    /** Bind an ephemeral datagram socket for a UDP probe. */
    SelectionKey openDatagram(UDPSessionCallback cb) throws Exception;

    /** Write plaintext to the raw channel behind {@code cb}. */
    void write(ProbeTCPCallback cb, byte[] data) throws Exception;

    /**
     * Begin a Bouncy Castle handshake on the channel behind {@code cb}. The returned session
     * is what the context feeds inbound bytes into and reads TLS facts from.
     */
    TlsSession startTls(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                        Consumer<PQCSessionConfig> onTransition) throws Exception;

    /** Abort a still-registered connection (cancels its pending connect-timeout appointment). */
    void abort(SelectionKey key);

    /** The live handshake pieces; either may be null on a transport that does not run TLS. */
    final class TlsSession {
        final PQCSessionConfig config;
        final PQCHandshakeStateMachine machine;

        TlsSession(PQCSessionConfig config, PQCHandshakeStateMachine machine) {
            this.config = config;
            this.machine = machine;
        }
    }
}
