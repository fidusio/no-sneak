package io.xlogistx.nosneak.probe.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

/**
 * One TCP connection within a {@link ProbeSession}. It is a thin translator:
 * NIO lifecycle events become session ingress calls, and inbound bytes are read
 * off the channel and handed to the session, which routes them to the active
 * {@code expect} matcher or the TLS handshake pump depending on session mode.
 * <p>
 * Reads follow the proven {@link io.xlogistx.nosneak.scanners.TLSProbeCallback}
 * pattern: {@code accept(SelectionKey)} performs the {@code channel.read}, and
 * {@code accept(ByteBuffer)} is a no-op. Because a session outlives individual
 * connections, the session ignores events from a stale (already-replaced)
 * callback via an identity check.
 */
public class ProbeTCPCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeTCPCallback.class).setEnabled(false);

    private final ProbeSession session;
    private final int connectionIndex;
    // Non-pooled: a per-connection buffer that the GC reclaims. (A pooled buffer would
    // need explicit caching on close, but the parent close delegate — which we cannot
    // override here since setDelegate() is a no-op once the base ctor installed one —
    // would never return it, leaking one 16K buffer per connection.)
    private final ByteBuffer readBuffer = ByteBuffer.allocate(16384);
    private volatile SelectionKey selectionKey;

    public ProbeTCPCallback(ProbeSession session, IPAddress address, int connectionIndex) {
        super(address);
        this.session = session;
        this.connectionIndex = connectionIndex;
        // No custom close delegate: the parent TCPSessionCallback delegate already closes
        // the channel + output stream; the selection key is cancelled inline in accept().
    }

    public int connectionIndex() {
        return connectionIndex;
    }

    @Override
    protected void connectedFinished() throws IOException {
        session.onConnected(this);
    }

    @Override
    public void accept(SelectionKey key) {
        this.selectionKey = key;
        try {
            if (key.isReadable()) {
                SocketChannel channel = (SocketChannel) key.channel();
                readBuffer.clear();
                int bytesRead = channel.read(readBuffer);
                if (bytesRead == -1) {
                    key.cancel();
                    session.onException(this, new IOException("Connection closed by peer"));
                    return;
                }
                if (bytesRead > 0) {
                    readBuffer.flip();
                    byte[] bytes = new byte[readBuffer.remaining()];
                    readBuffer.get(bytes);
                    session.onInbound(this, bytes);
                }
            }
        } catch (Exception e) {
            key.cancel();
            session.onException(this, e);
        }
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Inbound is handled via accept(SelectionKey) (see TLSProbeCallback).
    }

    @Override
    public void exception(Throwable e) {
        session.onException(this, e);
    }
}
