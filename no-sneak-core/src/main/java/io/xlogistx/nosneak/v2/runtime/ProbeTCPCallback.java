package io.xlogistx.nosneak.v2.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

/**
 * One raw (plaintext) TCP connection within a {@link ProbeContext}. A thin,
 * non-blocking translator: NIO lifecycle events become context ingress calls, and
 * inbound bytes are read off the channel and handed to the context, which routes
 * them to the active {@code expect} matcher.
 * <p>
 * Reads follow the non-blocking {@code accept(SelectionKey)} idiom (the read happens
 * there; {@code accept(ByteBuffer)} is a no-op). Because a context outlives individual
 * connections, the context ignores events from a stale (already-replaced) callback via
 * an identity check.
 */
public class ProbeTCPCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeTCPCallback.class).setEnabled(false);

    private final ProbeContext context;
    private final int connectionIndex;
    // Non-pooled per-connection buffer reclaimed by GC.
    private final ByteBuffer readBuffer = ByteBuffer.allocate(16384);
    private volatile SelectionKey selectionKey;

    public ProbeTCPCallback(ProbeContext context, IPAddress address, int connectionIndex) {
        super(address);
        this.context = context;
        this.connectionIndex = connectionIndex;
    }

    public int connectionIndex() {
        return connectionIndex;
    }

    @Override
    protected void connectedFinished() throws IOException {
        context.onConnected(this);
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
                    context.onException(this, new IOException("Connection closed by peer"));
                    return;
                }
                if (bytesRead > 0) {
                    readBuffer.flip();
                    byte[] bytes = new byte[readBuffer.remaining()];
                    readBuffer.get(bytes);
                    context.onInbound(this, bytes);
                }
            }
        } catch (Exception e) {
            key.cancel();
            context.onException(this, e);
        }
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Inbound is handled via accept(SelectionKey).
    }

    @Override
    public void exception(Throwable e) {
        context.onException(this, e);
    }
}
