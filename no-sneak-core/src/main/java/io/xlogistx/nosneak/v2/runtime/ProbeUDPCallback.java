package io.xlogistx.nosneak.v2.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.server.net.ssl.SSLConfigInt;

import java.nio.ByteBuffer;

/**
 * One UDP datagram session within a {@link ProbeContext}. UDP is connectionless: the
 * context {@code send}s a request datagram to the target and the response arrives via
 * {@link #accept(DataPacket)}, which forwards the decoded bytes to the context's
 * {@code expect} matcher. Inbound datagrams are dispatched on
 * the executor supplied by the context; the context serialises ingress.
 */
import java.util.concurrent.Executor;

public class ProbeUDPCallback extends UDPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeUDPCallback.class).setEnabled(false);

    private final ProbeContext context;
    private final int connectionIndex;

    public ProbeUDPCallback(Executor executor, ProbeContext context, int port, int connectionIndex) {
        // Executor for inbound dispatch; `port` is a valid placeholder — the socket binds to an
        // ephemeral local port via NIOSocket.addDatagramSocket(new InetSocketAddress(0), this).
        super(executor, port);
        this.context = context;
        this.connectionIndex = connectionIndex;
    }

    public int connectionIndex() {
        return connectionIndex;
    }

    @Override
    public void accept(DataPacket<?> dataPacket) {
        if (dataPacket == null) {
            return;
        }
        ByteBuffer buf = dataPacket.getBuffer();
        if (buf == null || buf.remaining() <= 0) {
            return;
        }
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        context.onUDPInbound(this, bytes);
    }

    @Override
    public void exception(Throwable e) {
        context.onUDPException(this, e);
    }

    @Override
    public void sslHandshakeSuccessful(SSLConfigInt config) {
        // Not applicable to UDP.
    }
}
