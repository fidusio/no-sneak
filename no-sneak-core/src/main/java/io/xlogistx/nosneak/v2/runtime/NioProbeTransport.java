package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.tls.PQCConnectionHelper.PQCHandshakeState;
import io.xlogistx.nosneak.v2.tls.PQCHandshakeStateMachine;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.common.UDPSessionCallback;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.function.Consumer;

/** The production {@link ProbeTransport}: the injected {@link NIOSocket} and Bouncy Castle. */
final class NioProbeTransport implements ProbeTransport {

    private final NIOSocket nioSocket;

    NioProbeTransport(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
    }

    @Override
    public SelectionKey open(TCPSessionCallback cb, int timeoutSec) throws Exception {
        return nioSocket.addClientSocket(cb, timeoutSec);
    }

    @Override
    public SelectionKey open(TCPSessionCallback cb) throws Exception {
        return nioSocket.addClientSocket(cb);
    }

    @Override
    public SelectionKey openDatagram(UDPSessionCallback cb) throws Exception {
        return nioSocket.addDatagramSocket(new InetSocketAddress(0), cb); // ephemeral local bind
    }

    @Override
    public void write(ProbeTCPCallback cb, byte[] data) throws Exception {
        SocketChannel channel = cb.getChannel();
        if (channel == null) {
            throw new IOException("no channel to write to");
        }
        ByteBufferUtil.write(channel, ByteBuffer.wrap(data), false);
    }

    @Override
    public TlsSession startTls(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                               Consumer<PQCSessionConfig> onTransition) throws Exception {
        PQCSessionConfig config = new PQCSessionConfig(sni, classicalOnly);
        config.channel = cb.getChannel();
        PQCHandshakeStateMachine machine = new PQCHandshakeStateMachine(config);
        machine.publish(PQCHandshakeState.START, onTransition);
        return new TlsSession(config, machine);
    }

    @Override
    public void abort(SelectionKey key) {
        nioSocket.abortClientSocket(key);
    }
}
