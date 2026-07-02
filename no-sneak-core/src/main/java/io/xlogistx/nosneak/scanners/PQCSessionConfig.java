package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.TlsClientProtocol;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.io.CloseableType;
import org.zoxweb.shared.io.CloseableTypeDelegate;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Configuration and state holder for PQC TLS sessions.
 * Similar to SSLSessionConfig but for Bouncy Castle TLS with PQC support.
 */
public class PQCSessionConfig implements CloseableType {

    public static final LogWrapper log = new LogWrapper(PQCSessionConfig.class).setEnabled(false);

    // BC TLS protocol handler (non-blocking mode)
    public volatile TlsClientProtocol tlsProtocol;
    public volatile PQCTlsClient tlsClient;

    // Network channel
    public volatile SocketChannel channel;

    // Buffers for NIO <-> BC TLS bridge
    // Incoming encrypted data from network
    public volatile ByteBuffer inNetData;
    // Outgoing encrypted data to network
    public volatile ByteBuffer outNetData;
    // Decrypted application data
    public volatile ByteBuffer inAppData;

    // State machine reference
    public volatile PQCConnectionHelper connectionHelper;

    // State tracking

    public final AtomicBoolean handshakeStarted = new AtomicBoolean(false);
    public final AtomicBoolean handshakeComplete = new AtomicBoolean(false);
    private final CloseableTypeDelegate closeableDelegate = new CloseableTypeDelegate(this, true);

    // Hostname for SNI
    private final InetSocketAddress hostname;

    public PQCSessionConfig(InetSocketAddress hostname) {
        this.hostname = hostname;
        // Allocate buffers - 16KB is standard TLS record size
        this.inNetData = ByteBufferUtil.allocateByteBuffer(SharedIOUtil.K_16);
        this.outNetData = ByteBufferUtil.allocateByteBuffer(SharedIOUtil.K_16);
        this.inAppData = ByteBufferUtil.allocateByteBuffer(SharedIOUtil.K_16);

        closeableDelegate.setDelegate(()->{
            if (tlsProtocol != null) {
                try {
                    tlsProtocol.close();
                } catch (Exception ignored) {
                    ignored.printStackTrace();
                }
            }
            SharedIOUtil.close(channel);
            ByteBufferUtil.cache(inNetData, outNetData, inAppData);


            if (log.isEnabled()) log.getLogger().info("PQCSessionConfig closed for " + hostname);
        });
    }

    public String getHostname() {
        return hostname.getHostName();
    }

    /**
     * Initialize the BC TLS protocol in non-blocking mode
     */
    public void initProtocol() throws IOException {
        if (tlsProtocol != null) {
            throw new IllegalStateException("Protocol already initialized");
        }
        // Non-blocking constructor
        tlsProtocol = new PQCTlsClientProtocol();
        tlsClient = new PQCTlsClient(hostname);
    }

    /**
     * Start the TLS handshake (sends ClientHello)
     */
    public void beginHandshake() throws IOException {
        if (!handshakeStarted.compareAndSet(false, true)) {
            return; // Already started
        }
        tlsProtocol.connect(tlsClient);
    }

    /**
     * Check if there's output data to send to the network
     */
    public int getAvailableOutputBytes() {
        return tlsProtocol != null ? tlsProtocol.getAvailableOutputBytes() : 0;
    }

    /**
     * Read output data to send to network
     */
    public int readOutput(byte[] buffer, int offset, int length) {
        return tlsProtocol.readOutput(buffer, offset, length);
    }

    /**
     * Read output data to ByteBuffer
     */
    public int readOutput(ByteBuffer buffer, int length) {
        return tlsProtocol.readOutput(buffer, length);
    }

    /**
     * Offer input data received from network
     */
    public void offerInput(byte[] data, int offset, int length) throws IOException {
        tlsProtocol.offerInput(data, offset, length);
    }

    /**
     * Check if handshake is still in progress
     */
    public boolean isHandshaking() {
        return tlsProtocol != null && tlsProtocol.isHandshaking();
    }

    /**
     * Check if there's decrypted application data available
     */
    public int getAvailableInputBytes() {
        return tlsProtocol != null ? tlsProtocol.getAvailableInputBytes() : 0;
    }

    /**
     * Read decrypted application data
     */
    public int readInput(byte[] buffer, int offset, int length) {
        return tlsProtocol.readInput(buffer, offset, length);
    }

    @Override
    public void close() {
        SharedIOUtil.close(closeableDelegate);
    }

    @Override
    public boolean isClosed() {
        return closeableDelegate.isClosed();
    }
}
