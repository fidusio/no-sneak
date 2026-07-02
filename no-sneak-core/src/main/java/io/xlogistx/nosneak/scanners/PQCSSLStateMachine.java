package io.xlogistx.nosneak.scanners;

import io.xlogistx.nosneak.scanners.PQCConnectionHelper.PQCHandshakeState;
import org.zoxweb.server.fsm.MonoStateMachine;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.Identifier;
import org.zoxweb.shared.util.RateCounter;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.scanners.PQCConnectionHelper.PQCHandshakeState.*;

/**
 * Non-blocking state machine for PQC TLS handshake using Bouncy Castle.
 * Inspired by CustomSSLStateMachine but adapted for BC TlsClientProtocol.
 * <p>
 * BC TLS non-blocking mode:
 * - Call connect(tlsClient) to send ClientHello
 * - Check getAvailableOutputBytes() for data to send
 * - Call offerInput() when network data arrives
 * - Check isHandshaking() for completion
 */
public class PQCSSLStateMachine
        extends MonoStateMachine<PQCHandshakeState, Consumer<PQCSessionConfig>>
        implements PQCConnectionHelper, Closeable, Identifier<Long> {

    public static final LogWrapper log = new LogWrapper(PQCSSLStateMachine.class).setEnabled(false);

    // Rate counters for monitoring
    static RateCounter rcStart = new RateCounter("Start");
    static RateCounter rcNeedWrite = new RateCounter("NeedWrite");
    static RateCounter rcNeedRead = new RateCounter("NeedRead");
    static RateCounter rcFinished = new RateCounter("Finished");
    static RateCounter rcClosed = new RateCounter("Closed");

    private static final AtomicLong counter = new AtomicLong();

    private final PQCSessionConfig config;
    private final long id;

    // Temp buffer for reading from channel


    public static long getIDCount() {
        return counter.get();
    }

    /**
     * Create a PQC SSL state machine for a session
     *
     * @param config the session configuration
     */
    public PQCSSLStateMachine(PQCSessionConfig config) {
        super(false); // non-synchronous
        this.config = config;
        this.id = counter.incrementAndGet();
        config.connectionHelper = this;

        // Register state handlers
        register(START, this::handleStart)
                .register(NEED_WRITE, this::handleNeedWrite)
                .register(NEED_READ, this::handleNeedRead)
                .register(FINISHED, this::handleFinished)
                .register(CLOSED, this::handleClosed);
    }

    @Override
    public Long getID() {
        return id;
    }

    @Override
    public PQCSessionConfig getConfig() {
        return config;
    }

    @Override
    public void close() throws IOException {
        config.close();
    }

    // ==================== State Handlers ====================

    /**
     * START state - Initialize protocol and begin handshake
     */
    public void handleStart(Consumer<PQCSessionConfig> callback) {
        long ts = System.currentTimeMillis();

        if (log.isEnabled()) {
            log.getLogger().info("START: Initializing TLS handshake for " + config.getHostname());
        }

        try {
            // Initialize BC TLS protocol in non-blocking mode
            config.initProtocol();

            // Begin handshake - this sends ClientHello
            config.beginHandshake();

            // After connect(), there should be ClientHello to send
            if (config.getAvailableOutputBytes() > 0) {
                publish(NEED_WRITE, callback);
            } else {
                // Unusual - no output after connect
                if (log.isEnabled()) {
                    log.getLogger().info("START: No output after connect, waiting for input");
                }
                publish(NEED_READ, callback);
            }

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("START: Error - " + e.getMessage());
                e.printStackTrace();
            }
            // Mark as closed and notify callback
            publish(CLOSED, callback);
        }

        rcStart.register(System.currentTimeMillis() - ts);
    }

    /**
     * NEED_WRITE state - Send encrypted data to peer
     */
    public void handleNeedWrite(Consumer<PQCSessionConfig> callback) {
        long ts = System.currentTimeMillis();

        if (log.isEnabled()) {
            log.getLogger().info("NEED_WRITE: " + config.getAvailableOutputBytes() + " bytes to send");
        }

        if (config.isClosed()) {
            publish(CLOSED, callback);
            return;
        }

        try {
            int available = config.getAvailableOutputBytes();
            if (available > 0) {
                // Read from BC TLS into byte array first
                byte[] outputData = new byte[available];
                int read = config.tlsProtocol.readOutput(outputData, 0, available);

                if (read > 0) {
                    // Write to network channel
                    ByteBuffer writeBuffer = ByteBuffer.wrap(outputData, 0, read);
                    int totalWritten = ByteBufferUtil.write(config.channel, writeBuffer, false);

                    if (log.isEnabled()) {
                        log.getLogger().info("NEED_WRITE: Wrote " + totalWritten + "/" + read + " bytes to channel");
                    }

                    if (totalWritten < read) {
                        log.getLogger().warning("NEED_WRITE: Failed to write all bytes! remaining " + (read - totalWritten));
                    }
                }
            }

            // Determine next state
            if (config.isHandshaking()) {
                // More handshake to do - wait for server response
                publish(NEED_READ, callback);
            } else if (config.handshakeComplete.get()) {
                publish(FINISHED, callback);
            } else {
                // Check if handshake just completed
                if (!config.isHandshaking() && config.handshakeStarted.get()) {
                    config.handshakeComplete.set(true);
                    publish(FINISHED, callback);
                } else {
                    publish(NEED_READ, callback);
                }
            }

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("NEED_WRITE: Error - " + e.getMessage());
                e.printStackTrace();
            }
            publish(CLOSED, callback);
        }

        rcNeedWrite.register(System.currentTimeMillis() - ts);
    }

    /**
     * NEED_READ state - Waiting for data from peer.
     * In NIO mode, this is a waiting state - data will arrive via processIncomingData().
     * This method is called to indicate we're waiting for data.
     */
    public void handleNeedRead(Consumer<PQCSessionConfig> callback) {
        long ts = System.currentTimeMillis();

        if (log.isEnabled()) {
            log.getLogger().info("NEED_READ: Waiting for data from peer");
        }

        if (config.isClosed()) {
            publish(CLOSED, callback);
            return;
        }

        // In NIO mode, we don't read directly here.
        // Data will arrive via processIncomingData() callback from NIOSocket.
        // Just record that we're in NEED_READ state.

        rcNeedRead.register(System.currentTimeMillis() - ts);
    }

    /**
     * FINISHED state - Handshake complete
     */
    public void handleFinished(Consumer<PQCSessionConfig> callback) {
        long ts = System.currentTimeMillis();

        if (log.isEnabled()) {
            log.getLogger().info("FINISHED: Handshake complete for " + config.getHostname());
        }

        // Notify callback that handshake is successful
        if (callback != null) {
            try {
                // Signal handshake completion via the callback
                // The callback can extract PQC info from config.tlsClient
                callback.accept(config);
            } catch (Exception e) {
                if (log.isEnabled()) {
                    log.getLogger().info("FINISHED: Callback error - " + e.getMessage());
                }
            }
        }

        rcFinished.register(System.currentTimeMillis() - ts);
    }

    /**
     * CLOSED state - Connection closed or error
     */
    public void handleClosed(Consumer<PQCSessionConfig> callback) {
        long ts = System.currentTimeMillis();

        if (log.isEnabled()) {
            log.getLogger().info("CLOSED: Connection closed for " + config.getHostname());
        }

        config.close();

        rcClosed.register(System.currentTimeMillis() - ts);
    }

    // ==================== Utility Methods ====================

    /**
     * Process incoming data from NIO (called by NIOSocket callback)
     */
    public void processIncomingData(ByteBuffer data, Consumer<PQCSessionConfig> callback) {
        if (config.isClosed()) {
            return;
        }

        try {
            if (data != null && data.hasRemaining()) {
                byte[] bytes = new byte[data.remaining()];
                data.get(bytes);
                config.offerInput(bytes, 0, bytes.length);

                // Check what to do next
                if (config.getAvailableOutputBytes() > 0) {
                    publish(NEED_WRITE, callback);
                } else if (!config.isHandshaking()) {
                    config.handshakeComplete.set(true);
                    publish(FINISHED, callback);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("processIncomingData: Error - " + e.getMessage());
            }
            // Error during processing - connection should be closed by caller
        }
    }

    /**
     * Get rate statistics
     */
    public static String rates() {
        return String.join(",",
                rcStart.toString(),
                rcNeedWrite.toString(),
                rcNeedRead.toString(),
                rcFinished.toString(),
                rcClosed.toString());
    }
}
