package io.xlogistx.nosneak.scanners;

import java.util.function.Consumer;

/**
 * Interface for PQC TLS connection state machine.
 * Similar to SSLConnectionHelper but for BC TLS.
 */
public interface PQCConnectionHelper {

    /**
     * PQC TLS handshake states
     */
    enum PQCHandshakeState {
        /**
         * Initial state - need to start handshake
         */
        START,

        /**
         * Need to send data to peer (ClientHello, etc.)
         */
        NEED_WRITE,

        /**
         * Need to read data from peer (ServerHello, etc.)
         */
        NEED_READ,

        /**
         * Handshake complete, ready for application data
         */
        FINISHED,

        /**
         * Connection closed or error
         */
        CLOSED
    }

    /**
     * Publish a state transition
     * @param state the new state
     * @param callback the session callback
     */
    void publish(PQCHandshakeState state, Consumer<PQCSessionConfig> callback);

    /**
     * Get the session configuration
     */
    PQCSessionConfig getConfig();
}
