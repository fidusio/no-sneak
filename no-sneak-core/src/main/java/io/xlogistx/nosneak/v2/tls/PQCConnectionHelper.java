package io.xlogistx.nosneak.v2.tls;

import java.util.function.Consumer;

/**
 * Interface for the PQC/BC TLS handshake driver. Both a trigger-{@code StateMachine}
 * implementation ({@link PQCHandshakeStateMachine}) and any future variant program to
 * this — the caller ({@code ProbeContext}) never depends on a concrete engine. No
 * {@code MonoStateMachine} is involved.
 */
public interface PQCConnectionHelper {

    /** PQC/BC TLS handshake steps. */
    enum PQCHandshakeState {
        START,       // initialize protocol + send ClientHello
        NEED_WRITE,  // flush BC output (ClientHello, etc.) to the network
        NEED_READ,   // parked: waiting for server bytes (delivered via processIncomingData)
        FINISHED,    // handshake complete
        CLOSED       // connection closed or error
    }

    /** Enter a handshake step; {@code callback} is notified on completion (FINISHED). */
    void publish(PQCHandshakeState state, Consumer<PQCSessionConfig> callback);

    /** The session configuration/state. */
    PQCSessionConfig getConfig();
}
