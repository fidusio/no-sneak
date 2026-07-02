package io.xlogistx.nosneak.scanners;

/**
 * Callback interface between PQCNIOScanner and its parent orchestrator.
 * Replaces Consumer&lt;PQCScanResult&gt; as the contract for handshake completion.
 */
public interface ScanCallback {

    /**
     * Called when TLS handshake completes successfully.
     * The config contains the TLS client, negotiated parameters, and certificate chain.
     *
     * @param config the session configuration with handshake results
     */
    void onHandshakeComplete(PQCSessionConfig config);

    /**
     * Called when the scan fails with an error.
     *
     * @param errorMessage description of the error
     */
    void onError(String errorMessage);
}
