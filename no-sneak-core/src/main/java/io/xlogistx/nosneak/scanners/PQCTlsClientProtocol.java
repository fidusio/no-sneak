package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.*;
import org.bouncycastle.util.Integers;
import org.zoxweb.server.logging.LogWrapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;

/**
 * Custom TlsClientProtocol that exposes the negotiated key exchange group.
 * BC's TlsClientProtocol processes the key_share internally without exposing it.
 * This subclass captures the group before it's consumed.
 */
public class PQCTlsClientProtocol extends TlsClientProtocol {

    public static final LogWrapper log = new LogWrapper(PQCTlsClientProtocol.class).setEnabled(false);

    private volatile int negotiatedNamedGroup = -1;
    private PQCTlsClient pqcTlsClient;

    public PQCTlsClientProtocol(InputStream input, OutputStream output) {
        super(input, output);
    }

    public PQCTlsClientProtocol() {
        super();
    }

    /**
     * Override connect to capture PQCTlsClient reference for key exchange tracking.
     * This is an override (not overload) so it works regardless of the declared type.
     */
    @Override
    public void connect(TlsClient tlsClient) throws IOException {
        if (tlsClient instanceof PQCTlsClient) {
            this.pqcTlsClient = (PQCTlsClient) tlsClient;
        }
        super.connect(tlsClient);
    }

    @Override
    protected void process13ServerHello(ServerHello serverHello, boolean afterHelloRetryRequest)
            throws IOException {

        // Extract key_share before parent processes it
        Hashtable extensions = serverHello.getExtensions();
        if (extensions != null) {
            try {
                KeyShareEntry keyShareEntry = TlsExtensionsUtils.getKeyShareServerHello(extensions);
                if (keyShareEntry != null) {
                    this.negotiatedNamedGroup = keyShareEntry.getNamedGroup();
                    if (log.isEnabled()) {
                        log.getLogger().info("Captured key_share named group: " +
                            PQCTlsClient.getNamedGroupName(negotiatedNamedGroup) +
                            " (0x" + Integer.toHexString(negotiatedNamedGroup) + ")" +
                            " PQC: " + PQCTlsClient.isPQCHybridGroup(negotiatedNamedGroup));
                    }
                    // Also update the TlsClient
                    if (pqcTlsClient != null) {
                        pqcTlsClient.setNegotiatedKeyExchange(negotiatedNamedGroup);
                    }
                }
            } catch (Exception e) {
                if (log.isEnabled()) {
                    log.getLogger().info("Error extracting key_share: " + e.getMessage());
                }
            }
        }

        // Call parent to complete processing
        super.process13ServerHello(serverHello, afterHelloRetryRequest);
    }

    /**
     * Get the negotiated named group (key exchange algorithm)
     * @return the NamedGroup value, or -1 if not yet negotiated
     */
    public int getNegotiatedNamedGroup() {
        return negotiatedNamedGroup;
    }

    /**
     * Get the negotiated named group name
     * @return human-readable name
     */
    public String getNegotiatedNamedGroupName() {
        if (negotiatedNamedGroup < 0) return "UNKNOWN";
        return PQCTlsClient.getNamedGroupName(negotiatedNamedGroup);
    }

    /**
     * Check if the negotiated group is PQC hybrid
     * @return true if PQC hybrid key exchange was used
     */
    public boolean isPQCHybridKeyExchange() {
        return negotiatedNamedGroup >= 0 && PQCTlsClient.isPQCHybridGroup(negotiatedNamedGroup);
    }
}
