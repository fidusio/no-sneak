package io.xlogistx.nosneak.scanners;

import io.xlogistx.nosneak.scanners.PQCConnectionHelper.PQCHandshakeState;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;

/**
 * Non-blocking PQC Scanner using PQCSSLStateMachine.
 * Integrates with NIOSocket for fully async TLS handshake with PQC support.
 * <p>
 * This class handles only the TLS handshake. Phase 2 tasks (revocation,
 * cipher enumeration, version testing) are managed by {@link PQCScanCallback}.
 */
public class PQCNIOScanner extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(PQCNIOScanner.class).setEnabled(false);

    private final ScanCallback scanCallback;
    private final long startTime;

    // State machine and config
    private PQCSessionConfig pqcConfig;
    private PQCSSLStateMachine stateMachine;

    // State machine callback - processes state transitions
    private final Consumer<PQCSessionConfig> smCallback = this::onStateTransition;

    // State tracking
    private volatile boolean completed = false;
    private volatile SelectionKey selectionKey;

    /**
     * Create a PQC NIO scanner for the given target.
     *
     * @param address      target address (host:port)
     * @param scanCallback callback to receive handshake results
     */
    public PQCNIOScanner(IPAddress address, ScanCallback scanCallback) {
        super(address);
        this.scanCallback = scanCallback;
        this.startTime = System.currentTimeMillis();
        closeableDelegate.setDelegate(()->{
            if (selectionKey != null) {
                selectionKey.cancel();
            }
            if (stateMachine != null) {
                try {
                    stateMachine.close();
                } catch (Exception ignored) {
                    ignored.printStackTrace();
                }
            }
            if (pqcConfig != null) {
                // pqcConfig.close() already closes the channel and caches buffers
                SharedIOUtil.close(pqcConfig);
            } else {
                SharedIOUtil.close(getChannel());
            }
            SharedIOUtil.close(getOutputStream());
        });
    }

    /**
     * Called when TCP connection is established.
     * Initialize PQC state machine and start handshake.
     */
    @Override
    protected void connectedFinished() throws IOException {
        if (completed) return;

        SocketChannel channel = getChannel();
        String hostname = getRemoteAddress().getHostName();

        if (log.isEnabled()) {
            log.getLogger().info("Connected to " + hostname + ":" + getRemoteAddress().getPort() +
                    ", initializing PQC state machine");
        }

        // Initialize PQC session config and state machine
        pqcConfig = new PQCSessionConfig(getRemoteAddress());
        pqcConfig.channel = channel;
        stateMachine = new PQCSSLStateMachine(pqcConfig);

        // Start handshake via state machine
        stateMachine.publish(PQCHandshakeState.START, smCallback);
    }

    /**
     * Called by state machine on state transitions
     */
    private void onStateTransition(PQCSessionConfig config) {
        // Check if handshake completed
        if (config != null && config.handshakeComplete.get() && !completed) {
            processHandshakeResult();
        }
    }

    /**
     * Called when data is received from NIO.
     * Process through state machine.
     */
    @Override
    public void accept(ByteBuffer buffer) {
        if (completed || pqcConfig == null || stateMachine == null) {
            return;
        }

        if (log.isEnabled() && buffer != null) {
            log.getLogger().info("Received " + buffer.remaining() + " bytes");
        }

        // Process incoming data through state machine
        stateMachine.processIncomingData(buffer, smCallback);
    }

    /**
     * Called when SelectionKey is ready.
     * This handles both read readiness and connection completion.
     */
    @Override
    public void accept(SelectionKey key) {
        if (completed) return;
        this.selectionKey = key;

        try {
            if (key.isReadable() && stateMachine != null) {
                // Read data from channel
                SocketChannel channel = (SocketChannel) key.channel();
                pqcConfig.inNetData.clear();
                int bytesRead = channel.read(pqcConfig.inNetData);

                if (bytesRead == -1) {
                    // Channel closed - cancel key before cleanup
                    key.cancel();
                    completeWithError("Connection closed by peer");
                    return;
                }

                if (bytesRead > 0) {
                    pqcConfig.inNetData.flip();
                    stateMachine.processIncomingData(pqcConfig.inNetData, smCallback);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error processing SelectionKey: " + e.getMessage());
            }
            key.cancel();
            completeWithError(e.getMessage());
        }
    }

    /**
     * Called by state machine on handshake completion.
     * Delegates to ScanCallback for Phase 2 processing.
     */
    private void processHandshakeResult() {
        if (completed) return;
        completed = true;

        try {
            scanCallback.onHandshakeComplete(pqcConfig);
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error in handshake callback: " + e.getMessage());
            }
            scanCallback.onError("Error processing result: " + e.getMessage());
        } finally {
            SharedIOUtil.close(this);
        }
    }

    /**
     * Complete with error
     */
    private void completeWithError(String errorMessage) {
        if (completed) return;
        completed = true;

        scanCallback.onError(errorMessage);
        SharedIOUtil.close(this);
    }


    @Override
    public void exception(Throwable e) {
        if (completed) return;

        if (log.isEnabled()) {
            log.getLogger().info("Connection exception: " + e.getMessage());
        }

        completeWithError(e.getMessage());
    }


    public boolean isCompleted() {
        return completed;
    }

    public PQCSessionConfig getPQCConfig() {
        return pqcConfig;
    }

    // ==================== Static Helpers (reused by ScannerMotherCallback) ====================

    /**
     * Convert BC Certificate to Java X509Certificate array
     */
    static X509Certificate[] convertCertificateChain(Certificate bcCert) {
        try {
            TlsCertificate[] tlsCerts = bcCert.getCertificateList();
            X509Certificate[] chain = new X509Certificate[tlsCerts.length];
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            for (int i = 0; i < tlsCerts.length; i++) {
                byte[] encoded = tlsCerts[i].getEncoded();
                chain[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
            }
            return chain;
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to convert certificate chain: " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Verify the certificate chain anchors to a trusted Root CA.
     *
     * @param chain the certificate chain (leaf first, root last)
     * @return true iff PKIX-validated to a trusted root
     * @deprecated use {@code OPSecUtil.validateChain(chain)} directly for the
     *             structured trust outcome; this is a compatibility shim that
     *             delegates to real PKIX validation (no longer the old
     *             signature-linkage-only check).
     */
    @Deprecated
    static boolean verifyCertificateChain(X509Certificate[] chain) {
        return io.xlogistx.opsec.OPSecUtil.singleton().validateChain(chain).isTrusted();
    }

    static PQCScanResult.KeyExchangeType parseKeyExchangeType(String type) {
        if (type == null) return PQCScanResult.KeyExchangeType.UNKNOWN;
        switch (type) {
            case "PQC_HYBRID":
                return PQCScanResult.KeyExchangeType.PQC_HYBRID;
            case "ECDHE":
                return PQCScanResult.KeyExchangeType.ECDHE;
            case "DHE":
                return PQCScanResult.KeyExchangeType.DHE;
            case "RSA":
                return PQCScanResult.KeyExchangeType.RSA;
            default:
                return PQCScanResult.KeyExchangeType.UNKNOWN;
        }
    }

    static PQCScanResult.SignatureType parseSignatureType(String type) {
        if (type == null) return PQCScanResult.SignatureType.UNKNOWN;
        switch (type) {
            case "PQC_SIGNATURE":
                return PQCScanResult.SignatureType.PQC_SIGNATURE;
            case "ECDSA":
                return PQCScanResult.SignatureType.ECDSA;
            case "RSA":
                return PQCScanResult.SignatureType.RSA;
            case "EDDSA":
                return PQCScanResult.SignatureType.EDDSA;
            default:
                return PQCScanResult.SignatureType.UNKNOWN;
        }
    }
}
