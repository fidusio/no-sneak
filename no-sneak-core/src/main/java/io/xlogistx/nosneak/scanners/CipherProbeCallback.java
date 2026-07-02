package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Vector;

/**
 * NIO-based cipher suite probe callback.
 * Connects to a server offering a specific set of cipher suites and reports which one was selected.
 * Used iteratively to enumerate all supported cipher suites.
 */
public class CipherProbeCallback extends TLSProbeCallback {

    public static final LogWrapper log = new LogWrapper(CipherProbeCallback.class).setEnabled(false);

    /**
     * Listener for cipher probe results.
     */
    public interface CipherProbeListener {
        /**
         * Called with the probe result.
         *
         * @param version  the protocol version tested
         * @param cipherId the selected cipher suite ID, or null if server rejected all ciphers
         */
        void onCipherProbeResult(ProtocolVersion version, Integer cipherId);
    }

    private final String hostname;
    private final ProtocolVersion targetVersion;
    private final int[] ciphersToOffer;
    private final CipherProbeListener listener;
    private volatile int selectedCipherSuite;

    public CipherProbeCallback(IPAddress address, String hostname,
                               ProtocolVersion targetVersion, int[] ciphers,
                               CipherProbeListener listener) {
        super(address);
        this.hostname = hostname;
        this.targetVersion = targetVersion;
        this.ciphersToOffer = ciphers;
        this.listener = listener;
    }

    @Override
    protected DefaultTlsClient createTlsClient() {
        return new ProbeEnumerationTlsClient(hostname, targetVersion, ciphersToOffer);
    }

    @Override
    protected void onProbeSuccess() {
        if (log.isEnabled()) {
            log.getLogger().info("Cipher probe success: " + PQCTlsClient.getCipherSuiteName(selectedCipherSuite));
        }
        listener.onCipherProbeResult(targetVersion, selectedCipherSuite);
    }

    @Override
    protected void onProbeFailure(Throwable cause) {
        if (log.isEnabled()) {
            log.getLogger().info("Cipher probe failure: " + cause.getMessage());
        }
        // null signals no more ciphers supported for this version
        listener.onCipherProbeResult(targetVersion, null);
    }

    /**
     * Minimal TLS client for cipher enumeration.
     */
    private class ProbeEnumerationTlsClient extends DefaultTlsClient {
        private final String hostname;
        private final ProtocolVersion targetVersion;
        private final int[] ciphers;

        ProbeEnumerationTlsClient(String hostname, ProtocolVersion targetVersion, int[] ciphers) {
            super(new BcTlsCrypto(new SecureRandom()));
            this.hostname = hostname;
            this.targetVersion = targetVersion;
            this.ciphers = ciphers;
        }

        @Override
        protected Vector<ServerName> getSNIServerNames() {
            Vector<ServerName> serverNames = new Vector<>();
            serverNames.add(new ServerName(NameType.host_name, hostname.getBytes(StandardCharsets.US_ASCII)));
            return serverNames;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[]{targetVersion};
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return ciphers;
        }

        @Override
        public void notifySelectedCipherSuite(int selected) {
            super.notifySelectedCipherSuite(selected);
            selectedCipherSuite = selected;
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                    // Accept any certificate for enumeration
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
