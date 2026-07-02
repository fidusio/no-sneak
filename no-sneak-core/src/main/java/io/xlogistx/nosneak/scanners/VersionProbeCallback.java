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
 * NIO-based protocol version probe callback.
 * Connects to a server offering a specific TLS/SSL version and reports whether it was accepted.
 */
public class VersionProbeCallback extends TLSProbeCallback {

    public static final LogWrapper log = new LogWrapper(VersionProbeCallback.class).setEnabled(false);

    /**
     * Listener for version probe results.
     */
    public interface VersionProbeListener {
        /**
         * Called with the probe result.
         *
         * @param versionName human-readable version name (e.g., "TLSv1.3")
         * @param supported   true if the server supports this version
         */
        void onVersionProbeResult(String versionName, boolean supported);
    }

    private final String hostname;
    private final ProtocolVersion targetVersion;
    private final String versionName;
    private final VersionProbeListener listener;

    public VersionProbeCallback(IPAddress address, String hostname,
                                ProtocolVersion targetVersion,
                                VersionProbeListener listener) {
        super(address);
        this.hostname = hostname;
        this.targetVersion = targetVersion;
        this.versionName = ProtocolVersionTester.getVersionName(targetVersion);
        this.listener = listener;
    }

    @Override
    protected DefaultTlsClient createTlsClient() {
        return new ProbeVersionTlsClient(hostname, targetVersion);
    }

    @Override
    protected void onProbeSuccess() {
        if (log.isEnabled()) {
            log.getLogger().info("Version probe success: " + versionName);
        }
        listener.onVersionProbeResult(versionName, true);
    }

    @Override
    protected void onProbeFailure(Throwable cause) {
        if (log.isEnabled()) {
            log.getLogger().info("Version probe failure for " + versionName + ": " + cause.getMessage());
        }
        listener.onVersionProbeResult(versionName, false);
    }

    /**
     * Minimal TLS client for version testing.
     */
    private static class ProbeVersionTlsClient extends DefaultTlsClient {
        private final String hostname;
        private final ProtocolVersion targetVersion;

        ProbeVersionTlsClient(String hostname, ProtocolVersion targetVersion) {
            super(new BcTlsCrypto(new SecureRandom()));
            this.hostname = hostname;
            this.targetVersion = targetVersion;
        }

        @Override
        protected Vector<ServerName> getSNIServerNames() {
            // SSLv3 doesn't support SNI
            if (targetVersion.equals(ProtocolVersion.SSLv3)) {
                return null;
            }
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
            if (targetVersion.equals(ProtocolVersion.TLSv13)) {
                return new int[]{
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256
                };
            }
            return new int[]{
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA
            };
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                    // Accept any certificate for version testing
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
