package io.xlogistx.nosneak.v2.analysis;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Integers;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Vector;

/**
 * NIO-based protocol-version probe: connects offering a single TLS/SSL version and
 * reports whether the server accepted it. One independent connection per version — the
 * unit the {@code enumerate-versions} action fans out in parallel.
 */
public class VersionProbeCallback extends TLSProbeCallback {

    public static final LogWrapper log = new LogWrapper(VersionProbeCallback.class).setEnabled(false);

    /** Listener for version probe results. */
    public interface VersionProbeListener {
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
        this.versionName = getVersionName(targetVersion);
        this.listener = listener;
    }

    /** Human-readable protocol-version name. */
    public static String getVersionName(ProtocolVersion v) {
        if (v == null) return "UNKNOWN";
        if (v.equals(ProtocolVersion.TLSv13)) return "TLSv1.3";
        if (v.equals(ProtocolVersion.TLSv12)) return "TLSv1.2";
        if (v.equals(ProtocolVersion.TLSv11)) return "TLSv1.1";
        if (v.equals(ProtocolVersion.TLSv10)) return "TLSv1.0";
        if (v.equals(ProtocolVersion.SSLv3)) return "SSLv3";
        return v.toString();
    }

    @Override
    protected DefaultTlsClient createTlsClient() {
        return new ProbeVersionTlsClient(hostname, targetVersion);
    }

    @Override
    protected void onProbeSuccess() {
        listener.onVersionProbeResult(versionName, true);
    }

    @Override
    protected void onProbeFailure(Throwable cause) {
        if (log.isEnabled()) log.getLogger().info("probe FAIL " + versionName + ": " + cause);
        listener.onVersionProbeResult(versionName, false);
    }

    /** Minimal TLS client restricted to one version. */
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
            if (targetVersion.equals(ProtocolVersion.SSLv3)) {
                return null; // SSLv3 has no SNI
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
        @SuppressWarnings({"rawtypes", "unchecked"})
        protected Vector getSupportedGroups(Vector namedGroupRoles) {
            // Advertise classical named groups so ECDHE cipher suites can negotiate on a
            // strict server (DefaultTlsClient's default omits these for a single version).
            Vector supportedGroups = new Vector();
            supportedGroups.add(Integers.valueOf(NamedGroup.x25519));
            supportedGroups.add(Integers.valueOf(NamedGroup.secp256r1));
            supportedGroups.add(Integers.valueOf(NamedGroup.secp384r1));
            supportedGroups.add(Integers.valueOf(NamedGroup.secp521r1));
            supportedGroups.add(Integers.valueOf(NamedGroup.ffdhe2048));
            supportedGroups.add(Integers.valueOf(NamedGroup.ffdhe3072));
            return supportedGroups;
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
                    // Accept any certificate for version testing.
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
