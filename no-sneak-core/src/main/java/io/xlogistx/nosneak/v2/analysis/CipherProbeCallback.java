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
 * NIO-based cipher-suite probe: connects offering a specific cipher set at a given version
 * and reports which cipher the server selected (or {@code null} if none accepted). One
 * independent connection per candidate cipher — the unit {@code enumerate-ciphers} fans out
 * in parallel.
 */
public class CipherProbeCallback extends TLSProbeCallback {

    public static final LogWrapper log = new LogWrapper(CipherProbeCallback.class).setEnabled(false);

    /** Listener for cipher probe results. */
    public interface CipherProbeListener {
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
        listener.onCipherProbeResult(targetVersion, selectedCipherSuite);
    }

    @Override
    protected void onProbeFailure(Throwable cause) {
        // null signals the server did not accept the offered cipher(s).
        listener.onCipherProbeResult(targetVersion, null);
    }

    /** Minimal TLS client for cipher enumeration. */
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
        @SuppressWarnings({"rawtypes", "unchecked"})
        protected Vector getSupportedGroups(Vector namedGroupRoles) {
            // Advertise classical named groups so ECDHE ciphers can negotiate on strict servers.
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
                    // Accept any certificate for enumeration.
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
