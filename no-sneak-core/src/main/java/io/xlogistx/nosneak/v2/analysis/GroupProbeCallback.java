package io.xlogistx.nosneak.v2.analysis;

import io.xlogistx.nosneak.v2.tls.PQCTlsClient;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NameType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Integers;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;
import java.util.concurrent.ScheduledExecutorService;

/**
 * NIO-based named-group probe: one TLS 1.3 handshake that offers <b>exactly one</b> named group
 * in {@code supported_groups} and {@code key_share}, and reports whether the server completed
 * the handshake on it. One independent connection per candidate group — the unit
 * {@code enumerate-groups} fans out in parallel (A12: the scanner used to advertise its own
 * groups and never learn the server's accepted set).
 * <p>
 * This is an ordinary ClientHello with a narrower offer; a server that does not support the
 * group answers with a handshake_failure alert or a HelloRetryRequest naming a group we did not
 * offer, and either ends the handshake as "not accepted". Nothing beyond a handshake is sent.
 */
public class GroupProbeCallback extends TLSProbeCallback {

    public static final LogWrapper log = new LogWrapper(GroupProbeCallback.class).setEnabled(false);

    /**
     * The groups this probe offers, best first. Hybrids are listed before the classical curves
     * so the recorded order reads PQC → ECDHE → FFDHE. Every entry is one Bouncy Castle can
     * originate a key share for on plain {@code BcTlsCrypto} (the same crypto
     * {@code PQCTlsClient} uses for the main handshake).
     */
    public static final int[] CANDIDATE_GROUPS = {
            NamedGroup.X25519MLKEM768,
            NamedGroup.SecP256r1MLKEM768,
            NamedGroup.SecP384r1MLKEM1024,
            NamedGroup.x25519,
            NamedGroup.x448,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
            NamedGroup.secp521r1,
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072
    };

    /** Listener for a single group probe. */
    public interface GroupProbeListener {
        /**
         * @param namedGroup the group that was offered
         * @param accepted   true when the server completed a TLS 1.3 handshake on that group
         */
        void onGroupProbeResult(int namedGroup, boolean accepted);
    }

    private final String hostname;
    private final int namedGroup;
    private final GroupProbeListener listener;
    private volatile int serverKeyShareGroup;

    public GroupProbeCallback(ScheduledExecutorService scheduler, IPAddress address, String hostname,
                              int namedGroup, GroupProbeListener listener) {
        super(scheduler, address);
        this.hostname = hostname;
        this.namedGroup = namedGroup;
        this.listener = listener;
    }

    /** IANA-style name of a candidate, shared with the main handshake's naming. */
    public static String groupName(int namedGroup) {
        return PQCTlsClient.getNamedGroupName(namedGroup);
    }

    /** True for the ML-KEM hybrids — the groups a PQC-ready server must accept at least one of. */
    public static boolean isPqcHybrid(int namedGroup) {
        return namedGroup == NamedGroup.X25519MLKEM768
                || namedGroup == NamedGroup.SecP256r1MLKEM768
                || namedGroup == NamedGroup.SecP384r1MLKEM1024;
    }

    @Override
    protected void sslUpgraded(SSLConfigInt sslConfig) throws IOException {
    }

    @Override
    protected DefaultTlsClient createTlsClient() {
        return new SingleGroupTlsClient(hostname, namedGroup);
    }

    @Override
    protected void onProbeSuccess() {
        // The handshake completed and we offered one group, so the server used it. The
        // key_share we saw is checked defensively: a server that answered with a different
        // group would not have completed against BC, but the record must never lie.
        boolean sameGroup = serverKeyShareGroup == 0 || serverKeyShareGroup == namedGroup;
        listener.onGroupProbeResult(namedGroup, sameGroup);
    }

    @Override
    protected void onProbeFailure(Throwable cause) {
        if (log.isEnabled()) log.getLogger().info("group " + groupName(namedGroup) + " rejected: " + cause);
        listener.onGroupProbeResult(namedGroup, false);
    }

    /** Minimal TLS 1.3 client that offers a single named group. */
    private class SingleGroupTlsClient extends DefaultTlsClient {
        private final String hostname;
        private final int group;

        SingleGroupTlsClient(String hostname, int group) {
            super(new BcTlsCrypto(new SecureRandom()));
            this.hostname = hostname;
            this.group = group;
        }

        @Override
        protected Vector<ServerName> getSNIServerNames() {
            Vector<ServerName> serverNames = new Vector<>();
            serverNames.add(new ServerName(NameType.host_name, hostname.getBytes(StandardCharsets.US_ASCII)));
            return serverNames;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[]{ProtocolVersion.TLSv13};
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        protected Vector getSupportedGroups(Vector namedGroupRoles) {
            Vector supportedGroups = new Vector();
            supportedGroups.add(Integers.valueOf(group));
            return supportedGroups;
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256
            };
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public void processServerExtensions(Hashtable serverExtensions) throws IOException {
            super.processServerExtensions(serverExtensions);
            if (serverExtensions == null) {
                return;
            }
            try {
                KeyShareEntry entry = TlsExtensionsUtils.getKeyShareServerHello(serverExtensions);
                if (entry != null) {
                    serverKeyShareGroup = entry.getNamedGroup();
                }
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("key_share not readable: " + e.getMessage());
            }
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                    // Accept any certificate: this probe measures key exchange, not trust.
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }
}
