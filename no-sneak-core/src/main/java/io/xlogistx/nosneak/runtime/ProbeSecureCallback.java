package io.xlogistx.nosneak.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.BaseChannelOutputStream;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.ssl.SSLCheckDisabler;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.server.net.ssl.SSLContextInfo;
import org.zoxweb.shared.net.IPAddress;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * A TLS-secured connection within a {@link ProbeContext}, used by the {@code tls-connect}
 * action so that {@code send}/{@code expect} can exchange <em>application data through an
 * established TLS session</em> (e.g. an HTTPS {@code GET} and its {@code Server:} header).
 * <p>
 * Unlike {@link ProbeTCPCallback} (raw channel + Bouncy-Castle handshake), this lets the
 * framework's JSSE stack own the TLS: the base {@link TCPSessionCallback} runs the
 * handshake automatically on connect and delivers <b>decrypted</b> application bytes to
 * {@link #accept(ByteBuffer)}. It does <b>not</b> override {@code accept(SelectionKey)} —
 * the base performs the SSL read+decrypt there. The SSL context is trust-all so ordinary
 * <b>RSA</b> key exchange and any/untrusted certificate complete the handshake — this is
 * service detection, not certificate validation.
 * <p>
 * <b>Which JSSE provider, and why it is named explicitly.</b> {@code SecUtil} registers BCJSSE at
 * provider position 2, so a bare {@code SSLContext.getInstance("TLS")} resolves to Bouncy Castle's
 * JSSE. The {@code bctls-jdk18on} 1.86 artifact is a multi-release jar whose
 * {@code META-INF/versions/9} copy of {@code SSLEngineUtil} declares {@code create(...)} returning
 * {@code ProvSSLEngine} while the base {@code ProvSSLContextSpi} (no versioned copy exists) still
 * calls it with the {@code javax.net.ssl.SSLEngine} descriptor — so on every JDK ≥ 9
 * {@code createSSLEngine(host, port)} throws {@code NoSuchMethodError} (sha1 of the cached jar
 * matches Maven Central; this is the artifact as published). This path only carries application
 * bytes — PQC classification lives on the Bouncy Castle <em>TLS API</em> path in
 * {@link ProbeTCPCallback}, which does not go through JSSE — so the engine is minted from the
 * JDK's own {@code SunJSSE} provider here. {@code BcjsseEngineCreationTest} is the canary: when
 * the bctls artifact is consistent again it fails, and this explicit provider choice can go.
 */
public class ProbeSecureCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeSecureCallback.class).setEnabled(false);

    /** The JDK's JSSE provider; see the class javadoc for why it is named rather than defaulted. */
    static final String JDK_JSSE_PROVIDER = "SunJSSE";

    private final ProbeContext context;
    private final int connectionIndex;

    public ProbeSecureCallback(ProbeContext context, IPAddress address, int connectionIndex,
                               boolean certValidationEnabled)
            throws NoSuchAlgorithmException, KeyManagementException {
        super(address);
        this.context = context;
        this.connectionIndex = connectionIndex;
        // The framework uses the SSLContextInfo address as the connect target, so it must be
        // resolvable (an unresolved address throws UnresolvedAddressException at connect). The
        // IPAddress ctor resolves while retaining the hostname for SNI. Trust-all
        // (certValidationEnabled=false) so ordinary RSA + any/untrusted cert handshakes.
        setSSLContextInfo(new SSLContextInfo(
                jdkTlsContext(certValidationEnabled),
                new InetSocketAddress(address.getInetAddress(), address.getPort())));
    }

    /**
     * An {@code SSLContext} from the JDK's own JSSE provider, trust-all unless
     * {@code certValidationEnabled}. Package-private so the canary test builds exactly what
     * production uses.
     */
    static SSLContext jdkTlsContext(boolean certValidationEnabled)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLS", JDK_JSSE_PROVIDER);
        } catch (NoSuchProviderException e) {
            throw new NoSuchAlgorithmException(JDK_JSSE_PROVIDER + " provider is not available", e);
        }
        ctx.init(null,
                 certValidationEnabled ? null : SSLCheckDisabler.SINGLETON.getTrustManagers(),
                 new SecureRandom());
        return ctx;
    }

    public int connectionIndex() {
        return connectionIndex;
    }

    /**
     * The one "TLS is up" signal, fired exactly once. zoxweb 2.4.0 announces a finished client
     * handshake through {@link #sslUpgraded(SSLConfigInt)} ({@code sslHandshakeSuccessful} no
     * longer calls {@code connectedFinished()}), and {@code connectedFinished()} only when there
     * is no SSL context at all — which never happens here. Both routes funnel into this guard so
     * the probe sees a single {@code connected} outcome whichever the framework chooses.
     */
    private final java.util.concurrent.atomic.AtomicBoolean announced =
            new java.util.concurrent.atomic.AtomicBoolean();

    private void announceSecureConnected() {
        if (announced.compareAndSet(false, true)) {
            context.onSecureConnected(this);
        }
    }

    @Override
    protected void connectedFinished() throws IOException {
        announceSecureConnected();
    }

    @Override
    protected void sslUpgraded(SSLConfigInt sslConfig) throws IOException {
        // Handshake complete: the base has installed the SSL output stream and will deliver
        // decrypted bytes to accept(ByteBuffer) from here on.
        announceSecureConnected();
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Decrypted application data. smartUnwrap leaves this buffer in WRITE mode and never
        // clears it, so we must flip -> drain -> clear it: reading remaining() without flipping
        // would yield free space, and not clearing would overflow the next unwrap.
        if (buffer == null) {
            return;
        }
        ((Buffer) buffer).flip();
        int n = buffer.remaining();
        if (n > 0) {
            byte[] bytes = new byte[n];
            buffer.get(bytes);
            context.onSecureInbound(this, bytes);
        }
        ((Buffer) buffer).clear();
    }

    // Intentionally NOT overriding accept(SelectionKey): in SSL mode the base reads ciphertext
    // and decrypts there, delivering plaintext to accept(ByteBuffer) above.

    @Override
    public void exception(Throwable e) {
        context.onSecureException(this, e);
    }

    /** Encrypt and send application data through the established TLS session. */
    public boolean writeApp(byte[] data) {
        if (data == null) {
            return false;
        }
        BaseChannelOutputStream os = getOutputStream();
        if (os == null) {
            return false;
        }
        try {
            os.write(ByteBuffer.wrap(data), false);
            return true;
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("secure write error: " + e.getMessage());
            return false;
        }
    }
}
