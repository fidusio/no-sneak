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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
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
 * <b>Which JSSE provider.</b> Whichever the JCA resolves for {@code "TLS"} — with {@code SecUtil}'s
 * registration that is BCJSSE at position 2. Between 2026-09-11 and 2026-09-20 the engine was
 * pinned to the JDK's {@code SunJSSE} because the {@code bctls-jdk18on} 1.86 jar as published
 * could not mint an {@code SSLEngine} on JDK ≥ 9 (inconsistent multi-release copies of
 * {@code SSLEngineUtil}; PENDING-ISSUES P23). The classpath has since moved to a consistent
 * {@code bctls}, the canary test that guarded the pin fired, and the pin was removed at the
 * maintainer's request. This path only carries application bytes; PQC classification lives on
 * the Bouncy Castle <em>TLS API</em> path in {@link ProbeTCPCallback} and never went through JSSE.
 * {@code TlsConnectContextTest} pins that the default provider mints the engine this path uses.
 */
public class ProbeSecureCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeSecureCallback.class).setEnabled(false);

    private final ProbeContext context;
    private final int connectionIndex;

    public ProbeSecureCallback(ProbeContext context, IPAddress address, int connectionIndex,
                               boolean certValidationEnabled)
            throws NoSuchAlgorithmException, KeyManagementException {
        super(address);
        this.context = context;
        this.connectionIndex = connectionIndex;
        // The framework uses the SSLContextInfo address as the connect target, so it must be
        // resolved (an unresolved address throws UnresolvedAddressException at connect) — and it
        // must carry a host name, see namedAddress(). Trust-all (certValidationEnabled=false) so
        // ordinary RSA + any/untrusted cert handshakes.
        setSSLContextInfo(new SSLContextInfo(
                tlsContext(certValidationEnabled),
                namedAddress(address.getInetAddress(), address.getPort())));
    }

    /**
     * The connect address for the framework: resolved once, with {@code host} pinned as the
     * {@link InetAddress}'s host name.
     * <p>
     * zoxweb mints the engine with {@code createSSLEngine(clientAddress.getHostName(), port)}
     * ({@code SSLContextInfo.newInstance()}). On an {@code InetAddress} that was resolved from
     * an IP literal, {@code getHostName()} is a <b>reverse DNS lookup</b> — on the maintainer's
     * segment that costs 4.6 s for an address without a PTR record, spent between the TCP
     * connect and the ClientHello, inside this probe's single {@code timeoutSec} window. Against
     * 10.0.0.8 (TLS 1.2, 22 KB server flight) the handshake then reached ServerKeyExchange
     * exactly as the 5 s deadline closed the engine, and {@code https-scan} recorded
     * {@code no-server-header} on a host that answers in 0.5 s (2026-09-22). A name-resolved
     * target never pays it because the resolver already stored the name on the address.
     * {@link InetAddress#getByAddress(String, byte[])} stores {@code host} the same way, so
     * {@code getHostName()} answers from memory for literals and names alike, and the SNI the
     * engine sends is unchanged (a literal was never a valid server name; a name is kept).
     * An unresolvable {@code host} yields the same unresolved address the plain constructor
     * used to, so the connect still fails the same way.
     */
    static InetSocketAddress namedAddress(String host, int port) {
        try {
            InetAddress resolved = InetAddress.getByName(host);
            return new InetSocketAddress(InetAddress.getByAddress(host, resolved.getAddress()), port);
        } catch (UnknownHostException e) {
            return InetSocketAddress.createUnresolved(host, port);
        }
    }

    /**
     * The {@code SSLContext} this path talks through: the JCA's default {@code "TLS"} provider,
     * trust-all unless {@code certValidationEnabled}. Package-private so the test builds exactly
     * what production uses.
     */
    static SSLContext tlsContext(boolean certValidationEnabled)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = SSLContext.getInstance("TLS");
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
