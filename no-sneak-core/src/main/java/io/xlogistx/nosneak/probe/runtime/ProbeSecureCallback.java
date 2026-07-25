package io.xlogistx.nosneak.probe.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.BaseChannelOutputStream;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.ssl.SSLContextInfo;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * A TLS-secured connection within a {@link ProbeSession}, used by the
 * {@code tls-connect} action so that {@code send}/{@code expect} can exchange
 * <em>application data through an established TLS session</em> (e.g. an HTTPS
 * {@code GET} and its {@code Server:} response header).
 * <p>
 * Unlike {@link ProbeTCPCallback} (which drives a raw plaintext channel and a
 * Bouncy-Castle handshake), this callback lets the framework's JSSE stack own the
 * TLS: the base {@link TCPSessionCallback} runs the handshake automatically on
 * connect and then delivers <b>decrypted</b> application bytes to
 * {@link #accept(ByteBuffer)}. Crucially it does <b>not</b> override
 * {@code accept(SelectionKey)} — the base performs the SSL read+decrypt there.
 * The SSL context is trust-all ({@code certValidationEnabled=false}) so ordinary
 * RSA key exchange and any/untrusted certificate complete the handshake — this is
 * service detection, not certificate validation.
 */
public class ProbeSecureCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeSecureCallback.class).setEnabled(false);

    private final ProbeSession session;
    private final int connectionIndex;

    public ProbeSecureCallback(ProbeSession session, IPAddress address, int connectionIndex,
                               boolean certValidationEnabled)
            throws NoSuchAlgorithmException, KeyManagementException {
        super(address);
        this.session = session;
        this.connectionIndex = connectionIndex;
        // The framework uses the SSLContextInfo address as the connect target, so it must be
        // resolvable (an unresolved address throws UnresolvedAddressException at connect). The
        // IPAddress ctor resolves while retaining the hostname for SNI. Trust-all
        // (certValidationEnabled=false) so ordinary RSA + any/untrusted cert handshakes — this
        // is service detection, not certificate validation.
        setSSLContextInfo(new SSLContextInfo(address, certValidationEnabled));
    }

    public int connectionIndex() {
        return connectionIndex;
    }

    @Override
    protected void connectedFinished() throws IOException {
        // Base class runs sslUpgrade() before this, so connectedFinished fires only
        // after a successful TLS handshake (see TCPSessionCallback.connected/sslUpgrade).
        session.onSecureConnected(this);
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Decrypted application data handed up by the TLS layer. smartUnwrap leaves this
        // buffer in WRITE mode (position = end of plaintext) and never clears it, so we must
        // flip → drain → clear it: reading remaining() without flipping would yield free space,
        // and not clearing would overflow the next unwrap (NOT_HANDSHAKING BUFFER_OVERFLOW).
        if (buffer == null) {
            return;
        }
        ((Buffer) buffer).flip();
        int n = buffer.remaining();
        if (n > 0) {
            byte[] bytes = new byte[n];
            buffer.get(bytes);
            session.onSecureInbound(this, bytes);
        }
        ((Buffer) buffer).clear();
    }

    // Intentionally NOT overriding accept(SelectionKey): in SSL mode the base class reads
    // ciphertext and decrypts there, delivering plaintext to accept(ByteBuffer) above.

    @Override
    public void exception(Throwable e) {
        session.onSecureException(this, e);
    }

    /**
     * Encrypt and send application data through the established TLS session.
     *
     * @return {@code true} if written; {@code false} on a null payload/stream or a write failure.
     */
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
