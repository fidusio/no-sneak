package io.xlogistx.nosneak.v2.runtime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.ssl.SSLCheckDisabler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the {@code tls-connect} engine source and the defect it works around
 * ({@code PENDING-ISSUES.md} P23). No network: an {@link SSLEngine} is minted, never handshaken.
 * <p>
 * The second test is a <b>canary</b>: it asserts that the cached {@code bctls-jdk18on} artifact
 * still cannot mint an engine on this JDK. The day a consistent bctls lands, that test fails —
 * which is the signal to drop {@link ProbeSecureCallback#JDK_JSSE_PROVIDER} and let the
 * framework's default provider order stand again.
 */
public class BcjsseEngineCreationTest {

    @Test
    public void theJdkProviderMintsTheClientEngineTlsConnectUses() throws Exception {
        SSLContext ctx = ProbeSecureCallback.jdkTlsContext(false);
        assertEquals(ProbeSecureCallback.JDK_JSSE_PROVIDER, ctx.getProvider().getName());

        SSLEngine engine = ctx.createSSLEngine("example.invalid", 443);
        assertNotNull(engine);
        assertEquals("example.invalid", engine.getPeerHost());
        assertEquals(443, engine.getPeerPort());
        assertTrue(engine.getSupportedProtocols().length > 0);
    }

    @Test
    public void certValidationEnabledStillUsesTheJdkProvider() throws Exception {
        SSLContext ctx = ProbeSecureCallback.jdkTlsContext(true);
        assertEquals(ProbeSecureCallback.JDK_JSSE_PROVIDER, ctx.getProvider().getName());
        assertNotNull(ctx.createSSLEngine());
    }

    /**
     * CANARY — documents the bctls defect this class works around. bctls-jdk18on 1.86 is a
     * multi-release jar whose {@code versions/9/.../SSLEngineUtil} returns {@code ProvSSLEngine}
     * while the base {@code ProvSSLContextSpi} calls it with the {@code javax.net.ssl.SSLEngine}
     * descriptor. When this assertion fails, the artifact on the classpath is consistent: remove
     * the explicit provider in {@link ProbeSecureCallback#jdkTlsContext} and delete this test.
     */
    @Test
    public void bcjsseOnThisClasspathCannotMintAnEngine_removeWorkaroundWhenThisFails() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCJSSE") == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
        SSLContext bc = SSLContext.getInstance("TLS", "BCJSSE");
        bc.init(null, SSLCheckDisabler.SINGLETON.getTrustManagers(), new SecureRandom());

        assertThrows(NoSuchMethodError.class, () -> bc.createSSLEngine("example.invalid", 443),
                "bctls now mints engines: drop ProbeSecureCallback.JDK_JSSE_PROVIDER and this canary");
    }
}
