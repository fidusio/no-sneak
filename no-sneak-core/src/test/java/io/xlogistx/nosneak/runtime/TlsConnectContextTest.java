package io.xlogistx.nosneak.runtime;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SecUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code tls-connect} path takes its {@code SSLContext} from whatever provider the JCA
 * resolves for {@code "TLS"} — with {@link SecUtil}'s registration that is BCJSSE. Until
 * 2026-09-20 the provider was pinned to SunJSSE because the published {@code bctls} 1.86 jar
 * could not mint an {@code SSLEngine} on JDK ≥ 9 (PENDING-ISSUES P23); a canary test guarded the
 * pin and fired once a consistent jar was on the classpath. This replaces both: it pins the one
 * fact production depends on, that the default context mints a client engine, in both trust
 * modes, and names the provider in the failure so a broken jar is recognised at once.
 */
public class TlsConnectContextTest {

    static {
        // What the application does at start-up: SecUtil's static initialiser registers Bouncy
        // Castle (position 1) and BCJSSE (position 2) with the JCA.
        try {
            Class.forName(SecUtil.class.getName());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void theDefaultProviderMintsTheClientEngineTlsConnectUses() throws Exception {
        SSLContext ctx = ProbeSecureCallback.tlsContext(false);
        SSLEngine engine = ctx.createSSLEngine("example.invalid", 443);
        assertNotNull(engine, "provider " + ctx.getProvider().getName() + " could not mint an engine");
        engine.setUseClientMode(true);
        assertTrue(engine.getUseClientMode());
        assertTrue(engine.getSupportedProtocols().length > 0, ctx.getProvider().getName());
    }

    @Test
    public void certValidationEnabledMintsAnEngineToo() throws Exception {
        SSLContext ctx = ProbeSecureCallback.tlsContext(true);
        assertNotNull(ctx.createSSLEngine(), "provider " + ctx.getProvider().getName());
    }
}
