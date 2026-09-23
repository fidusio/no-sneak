package io.xlogistx.nosneak.runtime;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.net.IPAddress;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    // ---- the connect address zoxweb mints the engine from (2026-09-22) ------------------------
    // SSLContextInfo.newInstance() calls clientAddress.getHostName(); on an address resolved from
    // an IP literal that is a reverse DNS lookup (4.6 s on the maintainer's segment for an address
    // without a PTR record), paid between the TCP connect and the ClientHello, inside the probe's
    // one timeoutSec window. The callback pins the host string as the address's name so the call
    // answers from memory. 192.0.2.1 is TEST-NET-1: never routable, never has a PTR record, so an
    // unpinned address would reverse-resolve (and time out) here — the time bound is the pin.

    private static final long PINNED_BUDGET_MS = 1_000;

    @Test
    public void anIpLiteralTargetCarriesItsOwnNameSoTheEngineNeverReverseResolvesIt() throws Exception {
        long t0 = System.nanoTime();
        ProbeSecureCallback cb = new ProbeSecureCallback(null, new IPAddress("192.0.2.1", 443), 1, false);
        InetSocketAddress a = cb.getSSLContextInfo().getClientAddress();
        String name = a.getHostName();
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertFalse(a.isUnresolved(), "the framework connects to this address, it must be resolved");
        assertEquals("192.0.2.1", name);
        assertEquals("192.0.2.1", a.getAddress().getHostAddress());
        assertEquals(443, a.getPort());
        assertTrue(ms < PINNED_BUDGET_MS, "getHostName() took " + ms + " ms: the literal was not pinned");
    }

    @Test
    public void aNamedTargetKeepsItsNameForSni() {
        InetSocketAddress a = ProbeSecureCallback.namedAddress("localhost", 8443);
        assertFalse(a.isUnresolved());
        assertEquals("localhost", a.getHostName());
        assertEquals(8443, a.getPort());
    }

    @Test
    public void anUnresolvableTargetStaysUnresolvedSoTheConnectFailsAsBefore() {
        InetSocketAddress a = ProbeSecureCallback.namedAddress("no-such-host.invalid", 443);
        assertTrue(a.isUnresolved());
        assertEquals("no-such-host.invalid", a.getHostString());
    }
}
