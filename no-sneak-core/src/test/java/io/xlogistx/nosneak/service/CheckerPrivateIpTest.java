package io.xlogistx.nosneak.service;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.http.HTTPStatusCode;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins {@link Checker.TargetGuard}: the addresses the old string-prefix guard let through are
 * now refused, and public addresses still pass. Literals only — no DNS.
 */
public class CheckerPrivateIpTest {

    private static boolean priv(String literal) throws Exception {
        return Checker.TargetGuard.isPrivate(InetAddress.getByName(literal));
    }

    @Test
    public void theAddressesTheOldGuardMissedAreRefused() throws Exception {
        assertTrue(priv("127.0.0.1"), "loopback");
        assertTrue(priv("169.254.169.254"), "link-local / cloud metadata");
        assertTrue(priv("::1"), "IPv6 loopback");
        assertTrue(priv("[::1]"), "bracketed IPv6 loopback");
        assertTrue(priv("fe80::1"), "IPv6 link-local");
        assertTrue(priv("fd00::1"), "ULA");
        assertTrue(priv("fc00::1"), "ULA, low half");
        assertTrue(priv("0.0.0.0"), "unspecified");
        assertTrue(priv("::"), "IPv6 unspecified");
        assertTrue(priv("224.0.0.251"), "multicast");
        assertTrue(priv("ff02::fb"), "IPv6 multicast");
        assertTrue(priv("100.64.0.1"), "shared address space");
    }

    @Test
    public void theClassicPrivateRangesAreStillRefused() throws Exception {
        assertTrue(priv("10.1.2.3"));
        assertTrue(priv("172.16.0.1"));
        assertTrue(priv("172.31.0.1"));
        assertTrue(priv("192.168.56.1"));
    }

    @Test
    public void publicAddressesPass() throws Exception {
        assertFalse(priv("8.8.8.8"));
        assertFalse(priv("2001:4860:4860::8888"));
        assertFalse(priv("172.32.0.1"), "just outside 172.16/12");
        assertFalse(priv("100.128.0.1"), "just outside 100.64/10");
        assertFalse(priv("11.0.0.1"), "just outside 10/8");
    }

    @Test
    public void aLiteralIsCheckedWithoutDns() {
        Checker.TargetGuard.Rejection r = Checker.TargetGuard.check("127.0.0.1");
        assertNotNull(r);
        assertEquals(HTTPStatusCode.UNAUTHORIZED, r.status());
        assertTrue(r.message().contains("127.0.0.1"));

        assertNull(Checker.TargetGuard.check("8.8.8.8"));
    }

    @Test
    public void anEmptyTargetIsABadRequest() {
        Checker.TargetGuard.Rejection r = Checker.TargetGuard.check("  ");
        assertNotNull(r);
        assertEquals(HTTPStatusCode.BAD_REQUEST, r.status());
    }

    @Test
    public void nullIsPrivate() {
        assertTrue(Checker.TargetGuard.isPrivate(null));
    }
}
