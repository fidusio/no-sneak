package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The {@code detail} channel (§4.7): the only way native error text reaches a caller. */
public class ResolveResultTest {

    private static final InetAddress TARGET = InetAddress.ofLiteral("10.0.0.7");

    @Test
    public void detailIsEmptyByDefault() {
        ResolveResult r = ResolveResult.notResolved(TARGET, ResolveOutcome.TIMEOUT, Duration.ofSeconds(1));
        assertTrue(r.detail().isEmpty());
        assertNull(r.source());
        assertFalse(r.resolved());

        ResolveResult ok = ResolveResult.resolved(TARGET, MacAddress.parse("aa:bb:cc:dd:ee:ff"),
                                                  ResolveSource.ACTIVE_ARP, Duration.ofMillis(3));
        assertTrue(ok.detail().isEmpty());
        assertTrue(ok.resolved());
    }

    @Test
    public void notResolvedCarriesDetail() {
        ResolveResult r = ResolveResult.notResolved(TARGET, ResolveOutcome.ERROR,
                                                    Duration.ofMillis(5), "pcap_sendpacket: send error");
        assertEquals(ResolveOutcome.ERROR, r.outcome());
        assertEquals(Optional.of("pcap_sendpacket: send error"), r.detail());
    }

    @Test
    public void nullDetailIsCanonicalisedToEmpty() {
        ResolveResult r = new ResolveResult(TARGET, null, ResolveOutcome.TIMEOUT, null,
                                            Duration.ZERO, null);
        assertTrue(r.detail().isEmpty());
        assertTrue(r.mac().isEmpty());
        assertEquals(r, ResolveResult.notResolved(TARGET, ResolveOutcome.TIMEOUT, Duration.ZERO, null));
    }
}
