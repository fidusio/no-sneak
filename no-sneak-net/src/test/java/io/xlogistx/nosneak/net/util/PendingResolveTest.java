package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveResult;
import io.xlogistx.nosneak.net.common.ResolveSource;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The shared in-flight resolve: one future for all callers, one send error per resolve. */
public class PendingResolveTest {

    private static final InetAddress TARGET = InetAddress.ofLiteral("10.0.0.7");

    @Test
    public void expireWithoutSendErrorIsTimeout() {
        Instant t0 = Instant.parse("2026-09-11T10:00:00Z");
        PendingResolve p = new PendingResolve(TARGET, t0);
        ResolveResult r = p.expire(t0.plusMillis(1000));
        assertEquals(ResolveOutcome.TIMEOUT, r.outcome());
        assertEquals(Duration.ofMillis(1000), r.elapsed());
        assertTrue(r.detail().isEmpty());
    }

    @Test
    public void expireAfterSendErrorIsErrorWithText() {
        PendingResolve p = new PendingResolve(TARGET);
        p.recordSendError("pcap_sendpacket on en0: send error: Operation not permitted");
        ResolveResult r = p.expire(Instant.now());
        assertEquals(ResolveOutcome.ERROR, r.outcome());
        assertEquals(Optional.of("pcap_sendpacket on en0: send error: Operation not permitted"),
                     r.detail());
    }

    @Test
    public void firstSendErrorWins() {
        PendingResolve p = new PendingResolve(TARGET);
        p.recordSendError(null);
        assertNull(p.sendError());
        p.recordSendError("first");
        p.recordSendError("second");
        assertEquals("first", p.sendError());
    }

    /** Pins the javadoc claim every backend used to carry: a caller cannot complete everyone. */
    @Test
    public void awaitIsACopySoACallerCannotCompleteEveryoneElse() {
        PendingResolve p = new PendingResolve(TARGET);
        CompletableFuture<ResolveResult> a = p.await();
        CompletableFuture<ResolveResult> b = p.await();

        a.complete(ResolveResult.notResolved(TARGET, ResolveOutcome.ERROR, Duration.ZERO, "rogue"));
        assertFalse(b.isDone(), "completing one caller's copy must not complete the others");
        assertFalse(p.isDone());

        ResolveResult real = ResolveResult.resolved(TARGET, MacAddress.parse("aa:bb:cc:dd:ee:ff"),
                                                    ResolveSource.ACTIVE_ARP, Duration.ofMillis(3));
        assertTrue(p.completeAll(real));
        assertEquals(real, b.join());
        assertTrue(p.isDone());
    }

    @Test
    public void completeAllIsIdempotent() {
        PendingResolve p = new PendingResolve(TARGET);
        ResolveResult first = p.abort("closed");
        assertTrue(p.completeAll(first));
        assertFalse(p.completeAll(p.expire(Instant.now())));
        assertEquals(first, p.await().join());
        assertEquals(ResolveOutcome.ERROR, first.outcome());
        assertEquals(Optional.of("closed"), first.detail());
    }
}
