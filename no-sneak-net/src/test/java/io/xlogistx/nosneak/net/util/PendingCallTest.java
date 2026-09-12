package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.PingError;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** One ping() call's probes settle EXACTLY ONCE each, whichever thread arrives second. */
public class PendingCallTest {

    private static final InetAddress TARGET = InetAddress.ofLiteral("10.0.0.7");

    /**
     * §13.23-E: a probe registered but never sent (its sender threw before the deadline was
     * armed) must not leave the call incomplete forever. failRemaining closes it and the
     * slot that was never registered at all.
     */
    @Test
    public void aCallWhoseProbeWasNeverSentStillCompletes() {
        PendingCall call = new PendingCall(TARGET, 3);
        PendingCall.Probe sent = call.newProbe(1, 0);
        PendingCall.Probe neverSent = call.newProbe(2, 0);   // registered, then the sender threw
        assertTrue(sent.settle(PingProbe.replied(1, Duration.ofMillis(3))));
        assertFalse(call.future.isDone(), "two slots are still open");

        call.failRemaining(PingError.IO, "scheduler refused the deadline");

        assertTrue(call.future.isDone());
        assertTrue(neverSent.isSettled());
        PingResult r = call.future.join();
        assertEquals(3, r.sent());
        assertEquals(1, r.received());
        assertEquals(List.of(PendingCall.NEVER_SENT, 1, 2),
                     r.probes().stream().map(PingProbe::sequence).toList());
        assertEquals(Optional.of(PingError.IO), r.probes().get(0).error(), "the never-registered slot");
        assertEquals(Optional.of(PingError.IO), r.probes().get(2).error(), "the registered-but-unsent probe");
        assertEquals(Optional.of("scheduler refused the deadline"), r.detail());
        assertEquals(2, call.registeredCount());
    }

    /** The aggregate completes exactly when the last of {@code expected} settles, in any order. */
    @Test
    public void completesExactlyWhenTheLastOfExpectedSettlesRegardlessOfOrder() {
        PendingCall call = new PendingCall(TARGET, 3);
        call.settleUnsent(PingProbe.failed(9, PingError.IO));          // unsent first
        assertFalse(call.future.isDone());
        PendingCall.Probe a = call.newProbe(1, 0);
        PendingCall.Probe b = call.newProbe(2, 0);
        assertTrue(b.fail(PingError.TIMEOUT));                          // later probe first
        assertFalse(call.future.isDone(), "one slot still open");
        assertTrue(a.settle(PingProbe.replied(1, Duration.ofMillis(1))));
        assertTrue(call.future.isDone());
        assertEquals(List.of(1, 2, 9), call.future.join().probes().stream().map(PingProbe::sequence).toList());
    }

    @Test
    public void failRemainingIsIdempotentAndNeverOvercounts() {
        PendingCall call = new PendingCall(TARGET, 2);
        call.newProbe(1, 0);
        call.failRemaining(PingError.IO, "first");
        call.failRemaining(PingError.TIMEOUT, "second");
        PingResult r = call.future.join();
        assertEquals(2, r.probes().size(), "a second failRemaining adds nothing");
        assertEquals(Optional.of("first"), r.detail(), "first detail wins");
        assertTrue(r.probes().stream().allMatch(p -> p.error().equals(Optional.of(PingError.IO))));
    }

    /** Still through the completer, never on the aborting thread (§13.23-D). */
    @Test
    public void failRemainingCompletesOnTheCompleter() throws Exception {
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors
                .newSingleThreadExecutor(r -> new Thread(r, "completer"));
        try {
            PendingCall call = new PendingCall(TARGET, 1, pool);
            java.util.concurrent.CompletableFuture<String> where =
                    call.future.thenApply(r -> Thread.currentThread().getName());
            call.failRemaining(PingError.IO, null);
            assertEquals("completer", where.get(2, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    /** The S13 regression: close() and the timeout task both settling probe A. */
    @Test
    public void aProbeSettledTwiceCountsOnce() {
        PendingCall call = new PendingCall(TARGET, 3);
        PendingCall.Probe a = call.newProbe(1, 0);
        PendingCall.Probe b = call.newProbe(2, 0);
        PendingCall.Probe c = call.newProbe(3, 0);

        assertTrue(a.fail(PingError.IO));
        assertFalse(a.fail(PingError.TIMEOUT), "second settlement of A is a no-op");
        assertTrue(b.fail(PingError.TIMEOUT));
        assertFalse(call.future.isDone(), "[A, A, B] must NOT complete the call");

        assertTrue(c.settle(PingProbe.replied(3, Duration.ofMillis(5))));
        PingResult r = call.future.join();
        assertEquals(3, r.sent());
        assertEquals(1, r.received());
        assertEquals(List.of(1, 2, 3), r.probes().stream().map(PingProbe::sequence).toList());
        assertEquals(Optional.of(PingError.IO), r.probes().get(0).error());
    }

    @Test
    public void completesOnlyWhenEveryProbeHasSettled() {
        PendingCall call = new PendingCall(TARGET, 2);
        PendingCall.Probe a = call.newProbe(1, 0);
        call.newProbe(2, 0);
        a.settle(PingProbe.replied(1, Duration.ofMillis(1)));
        assertFalse(call.future.isDone());
        call.settleUnsent(PingProbe.failed(2, PingError.PERMISSION));
        assertTrue(call.future.isDone());
        assertEquals(1, call.future.join().received());
    }

    @Test
    public void probesAreOrderedBySequence() {
        PendingCall call = new PendingCall(TARGET, 3);
        PendingCall.Probe a = call.newProbe(7, 0);
        PendingCall.Probe b = call.newProbe(5, 0);
        PendingCall.Probe c = call.newProbe(6, 0);
        a.fail(PingError.TIMEOUT);
        c.fail(PingError.TIMEOUT);
        b.fail(PingError.TIMEOUT);
        assertEquals(List.of(5, 6, 7), call.future.join().probes().stream()
                                          .map(PingProbe::sequence).toList());
    }

    @Test
    public void settleCancelsTheExpiry() throws Exception {
        ScheduledThreadPoolExecutor pool = new ScheduledThreadPoolExecutor(1);
        try {
            PendingCall call = new PendingCall(TARGET, 1);
            PendingCall.Probe a = call.newProbe(1, 0);
            ScheduledFuture<?> expiry = pool.schedule(() -> a.fail(PingError.TIMEOUT), 10, java.util.concurrent.TimeUnit.SECONDS);
            a.expiry = expiry;
            assertTrue(a.settle(PingProbe.replied(1, Duration.ofMillis(2))));
            assertTrue(expiry.isCancelled());
            assertTrue(a.isSettled());
            assertEquals(1, call.future.join().received());
        } finally {
            pool.shutdownNow();
        }
    }

    /** The reader's cause of death rides on the aggregate as an IO error with text (§4.7). */
    @Test
    public void detailReachesTheAggregate() {
        PendingCall call = new PendingCall(TARGET, 2);
        PendingCall.Probe a = call.newProbe(1, 0);
        PendingCall.Probe b = call.newProbe(2, 0);
        call.setDetail("recvfrom: EBADF");
        call.setDetail("later, vaguer");
        a.fail(PingError.IO);
        b.fail(PingError.IO);
        PingResult r = call.future.join();
        assertEquals(Optional.of(PingError.IO), r.error());
        assertEquals(Optional.of("recvfrom: EBADF"), r.detail());
    }

    @Test
    public void aCallWithoutDetailHasNoCallLevelError() {
        PendingCall call = new PendingCall(TARGET, 1);
        call.newProbe(1, 0).fail(PingError.TIMEOUT);
        PingResult r = call.future.join();
        assertTrue(r.error().isEmpty());
        assertTrue(r.detail().isEmpty());
    }
}
