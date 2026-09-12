package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins §13.23-D: a reader thread that completes a resolve or a ping never runs the
 * caller's continuation, and a slow continuation cannot hold the reader up. The "reader"
 * here is an ordinary named thread; the completer is a two-thread pool standing in for the
 * injected dispatcher.
 */
public class CompletionThreadTest {

    private static final InetAddress A = InetAddress.ofLiteral("10.0.0.1");
    private static final InetAddress B = InetAddress.ofLiteral("10.0.0.2");

    private ExecutorService completer;

    @AfterEach
    public void shutdown() {
        if (completer != null) {
            completer.shutdownNow();
        }
    }

    private ExecutorService pool(int threads) {
        completer = Executors.newFixedThreadPool(threads, r -> new Thread(r, "completer"));
        return completer;
    }

    @Test
    public void aResolveContinuationRunsOnTheCompleterNotTheReader() throws Exception {
        PendingResolve p = new PendingResolve(A, pool(1));
        CompletableFuture<String> where = p.await().thenApply(r -> Thread.currentThread().getName());

        Thread reader = new Thread(() -> p.completeAll(
                ResolveResult.notResolved(A, ResolveOutcome.TIMEOUT, Duration.ZERO)), "reader");
        reader.start();
        reader.join(2_000);

        assertEquals("completer", where.get(2, TimeUnit.SECONDS));
    }

    @Test
    public void aPingContinuationRunsOnTheCompleterNotTheReader() throws Exception {
        PendingCall call = new PendingCall(A, 1, pool(1));
        PendingCall.Probe probe = call.newProbe(0, System.nanoTime());
        CompletableFuture<String> where = call.future.thenApply(r -> Thread.currentThread().getName());

        Thread reader = new Thread(() -> probe.settle(PingProbe.failed(0,
                io.xlogistx.nosneak.net.common.PingError.TIMEOUT)), "reader");
        reader.start();
        reader.join(2_000);

        assertEquals("completer", where.get(2, TimeUnit.SECONDS));
    }

    /**
     * The failure this exists to prevent: with inline completion, a continuation that sleeps
     * 300 ms holds the reader for 300 ms, and the second host's reply is not processed until
     * it wakes. Here the reader must finish both completions in a few milliseconds and B must
     * be observable long before A's continuation has finished sleeping.
     */
    @Test
    public void aSlowContinuationDoesNotHoldTheReaderUp() throws Exception {
        ExecutorService pool = pool(2);
        PendingResolve a = new PendingResolve(A, pool);
        PendingResolve b = new PendingResolve(B, pool);
        CountDownLatch slowStarted = new CountDownLatch(1);
        a.await().thenAccept(r -> {
            slowStarted.countDown();
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        CompletableFuture<ResolveResult> bSeen = b.await();

        AtomicLong readerNanos = new AtomicLong();
        AtomicReference<Throwable> readerError = new AtomicReference<>();
        Thread reader = new Thread(() -> {
            try {
                long t0 = System.nanoTime();
                a.completeAll(ResolveResult.notResolved(A, ResolveOutcome.TIMEOUT, Duration.ZERO));
                b.completeAll(ResolveResult.notResolved(B, ResolveOutcome.TIMEOUT, Duration.ZERO));
                readerNanos.set(System.nanoTime() - t0);
            } catch (Throwable t) {
                readerError.set(t);
            }
        }, "reader");
        reader.start();
        reader.join(2_000);

        assertTrue(readerError.get() == null, "reader threw: " + readerError.get());
        long readerMs = TimeUnit.NANOSECONDS.toMillis(readerNanos.get());
        assertTrue(readerMs < 100, "reader was held for " + readerMs + " ms by a continuation");
        assertTrue(slowStarted.await(2, TimeUnit.SECONDS), "A's continuation never ran");
        bSeen.get(100, TimeUnit.MILLISECONDS);
    }

    @Test
    public void completeAllIsClaimedExactlyOnceEvenBeforeTheCompleterRuns() {
        PendingResolve p = new PendingResolve(A, pool(1));
        assertTrue(p.completeAll(ResolveResult.notResolved(A, ResolveOutcome.TIMEOUT, Duration.ZERO)));
        assertFalse(p.completeAll(ResolveResult.notResolved(A, ResolveOutcome.ERROR, Duration.ZERO, "late")));
        assertTrue(p.isDone());
    }

    @Test
    public void theInlineConstructorsStillCompleteOnTheCaller() throws Exception {
        PendingResolve p = new PendingResolve(A);
        CompletableFuture<String> where = p.await().thenApply(r -> Thread.currentThread().getName());
        p.completeAll(ResolveResult.notResolved(A, ResolveOutcome.TIMEOUT, Duration.ZERO));
        assertEquals(Thread.currentThread().getName(), where.get(1, TimeUnit.SECONDS));
    }
}
