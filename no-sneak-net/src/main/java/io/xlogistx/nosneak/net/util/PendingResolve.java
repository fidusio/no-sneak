package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.ResolveOutcome;
import io.xlogistx.nosneak.net.common.ResolveResult;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One in-flight ARP or NDP resolution, shared by every caller that asked for the same
 * target while it was pending (§4.2 dedupe).
 * <p>
 * ONE future for all callers, handed out as copies: a {@code resolve()} that arrives while
 * the timeout task is removing this entry still gets completed, because {@code complete} is
 * idempotent and a late caller observes the finished result. Two futures per caller was the
 * shape that hung {@code sweep()}'s {@code allOf} forever instead of failing.
 * <p>
 * The send error lives HERE, per resolve, not on the backend (§13.23-B). A backend-wide
 * "last send error" is written by whichever socket failed most recently, so a concurrent
 * resolve on the other socket could report a stranger's failure as its own. The first
 * failure for THIS target wins and is what {@link #expire} reports.
 * <p>
 * COMPLETION HAPPENS ON THE COMPLETER, NEVER ON THE CALLER (§13.23-D). The caller of
 * {@link #completeAll} is a reader thread — the one thread per receive source whose only job
 * is to take packets off the wire — and anything a user attached to the future with
 * {@code thenAccept} or {@code whenComplete} would otherwise run on it. A slow continuation
 * there is a reader that is not reading: dropped replies and timeouts with no network cause.
 * The reader now hands one tiny task to the injected dispatcher and goes straight back to
 * {@code recvfrom}; the RTT was already computed and recorded before that hand-off, so no
 * measurement moves. Exactly-once is kept by a CAS here, not by the future.
 */
public final class PendingResolve {

    public final InetAddress target;
    public final Instant startedAt;
    /** Claimed by the one caller that actually sends; the rest share the future. */
    public final AtomicBoolean started = new AtomicBoolean();

    private volatile String sendError;
    private final CompletableFuture<ResolveResult> result = new CompletableFuture<>();
    private final AtomicBoolean claimed = new AtomicBoolean();
    private final Executor completer;

    /** Completes on the calling thread — for tests and for callers that have no pool. */
    public PendingResolve(InetAddress target) {
        this(target, Instant.now(), Runnable::run);
    }

    /** Completes on the calling thread — for tests and for callers that have no pool. */
    public PendingResolve(InetAddress target, Instant startedAt) {
        this(target, startedAt, Runnable::run);
    }

    /** @param completer the injected dispatcher; the future is completed on it, never on the caller */
    public PendingResolve(InetAddress target, Executor completer) {
        this(target, Instant.now(), completer);
    }

    public PendingResolve(InetAddress target, Instant startedAt, Executor completer) {
        this.target = Objects.requireNonNull(target, "target");
        this.startedAt = Objects.requireNonNull(startedAt, "startedAt");
        this.completer = Objects.requireNonNull(completer, "completer");
    }

    /** A copy, so a caller cannot complete the shared future for everyone else. */
    public CompletableFuture<ResolveResult> await() {
        return result.copy();
    }

    /**
     * Records that a solicitation for this target could not be transmitted. First failure
     * wins — the text that explains why nothing ever went out is the one worth keeping.
     *
     * @param text null is ignored, so callers can pass a send method's return value directly
     */
    public void recordSendError(String text) {
        if (text != null && sendError == null) {
            sendError = text;
        }
    }

    /** The recorded send failure, or null when every solicitation left the host. */
    public String sendError() {
        return sendError;
    }

    /**
     * Claims the resolve and completes every caller's future ON THE COMPLETER. Returns at
     * once; the calling thread never runs a continuation.
     *
     * @return true if this call claimed the resolve; false if it was already claimed
     */
    public boolean completeAll(ResolveResult outcome) {
        if (!claimed.compareAndSet(false, true)) {
            return false;
        }
        completer.execute(() -> result.complete(outcome));
        return true;
    }

    /** True once claimed — the completion may still be in flight on the completer. */
    public boolean isDone() {
        return claimed.get();
    }

    /**
     * What a fired deadline reports. PURE. A target whose solicitation never left the host
     * did not "time out" — nothing was waited for — so it is {@link ResolveOutcome#ERROR}
     * carrying the send text; otherwise it is an honest {@link ResolveOutcome#TIMEOUT}.
     */
    public ResolveResult expire(Instant now) {
        Duration elapsed = Duration.between(startedAt, now);
        return sendError == null
                ? ResolveResult.notResolved(target, ResolveOutcome.TIMEOUT, elapsed)
                : ResolveResult.notResolved(target, ResolveOutcome.ERROR, elapsed, sendError);
    }

    /** What {@code close()} or a dead reader reports: ERROR, with the reason. */
    public ResolveResult abort(String why) {
        return ResolveResult.notResolved(target, ResolveOutcome.ERROR,
                                         Duration.between(startedAt, Instant.now()), why);
    }
}
