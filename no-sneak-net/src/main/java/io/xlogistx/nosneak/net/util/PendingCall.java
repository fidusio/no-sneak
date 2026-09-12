package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.PingError;
import io.xlogistx.nosneak.net.common.PingProbe;
import io.xlogistx.nosneak.net.common.PingResult;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One {@code ping()} call: its probes, and the future that completes once every probe has
 * settled — by reply on the reader thread, by timeout on the scheduler, by a send failure on
 * the caller, or by {@code close()}.
 * <p>
 * EXACTLY ONCE per probe, enforced here rather than at every call site (§13.23-B). The
 * previous shape counted <em>entries</em>, so a probe settled by both the timeout task and
 * {@code close()} completed the call early with a duplicate in the list — {@code [A, A, B]}
 * for a three-probe call, C never reported. {@link Probe#settle} claims with a CAS, so a
 * second settlement of the same probe is a no-op whichever thread arrives second.
 * <p>
 * THE FUTURE IS COMPLETED ON THE COMPLETER, NEVER ON THE SETTLING THREAD (§13.23-D). The
 * last probe is usually settled by a reader thread parsing the reply; a continuation the
 * caller attached would otherwise run on that reader and stall packet capture for as long
 * as it took. The RTT is computed from {@link Probe#sentAtNanos} before settlement, so the
 * hand-off moves no measurement.
 * <p>
 * THE CALL ALWAYS COMPLETES (§13.23-E). {@code expected} probes must settle, and a caller
 * that registers a probe and then throws before sending it — a scheduler that refuses the
 * deadline, a frame builder that fails — would leave that slot unsettled forever, and the
 * future with it. {@link #failRemaining} closes every open slot at once: registered probes
 * not yet settled, and slots that were never registered at all (reported with a negative
 * sequence, because they never had one). Every {@code ping()} calls it from its abort path.
 */
public final class PendingCall {

    /** Sequence stamped on a slot that was never registered: nothing was ever sent for it. */
    public static final int NEVER_SENT = -1;

    public final CompletableFuture<PingResult> future = new CompletableFuture<>();
    public final InetAddress target;
    public final int expected;

    private final List<PingProbe> settled = new ArrayList<>();
    private final List<Probe> registered = new CopyOnWriteArrayList<>();
    private volatile String detail;
    private final Executor completer;

    /** Completes on the settling thread — for tests and for callers that have no pool. */
    public PendingCall(InetAddress target, int expected) {
        this(target, expected, Runnable::run);
    }

    /** @param completer the injected dispatcher; the future is completed on it */
    public PendingCall(InetAddress target, int expected, Executor completer) {
        this.target = Objects.requireNonNull(target, "target");
        this.expected = expected;
        this.completer = Objects.requireNonNull(completer, "completer");
    }

    /** Registers a probe that is about to be sent. */
    public Probe newProbe(int sequence, long sentAtNanos) {
        Probe p = new Probe(this, sequence, sentAtNanos);
        registered.add(p);
        return p;
    }

    /** Probes registered so far via {@link #newProbe}; at most {@link #expected}. */
    public int registeredCount() {
        return registered.size();
    }

    /**
     * Settles every slot this call is still waiting for, so the future completes now.
     * Registered probes that have not settled fail with {@code error}; slots that were never
     * registered are reported as {@link #NEVER_SENT} probes with the same error. Idempotent,
     * and a no-op on a call that has already completed. Completion still goes through the
     * completer (§13.23-D).
     *
     * @param error  what the remaining slots report
     * @param detail native text for the aggregate, if any (first one wins)
     */
    public void failRemaining(PingError error, String detail) {
        setDetail(detail);
        for (Probe p : registered) {
            p.fail(error);
        }
        int missing;
        synchronized (settled) {
            missing = expected - settled.size();
        }
        for (int i = 0; i < missing; i++) {
            settleUnsent(PingProbe.failed(NEVER_SENT - i, error));
        }
    }

    /**
     * Native text for the aggregate result — the reader's cause of death, for instance.
     * First one wins; a later, vaguer explanation must not overwrite the precise one.
     */
    public void setDetail(String text) {
        if (text != null && detail == null) {
            detail = text;
        }
    }

    /**
     * Settles a probe that was never in flight — a send that failed before the packet left.
     * Such a probe has no {@link Probe} handle and no expiry, and is settled exactly once by
     * construction (the caller that failed to send is the only one that knows about it).
     */
    public void settleUnsent(PingProbe outcome) {
        add(outcome);
    }

    private void add(PingProbe outcome) {
        List<PingProbe> finished = null;
        synchronized (settled) {
            settled.add(outcome);
            if (settled.size() >= expected) {
                finished = new ArrayList<>(settled);
            }
        }
        if (finished != null) {
            finished.sort(Comparator.comparingInt(PingProbe::sequence));
            PingError err = detail == null ? null : PingError.IO;
            PingResult aggregate = PingResult.of(target, finished, err, detail);
            completer.execute(() -> future.complete(aggregate));
        }
    }

    /** One echo request in flight. */
    public static final class Probe {
        public final PendingCall call;
        public final int sequence;
        public final long sentAtNanos;
        /** The TIMEOUT task, cancelled on settlement; set by the sender after scheduling. */
        public volatile ScheduledFuture<?> expiry;
        private final AtomicBoolean settled = new AtomicBoolean();

        private Probe(PendingCall call, int sequence, long sentAtNanos) {
            this.call = call;
            this.sequence = sequence;
            this.sentAtNanos = sentAtNanos;
        }

        /**
         * Claims this probe and records its outcome. The first caller wins; every later call
         * returns false and changes nothing — that is the whole S13 fix.
         */
        public boolean settle(PingProbe outcome) {
            if (!settled.compareAndSet(false, true)) {
                return false;
            }
            ScheduledFuture<?> e = expiry;
            if (e != null) {
                expiry = null;
                try {
                    e.cancel(false);
                } catch (RuntimeException ignored) {
                    // a cancel that races the timer's own firing is harmless: settle is exactly-once
                }
            }
            call.add(outcome);
            return true;
        }

        public boolean fail(PingError error) {
            return settle(PingProbe.failed(sequence, error));
        }

        public boolean isSettled() {
            return settled.get();
        }
    }
}
