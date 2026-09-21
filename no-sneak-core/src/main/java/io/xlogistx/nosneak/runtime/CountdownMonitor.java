package io.xlogistx.nosneak.runtime;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A one-shot join barrier for a parallel fan-out: created with the number of child
 * sub-flows, it invokes {@code onComplete} exactly once when the last child reports
 * {@link #childDone()}. Thread-safe — children may complete on different threads (pool,
 * selector, scheduler). Zero children fires immediately.
 * <p>
 * This is the counting primitive that lets the engine wait for a set of concurrent
 * children (e.g. the scanner's cipher / version / revocation probes) before advancing.
 */
public final class CountdownMonitor {

    private final AtomicInteger pending;
    private final AtomicBoolean fired = new AtomicBoolean(false);
    private final Runnable onComplete;

    public CountdownMonitor(int count, Runnable onComplete) {
        this.onComplete = onComplete;
        this.pending = new AtomicInteger(count);
        if (count <= 0) {
            fire();
        }
    }

    /** Signal that one child sub-flow finished (success or failure). */
    public void childDone() {
        if (pending.decrementAndGet() <= 0) {
            fire();
        }
    }

    /**
     * Register one more child while the barrier is still open — the way a child that has
     * learned something mid-flight (a port that just connected) hands the join a follow-up
     * (that port's probe sweep) without a second barrier and without the parent waiting for
     * the whole first wave to land. Must be called <em>before</em> the registering child's own
     * {@link #childDone()}, so the count can never be zero in between; called after the
     * barrier fired it is refused.
     *
     * @return true when the child was added; false when the join has already completed
     */
    public boolean addChild() {
        if (fired.get()) {
            return false;
        }
        pending.incrementAndGet();
        if (fired.get()) {
            // Lost the race with the last childDone(): give the count back and refuse.
            pending.decrementAndGet();
            return false;
        }
        return true;
    }

    /** Children still outstanding. */
    public int remaining() {
        return Math.max(0, pending.get());
    }

    private void fire() {
        if (fired.compareAndSet(false, true)) {
            try {
                if (onComplete != null) {
                    onComplete.run();
                }
            } catch (Exception ignored) {
            }
        }
    }
}
