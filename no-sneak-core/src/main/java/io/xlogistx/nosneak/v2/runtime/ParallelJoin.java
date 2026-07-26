package io.xlogistx.nosneak.v2.runtime;

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
public final class ParallelJoin {

    private final AtomicInteger pending;
    private final AtomicBoolean fired = new AtomicBoolean(false);
    private final Runnable onComplete;

    public ParallelJoin(int count, Runnable onComplete) {
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
