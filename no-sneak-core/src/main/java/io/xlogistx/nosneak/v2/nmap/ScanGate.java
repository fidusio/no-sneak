package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.runtime.ConnectionGate;
import org.zoxweb.shared.util.RateController;

import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The scan's admission gate: an in-flight window, a launch queue, and a leaky-bucket pacer —
 * and never a parked thread.
 * <p>
 * Two independent limits, either or both optional:
 * <ul>
 *   <li><b>max in-flight</b> — at most N units launched-but-not-yet-finished at once. Callers
 *       {@link #submit(Runnable)} a launch (which initiates one async connection) and MUST call
 *       {@link #release()} exactly once when that unit finishes, so the next queued launch can
 *       proceed.</li>
 *   <li><b>max per second</b> — how fast admitted launches may <em>leave</em>. This is zoxweb's
 *       {@link RateController} in TIME mode, the same pacer {@code no-sneak-net}'s sweep uses:
 *       a leaky bucket with <b>no burst credit</b>. The previous shape here was a token bucket
 *       refilled by a 100 ms tick, which let up to {@code maxPerSec} connects leave in the first
 *       tick — exactly the burst the discovery module rejected on purpose, and the reason the two
 *       modules paced differently. Now one rule: when the bucket says "not yet", the launch is
 *       held and re-offered by the injected scheduler at its send time. Nothing sleeps.</li>
 * </ul>
 * {@code RateController} paces in whole milliseconds, rounded up, so the effective rate is at or
 * under the cap: 2000/s becomes 1 ms per launch, i.e. 1000/s; 500/s is exactly 2 ms. Under the
 * cap is the only direction a safety limit may err in.
 * <p>
 * Draining runs launches on the calling or scheduler thread; a launch itself is non-blocking.
 * It is also the {@link ConnectionGate} the probe engine is paced by, so a {@code -sV} scan's
 * candidate connections and enumeration children count against the same window as the port scan
 * (PENDING-ISSUES P4). Formerly {@code RateLimiter}; renamed when the pacer was replaced because
 * the name described a third of what the class does.
 */
public final class ScanGate implements ConnectionGate {

    private final int maxInFlight;          // <= 0 : unlimited
    private final RateController pacer;     // null : unpaced
    private final ScheduledExecutorService scheduler;
    private final Queue<Runnable> pending = new ConcurrentLinkedQueue<>();
    private final AtomicInteger inFlight = new AtomicInteger(0);
    private final Object lock = new Object();
    /**
     * Set while this thread is inside {@link #drain()}. A launch can complete synchronously —
     * a loopback connect finishes inside {@code addClientSocket}, which calls back into
     * {@link #release()} → {@code drain()} — so without this guard the drain recurses once per
     * queued unit and a large localhost scan dies with a StackOverflowError. Re-entering simply
     * returns; the outer loop is still running and picks the next unit up.
     */
    private static final ThreadLocal<Boolean> DRAINING = ThreadLocal.withInitial(() -> Boolean.FALSE);
    /**
     * A launch that has been ADMITTED (it holds an in-flight slot) but whose send time has not
     * come. At most one exists: the bucket serialises reservations, so the chain continues from
     * its timer. Guarded by {@link #lock}.
     */
    private Runnable held;
    private volatile ScheduledFuture<?> timer;

    /**
     * @param scheduler   the scheduler a held launch is re-offered on — injected rather than
     *                    looked up statically, so an embedder's pools (and the ones the owning
     *                    {@link org.zoxweb.server.net.NIOSocket} was built with) are the ones used
     * @param maxInFlight at most N units launched-but-unfinished at once; {@code <= 0} unlimited
     * @param maxPerSec   leaky-bucket pacing of new launches; {@code <= 0} unpaced
     */
    public ScanGate(ScheduledExecutorService scheduler, int maxInFlight, int maxPerSec) {
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.maxInFlight = maxInFlight;
        this.pacer = maxPerSec > 0
                ? new RateController("scan-gate", (float) maxPerSec, TimeUnit.SECONDS)
                        .setRCType(RateController.RCType.TIME)
                : null;
    }

    /** Queue a launch; it runs when a slot is free and the bucket says its time has come. */
    @Override
    public void submit(Runnable launch) {
        pending.add(launch);
        drain();
    }

    /**
     * Signal that one launched unit finished — frees an in-flight slot. Never lets the counter
     * go below zero: a single stray release would otherwise leave {@code inFlight} permanently
     * short and, once negative, the max-in-flight test at {@link #drain()} could never trip
     * again — silently turning the concurrency cap off for the rest of the scan.
     */
    @Override
    public void release() {
        int cur;
        do {
            cur = inFlight.get();
            if (cur <= 0) {
                break;
            }
        } while (!inFlight.compareAndSet(cur, cur - 1));
        drain();
    }

    /**
     * Counts one more unit and runs it now, cap or no cap, unpaced. The in-flight figure may then
     * exceed {@code maxInFlight}, which only means {@link #drain()} admits nothing new until the
     * overshoot is released. Used for a unit's own children (see {@link ConnectionGate#submitNow}).
     */
    @Override
    public void submitNow(Runnable launch) {
        inFlight.incrementAndGet();
        run(launch);
    }

    /** @return units currently launched but not yet finished (never negative). */
    public int inFlight() {
        return inFlight.get();
    }

    /** @return true while an admitted launch is waiting for its send time. */
    public boolean isHolding() {
        synchronized (lock) {
            return held != null;
        }
    }

    private void drain() {
        if (DRAINING.get()) {
            return; // re-entered from a synchronously-completing launch; the outer loop continues
        }
        DRAINING.set(Boolean.TRUE);
        try {
            drainLoop();
        } finally {
            DRAINING.set(Boolean.FALSE);
        }
    }

    private void drainLoop() {
        while (true) {
            Runnable r;
            long delayMs;
            synchronized (lock) {
                if (held != null || pending.isEmpty()) {
                    return;
                }
                if (maxInFlight > 0 && inFlight.get() >= maxInFlight) {
                    return;
                }
                r = pending.poll();
                if (r == null) {
                    return;
                }
                inFlight.incrementAndGet();
                delayMs = pacer == null ? 0 : pacer.nextWait();
                if (delayMs > 0) {
                    held = r;
                }
            }
            if (delayMs > 0) {
                // Admitted, but not yet: the scheduler re-offers it at its send time and the
                // chain continues from there. This pass is done; nothing waits.
                timer = scheduler.schedule(this::releaseHeld, delayMs, TimeUnit.MILLISECONDS);
                return;
            }
            run(r); // non-blocking: initiates one async connection
        }
    }

    private void releaseHeld() {
        Runnable h;
        synchronized (lock) {
            h = held;
            held = null;
        }
        timer = null;
        if (h != null) {
            run(h);
        }
        drain();
    }

    private static void run(Runnable launch) {
        try {
            launch.run();
        } catch (Exception ignored) {
            // a launch that throws has already reported through its own callback/Unit
        }
    }

    /**
     * Cancels the pacing timer. A launch that was admitted but still waiting is run now rather
     * than dropped, so its {@code Unit} completes and no barrier is left counting on it.
     */
    public void close() {
        ScheduledFuture<?> t = timer;
        if (t != null) {
            timer = null;
            try {
                t.cancel(false);
            } catch (Exception ignored) {
            }
        }
        Runnable h;
        synchronized (lock) {
            h = held;
            held = null;
        }
        if (h != null) {
            run(h);
        }
    }
}
