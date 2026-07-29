package io.xlogistx.nosneak.v2.nmap;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Non-blocking scan throttle: paces the launch of connection units without ever blocking a
 * thread. Two independent limits, either/both optional:
 * <ul>
 *   <li><b>max in-flight</b> — at most N units launched-but-not-yet-finished at once;</li>
 *   <li><b>max per second</b> — token-bucket pacing of new launches, refilled by a
 *       {@code defaultTaskScheduler} tick.</li>
 * </ul>
 * Callers {@link #submit(Runnable)} a launch (which initiates one async connection) and MUST
 * call {@link #release()} exactly once when that unit finishes (from its NIO/probe callback),
 * so the next queued launch can proceed. With no limits set it drains immediately (like a plain
 * fan-out). Draining runs launches on the calling/scheduler thread; the launch itself is
 * non-blocking, so no thread is ever parked.
 */
public final class RateLimiter {

    private static final long TICK_MS = 100;

    private final int maxInFlight;   // <= 0 : unlimited
    private final int maxPerSec;     // <= 0 : unpaced
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
    private double tokens;
    private volatile ScheduledFuture<?> ticker;

    /**
     * @param scheduler the scheduler the refill tick runs on — injected rather than looked up
     *                  statically, so an embedder's pools (and the ones the owning
     *                  {@link org.zoxweb.server.net.NIOSocket} was built with) are the ones used
     * @param maxInFlight at most N units launched-but-unfinished at once; {@code <= 0} unlimited
     * @param maxPerSec token-bucket pacing of new launches; {@code <= 0} unpaced
     */
    public RateLimiter(ScheduledExecutorService scheduler, int maxInFlight, int maxPerSec) {
        this.maxInFlight = maxInFlight;
        this.maxPerSec = maxPerSec;
        this.tokens = maxPerSec > 0 ? maxPerSec : 0;
        if (maxPerSec > 0) {
            this.ticker = scheduler.scheduleAtFixedRate(
                    this::tick, TICK_MS, TICK_MS, TimeUnit.MILLISECONDS);
        }
    }

    /** Queue a launch (initiates one async connection when a slot/token frees). */
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

    /** @return units currently launched but not yet finished (never negative). */
    public int inFlight() {
        return inFlight.get();
    }

    private void tick() {
        synchronized (lock) {
            tokens = Math.min(maxPerSec, tokens + maxPerSec * (TICK_MS / 1000.0));
        }
        drain();
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
            synchronized (lock) {
                if (pending.isEmpty()) {
                    return;
                }
                if (maxInFlight > 0 && inFlight.get() >= maxInFlight) {
                    return;
                }
                if (maxPerSec > 0 && tokens < 1.0) {
                    return;
                }
                r = pending.poll();
                if (r == null) {
                    return;
                }
                inFlight.incrementAndGet();
                if (maxPerSec > 0) {
                    tokens -= 1.0;
                }
            }
            try {
                r.run(); // non-blocking: initiates one async connection
            } catch (Exception ignored) {
            }
        }
    }

    public void close() {
        ScheduledFuture<?> t = ticker;
        if (t != null) {
            ticker = null;
            try { t.cancel(false); } catch (Exception ignored) { }
        }
    }
}
