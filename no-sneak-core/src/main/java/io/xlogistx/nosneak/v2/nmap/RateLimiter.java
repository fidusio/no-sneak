package io.xlogistx.nosneak.v2.nmap;

import org.zoxweb.server.task.TaskUtil;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
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
    private double tokens;
    private ScheduledFuture<?> ticker;

    public RateLimiter(int maxInFlight, int maxPerSec) {
        this.maxInFlight = maxInFlight;
        this.maxPerSec = maxPerSec;
        this.tokens = maxPerSec > 0 ? maxPerSec : 0;
        if (maxPerSec > 0) {
            this.ticker = TaskUtil.defaultTaskScheduler()
                    .scheduleAtFixedRate(this::tick, TICK_MS, TICK_MS, TimeUnit.MILLISECONDS);
        }
    }

    /** Queue a launch (initiates one async connection when a slot/token frees). */
    public void submit(Runnable launch) {
        pending.add(launch);
        drain();
    }

    /** Signal that one launched unit finished — frees an in-flight slot. */
    public void release() {
        inFlight.decrementAndGet();
        drain();
    }

    private void tick() {
        synchronized (lock) {
            tokens = Math.min(maxPerSec, tokens + maxPerSec * (TICK_MS / 1000.0));
        }
        drain();
    }

    private void drain() {
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
