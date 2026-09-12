package io.xlogistx.nosneak.v2.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.Delayed;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * A scheduler that never fires on its own. Tests fire a scheduled task by hand, so a probe's
 * connect / expect / overall deadlines are deterministic. {@code execute} runs inline, which is
 * also what the probe engine's sequential dispatch expects.
 */
public final class ManualScheduler extends AbstractExecutorService implements ScheduledExecutorService {

    /** One scheduled task. {@link #run()} fires it regardless of cancellation, on purpose. */
    public static final class Task implements ScheduledFuture<Object>, Runnable {
        public final Runnable body;
        public final long delayMs;
        private volatile boolean cancelled;
        private volatile boolean done;

        Task(Runnable body, long delayMs) {
            this.body = body;
            this.delayMs = delayMs;
        }

        /** Runs the task even if it was cancelled — that is how a lost race is simulated. */
        @Override
        public void run() {
            done = true;
            body.run();
        }

        @Override public long getDelay(TimeUnit unit) { return unit.convert(delayMs, TimeUnit.MILLISECONDS); }
        @Override public int compareTo(Delayed o) { return Long.compare(delayMs, o.getDelay(TimeUnit.MILLISECONDS)); }
        @Override public boolean cancel(boolean mayInterruptIfRunning) { cancelled = true; return !done; }
        @Override public boolean isCancelled() { return cancelled; }
        @Override public boolean isDone() { return done || cancelled; }
        @Override public Object get() { throw new UnsupportedOperationException(); }
        @Override public Object get(long timeout, TimeUnit unit) { throw new UnsupportedOperationException(); }
    }

    public final List<Task> tasks = new ArrayList<>();

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        Task t = new Task(command, unit.toMillis(delay));
        tasks.add(t);
        return t;
    }

    /** The most recently scheduled task that has not been cancelled — the current wait window. */
    public Task latestLive() {
        for (int i = tasks.size() - 1; i >= 0; i--) {
            if (!tasks.get(i).isCancelled() && !tasks.get(i).done) {
                return tasks.get(i);
            }
        }
        return null;
    }

    /** Fire the current wait window's timeout. */
    public void fireLatest() {
        Task t = latestLive();
        if (t == null) {
            throw new IllegalStateException("no live scheduled task to fire");
        }
        t.run();
    }

    public int liveCount() {
        int n = 0;
        for (Task t : tasks) {
            if (!t.isCancelled() && !t.done) {
                n++;
            }
        }
        return n;
    }

    @Override public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) { throw new UnsupportedOperationException(); }
    @Override public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) { throw new UnsupportedOperationException(); }
    @Override public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) { throw new UnsupportedOperationException(); }

    @Override public void execute(Runnable command) { command.run(); }
    @Override public void shutdown() { }
    @Override public List<Runnable> shutdownNow() { return List.of(); }
    @Override public boolean isShutdown() { return false; }
    @Override public boolean isTerminated() { return false; }
    @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return true; }
}
