package io.xlogistx.nosneak.net.util;

import org.zoxweb.shared.util.RateController;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Event-driven admission for a sweep: at most {@code maxInFlight} probes outstanding, launched
 * no faster than the pacer allows, and <b>never parking a thread</b> to get either.
 * <p>
 * {@code maxInFlight} bounds how many probes are OUTSTANDING; the rate cap bounds how fast they
 * LEAVE. They are different constraints (spec §3.5): 256 outstanding probes that each complete in
 * a millisecond still emit a quarter of a million packets a second, which churns switch CAM tables
 * and trips customer intrusion detection. The pacer is a leaky bucket without burst credit — a
 * burst allowance is exactly what would trip the IDS this exists to avoid.
 * <p>
 * Why this is a state machine and not a semaphore (§13.22): the executors are borrowed from
 * zoxweb's process-wide pools, and the scheduler delivers every due timer to the SAME pool the
 * dispatcher runs on. A sweep that parked pool threads on a semaphore or a sleep therefore parked
 * the very threads its per-host timeouts needed — once {@code maxInFlight} silent hosts held
 * permits, no timeout could run, no permit was released, and every timer in the JVM stopped.
 * Here nothing waits: a host is admitted when a slot is free and the bucket says so; a completion
 * or a scheduler tick admits the next one. The only shared state is the target iterator and the
 * in-flight count, guarded by this object's monitor for a few instructions at a time and never
 * across a send, a callback, or a scheduler call.
 * <p>
 * The probe function is what {@code sweepOne} already is on every backend: it starts the resolve
 * and/or ping for one host and returns a future that settles when both have — by reply on the
 * reader thread or by timeout on the scheduler. It is invoked on the dispatcher (or on the
 * scheduler tick that admitted it), the same threads the old fan-out used.
 */
public final class SweepDriver {

    private final Iterator<InetAddress> targets;
    private final int maxInFlight;
    private final RateController pacer;
    private final ScheduledExecutorService scheduler;
    private final Executor dispatcher;
    private final Function<InetAddress, CompletableFuture<Void>> probe;
    private final CompletableFuture<Void> result = new CompletableFuture<>();

    private int inFlight;
    private boolean finished;

    private SweepDriver(Iterator<InetAddress> targets, int maxInFlight, RateController pacer,
                        ScheduledExecutorService scheduler, Executor dispatcher,
                        Function<InetAddress, CompletableFuture<Void>> probe) {
        this.targets = Objects.requireNonNull(targets, "targets");
        this.maxInFlight = maxInFlight;
        this.pacer = pacer;
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
        this.probe = Objects.requireNonNull(probe, "probe");
        if (maxInFlight < 1) {
            throw new IllegalArgumentException("maxInFlight must be >= 1, got " + maxInFlight);
        }
    }

    /**
     * Builds the per-sweep pacer, or {@code null} for unlimited.
     * <p>
     * The rate is expressed in <b>hosts</b> per second — {@code maxPacketsPerSecond / packetsPerHost}
     * — so each admission is one {@link RateController#nextWait()}. {@code RateController} works in
     * whole milliseconds and rounds the interval UP, so the emitted rate is at or UNDER the cap,
     * which is the only direction a safety limit may err in: 2000 pps at 2 packets per host is
     * exactly 1000 hosts/s (1 ms); at 3 packets per host it is 667 hosts/s, rounded to 2 ms, i.e.
     * 1500 pps. A caller that cares about the last third should say so in its own budget.
     *
     * @param maxPacketsPerSecond {@code 0} or negative means unlimited, matching {@code SweepOptions}
     * @param packetsPerHost      the worst-case frames one host costs (ARP attempts plus pings)
     */
    public static RateController pacer(int maxPacketsPerSecond, int packetsPerHost) {
        if (maxPacketsPerSecond <= 0) {
            return null;
        }
        // A sweep with neither MAC nor ICMP costs nothing on the wire; pace it as one
        // packet per host rather than dividing by zero.
        int perHost = Math.max(1, packetsPerHost);
        RateController rc = new RateController("sweep",
                maxPacketsPerSecond / (float) perHost, TimeUnit.SECONDS);
        return rc.setRCType(RateController.RCType.TIME);
    }

    /**
     * Probes every target with at most {@code maxInFlight} outstanding, paced by {@code pacer}.
     *
     * @param targets     the hosts to probe, consumed once, in order
     * @param maxInFlight bound on probes launched but not yet settled
     * @param pacer       from {@link #pacer(int, int)}; {@code null} means unlimited
     * @param scheduler   the injected scheduler (§4.3) — used only when the bucket says "not yet"
     * @param dispatcher  the injected dispatcher (§4.3) — admission and the result complete on it
     * @param probe       starts one host's probes; a synchronous throw counts as a failed probe
     * @return completed on the dispatcher once every probe has settled; never exceptionally
     */
    public static CompletableFuture<Void> run(Iterator<InetAddress> targets, int maxInFlight,
                                              RateController pacer,
                                              ScheduledExecutorService scheduler,
                                              Executor dispatcher,
                                              Function<InetAddress, CompletableFuture<Void>> probe) {
        SweepDriver driver = new SweepDriver(targets, maxInFlight, pacer, scheduler, dispatcher, probe);
        dispatcher.execute(driver::admit);
        return driver.result;
    }

    /**
     * Admits targets until the window is full, the bucket says wait, or the targets run out.
     * Re-entered by every completion and by every pacing tick; safe to call from any thread.
     */
    private void admit() {
        while (true) {
            InetAddress next;
            long delayMs;
            synchronized (this) {
                if (finished || inFlight >= maxInFlight) {
                    return;
                }
                if (!targets.hasNext()) {
                    if (inFlight == 0) {
                        finished = true;
                        dispatcher.execute(() -> result.complete(null));
                    }
                    return;
                }
                next = targets.next();
                inFlight++;
                delayMs = pacer == null ? 0 : pacer.nextWait();
            }
            if (delayMs > 0) {
                // The bucket serialises reservations, so at most one target is ever waiting on a
                // timer. The chain continues from that tick; this pass is done.
                InetAddress waiting = next;
                scheduler.schedule(() -> {
                    launch(waiting);
                    admit();
                }, delayMs, TimeUnit.MILLISECONDS);
                return;
            }
            launch(next);
        }
    }

    private void launch(InetAddress target) {
        CompletableFuture<Void> f;
        try {
            f = probe.apply(target);
            if (f == null) {
                f = CompletableFuture.completedFuture(null);
            }
        } catch (RuntimeException e) {
            f = CompletableFuture.failedFuture(e);
        }
        f.whenComplete((r, t) -> {
            synchronized (this) {
                inFlight--;
            }
            // One short task per completion: the dispatcher queue depth is bounded by the
            // window, never by the size of the range.
            dispatcher.execute(this::admit);
        });
    }
}
