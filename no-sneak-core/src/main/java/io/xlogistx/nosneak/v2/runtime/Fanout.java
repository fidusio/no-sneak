package io.xlogistx.nosneak.v2.runtime;

import org.zoxweb.server.fsm.State;
import org.zoxweb.server.fsm.StateMachine;
import org.zoxweb.server.fsm.Trigger;
import org.zoxweb.server.fsm.TriggerConsumer;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Runs a set of child sub-flows <b>concurrently</b> and invokes {@code onAllDone} once all
 * finish. Built on the native trigger-{@link StateMachine} <em>parallel</em> dispatch: a
 * single {@code StateMachine} whose executor is the one supplied by the caller,
 * with one {@code TriggerConsumer} per child; publishing each child's trigger dispatches it
 * to a pool thread, so the children run in parallel (no {@code MonoStateMachine}).
 * <p>
 * Each child is a {@code Consumer<ParallelJoin>}: it kicks off its (possibly async) work and
 * <b>must</b> call {@link ParallelJoin#childDone()} exactly once when finished — synchronously
 * or later from a NIO/scheduler callback. This is the fan-out primitive the scanner's Phase-2
 * (cipher / version / revocation) rides on; the {@link ParallelJoin} barrier fires
 * {@code onAllDone} at zero.
 */
public final class Fanout {

    private static final AtomicLong COUNTER = new AtomicLong();

    private Fanout() {
    }

    /**
     * Run each task <b>concurrently</b> on the native trigger-{@link StateMachine} parallel
     * dispatch on the supplied executor, with <b>no</b> join barrier.
     * Callers that coordinate completion themselves — e.g. a match-first sweep that delivers on the
     * highest-priority completion and cancels the rest — use this to get the parallel {@code
     * publish} dispatch without a {@link ParallelJoin} counting the finishes.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void dispatch(List<Runnable> tasks, Executor executor) {
        int n = tasks == null ? 0 : tasks.size();
        if (n == 0) {
            return;
        }
        StateMachine<Void> sm = new StateMachine<>(
                "dispatch-" + COUNTER.incrementAndGet(), executor);
        State st = new State("go");
        for (int i = 0; i < n; i++) {
            final Runnable task = tasks.get(i);
            st.register(new TriggerConsumer<Void>("go-" + i) {
                @Override
                public void accept(Void v) {
                    task.run();
                }
            });
        }
        sm.register(st);
        for (int i = 0; i < n; i++) {
            sm.publish(new Trigger<Void>(sm, "go-" + i, st, null));
        }
    }

    /**
     * {@link #run} with at most {@code maxInFlight} children started at once. The first window
     * is dispatched in parallel exactly as {@code run} does; each child's {@code childDone()}
     * then admits the next unstarted child, dispatched through the same trigger machinery on the
     * same executor, until every child has run. {@code onAllDone} fires once all have finished.
     * This is the launcher a deep TLS probe uses against a single host: it keeps the number of
     * simultaneous handshakes at one peer bounded without any thread ever waiting for a slot.
     * A {@code maxInFlight <= 0} means no window (plain {@code run}).
     */
    public static void runBounded(List<Consumer<ParallelJoin>> children, int maxInFlight,
                                  Runnable onAllDone, Executor executor) {
        int n = children == null ? 0 : children.size();
        if (maxInFlight <= 0 || maxInFlight >= n) {
            run(children, onAllDone, executor);
            return;
        }
        ParallelJoin all = new ParallelJoin(n, onAllDone);
        AtomicInteger next = new AtomicInteger(maxInFlight);
        List<Consumer<ParallelJoin>> window = new java.util.ArrayList<>(maxInFlight);
        for (int i = 0; i < maxInFlight; i++) {
            window.add(admitting(children, i, next, all, executor));
        }
        run(window, null, executor);
    }

    /**
     * Child {@code i} wrapped so that its completion counts once on the overall barrier and then
     * dispatches the next unstarted child. Each wrapped child gets its own one-shot join, so a
     * child that (wrongly) reports done twice still admits exactly one successor.
     */
    private static Consumer<ParallelJoin> admitting(List<Consumer<ParallelJoin>> children, int i,
                                                    AtomicInteger next, ParallelJoin all, Executor executor) {
        return ignored -> {
            ParallelJoin one = new ParallelJoin(1, () -> {
                all.childDone();
                int j = next.getAndIncrement();
                if (j < children.size()) {
                    run(List.of(admitting(children, j, next, all, executor)), null, executor);
                }
            });
            try {
                children.get(i).accept(one);
            } catch (RuntimeException e) {
                one.childDone(); // a child that throws before arming its callback still finishes
            }
        };
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void run(List<Consumer<ParallelJoin>> children, Runnable onAllDone,
                           Executor executor) {
        int n = children == null ? 0 : children.size();
        ParallelJoin join = new ParallelJoin(n, onAllDone);
        if (n == 0) {
            return; // barrier already fired
        }
        // Parallel dispatch: publish() runs consumers on the pool executor.
        StateMachine<ParallelJoin> sm = new StateMachine<>(
                "fanout-" + COUNTER.incrementAndGet(), executor);
        State st = new State("fan");
        for (int i = 0; i < n; i++) {
            final Consumer<ParallelJoin> child = children.get(i);
            st.register(new TriggerConsumer<ParallelJoin>("go-" + i) {
                @Override
                public void accept(ParallelJoin j) {
                    child.accept(j);
                }
            });
        }
        sm.register(st);
        sm.setConfig(join);
        for (int i = 0; i < n; i++) {
            sm.publish(new Trigger<ParallelJoin>(sm, "go-" + i, st, join));
        }
    }
}
