package io.xlogistx.nosneak.v2.runtime;

import org.zoxweb.server.fsm.State;
import org.zoxweb.server.fsm.StateMachine;
import org.zoxweb.server.fsm.Trigger;
import org.zoxweb.server.fsm.TriggerConsumer;
import org.zoxweb.server.task.TaskUtil;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Runs a set of child sub-flows <b>concurrently</b> and invokes {@code onAllDone} once all
 * finish. Built on the native trigger-{@link StateMachine} <em>parallel</em> dispatch: a
 * single {@code StateMachine} whose executor is {@link TaskUtil#defaultTaskProcessor()},
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
     * dispatch (executor = {@link TaskUtil#defaultTaskProcessor()}), with <b>no</b> join barrier.
     * Callers that coordinate completion themselves — e.g. a match-first sweep that delivers on the
     * highest-priority completion and cancels the rest — use this to get the parallel {@code
     * publish} dispatch without a {@link ParallelJoin} counting the finishes.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void dispatch(List<Runnable> tasks) {
        int n = tasks == null ? 0 : tasks.size();
        if (n == 0) {
            return;
        }
        StateMachine<Void> sm = new StateMachine<>(
                "dispatch-" + COUNTER.incrementAndGet(), TaskUtil.defaultTaskProcessor());
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

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void run(List<Consumer<ParallelJoin>> children, Runnable onAllDone) {
        int n = children == null ? 0 : children.size();
        ParallelJoin join = new ParallelJoin(n, onAllDone);
        if (n == 0) {
            return; // barrier already fired
        }
        // Parallel dispatch: publish() runs consumers on the pool executor.
        StateMachine<ParallelJoin> sm = new StateMachine<>(
                "fanout-" + COUNTER.incrementAndGet(), TaskUtil.defaultTaskProcessor());
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
