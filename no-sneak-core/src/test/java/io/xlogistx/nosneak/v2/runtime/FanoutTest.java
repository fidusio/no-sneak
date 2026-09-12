package io.xlogistx.nosneak.v2.runtime;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.task.TaskUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the parallel fan-out primitives the analysis actions ride on. These guard the
 * properties an engine failure would hang on: the join fires <b>exactly once</b>, it fires even
 * when children fail, and children really do run concurrently (a fan-out that serialised would
 * turn a cipher sweep into a timeout pile-up).
 */
public class FanoutTest {

    @Test
    public void joinFiresOnceWhenTheLastChildCompletes() throws Exception {
        AtomicInteger fired = new AtomicInteger();
        ParallelJoin join = new ParallelJoin(3, fired::incrementAndGet);
        assertEquals(3, join.remaining());

        join.childDone();
        assertEquals(0, fired.get(), "the barrier must not fire early");
        join.childDone();
        join.childDone();
        assertEquals(1, fired.get());
        assertEquals(0, join.remaining());
    }

    /** An over-reporting child (a double callback) must not fire the barrier twice. */
    @Test
    public void joinIsIdempotentUnderExtraCompletions() {
        AtomicInteger fired = new AtomicInteger();
        ParallelJoin join = new ParallelJoin(1, fired::incrementAndGet);
        join.childDone();
        join.childDone();
        join.childDone();
        assertEquals(1, fired.get());
    }

    @Test
    public void zeroChildrenFiresImmediately() {
        AtomicInteger fired = new AtomicInteger();
        new ParallelJoin(0, fired::incrementAndGet);
        assertEquals(1, fired.get());
    }

    @Test
    public void joinSurvivesAThrowingCompletionHandler() {
        ParallelJoin join = new ParallelJoin(1, () -> {
            throw new RuntimeException("boom");
        });
        join.childDone(); // must not propagate out of the barrier
    }

    @Test
    public void joinIsThreadSafeUnderConcurrentCompletions() throws Exception {
        final int n = 64;
        AtomicInteger fired = new AtomicInteger();
        ParallelJoin join = new ParallelJoin(n, fired::incrementAndGet);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    join.childDone();
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        assertEquals(1, fired.get(), "the barrier must fire exactly once under contention");
    }

    @Test
    public void fanoutRunsEveryChildAndJoinsOnce() throws Exception {
        final int n = 6;
        AtomicInteger completions = new AtomicInteger();
        CountDownLatch joined = new CountDownLatch(1);
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            children.add(join -> {
                completions.incrementAndGet();
                join.childDone();
            });
        }
        Fanout.run(children, joined::countDown, TaskUtil.defaultTaskProcessor());
        assertTrue(joined.await(15, TimeUnit.SECONDS), "the join barrier never fired");
        assertEquals(n, completions.get());
    }

    /**
     * The children must genuinely run in parallel: each blocks on a barrier that only releases
     * once all of them have arrived, so a serialised dispatch would time out here.
     */
    @Test
    public void fanoutChildrenRunConcurrentlyOnDistinctThreads() throws Exception {
        final int n = 4;
        Set<String> threads = ConcurrentHashMap.newKeySet();
        CountDownLatch allArrived = new CountDownLatch(n);
        CountDownLatch joined = new CountDownLatch(1);
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            children.add(join -> {
                threads.add(Thread.currentThread().getName());
                allArrived.countDown();
                try {
                    // Only completes if the other children are running at the same time.
                    allArrived.await(15, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                join.childDone();
            });
        }
        Fanout.run(children, joined::countDown, TaskUtil.defaultTaskProcessor());
        assertTrue(joined.await(20, TimeUnit.SECONDS),
                "children did not run concurrently - the fan-out serialised");
        assertTrue(threads.size() > 1, "expected multiple pool threads, saw " + threads);
    }

    /** A child that throws before reporting must not strand the barrier forever. */
    @Test
    public void fanoutStillJoinsWhenAChildReportsFromItsFailurePath() throws Exception {
        CountDownLatch joined = new CountDownLatch(1);
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        children.add(join -> {
            try {
                throw new IllegalStateException("probe launch failed");
            } catch (Exception e) {
                join.childDone(); // the pattern every analysis child uses
            }
        });
        children.add(ParallelJoin::childDone);
        Fanout.run(children, joined::countDown, TaskUtil.defaultTaskProcessor());
        assertTrue(joined.await(15, TimeUnit.SECONDS));
    }

    @Test
    public void fanoutWithNoChildrenFiresImmediately() throws Exception {
        CountDownLatch joined = new CountDownLatch(1);
        Fanout.run(Collections.emptyList(), joined::countDown, TaskUtil.defaultTaskProcessor());
        assertTrue(joined.await(5, TimeUnit.SECONDS));
    }

    @Test
    public void dispatchRunsEveryTaskWithoutABarrier() throws Exception {
        final int n = 5;
        CountDownLatch ran = new CountDownLatch(n);
        List<Runnable> tasks = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            tasks.add(ran::countDown);
        }
        Fanout.dispatch(tasks, TaskUtil.defaultTaskProcessor());
        assertTrue(ran.await(15, TimeUnit.SECONDS), "not every dispatched task ran");
    }

    @Test
    public void dispatchToleratesEmptyAndNull() {
        Fanout.dispatch(Collections.emptyList(), TaskUtil.defaultTaskProcessor());
        Fanout.dispatch(null, TaskUtil.defaultTaskProcessor());
    }

    // ==================== runBounded: the enumeration launcher ====================

    /**
     * Children that finish only when the test says so: each child parks its join, the test
     * releases them one at a time and watches how many were started in between.
     */
    @Test
    public void runBoundedNeverStartsMoreThanTheWindowAndAdmitsOnePerCompletion() {
        final int n = 12;
        final int cap = 3;
        List<ParallelJoin> parked = new ArrayList<>();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            children.add(parked::add);
        }
        AtomicInteger done = new AtomicInteger();
        Fanout.runBounded(children, cap, done::incrementAndGet, Runnable::run);

        assertEquals(cap, parked.size(), "only the first window starts");
        assertEquals(0, done.get());
        for (int released = 0; released < n; released++) {
            assertTrue(parked.size() - released <= cap, "in flight must never exceed the window");
            parked.get(released).childDone();
            assertEquals(Math.min(n, cap + released + 1), parked.size(),
                    "each completion admits exactly one more child");
        }
        assertEquals(n, parked.size());
        assertEquals(1, done.get(), "the barrier fires once, when the last child finishes");
    }

    @Test
    public void runBoundedWithAWindowAtLeastTheChildCountIsPlainRun() {
        AtomicInteger started = new AtomicInteger();
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            children.add(j -> { started.incrementAndGet(); j.childDone(); });
        }
        AtomicInteger done = new AtomicInteger();
        Fanout.runBounded(children, 4, done::incrementAndGet, Runnable::run);
        assertEquals(4, started.get());
        assertEquals(1, done.get());
        Fanout.runBounded(children, 0, done::incrementAndGet, Runnable::run); // 0 = no window
        assertEquals(8, started.get());
        assertEquals(2, done.get());
    }

    @Test
    public void runBoundedToleratesSynchronousCompletionsDoubleDoneAndThrowingChildren() {
        List<Consumer<ParallelJoin>> children = new ArrayList<>();
        AtomicInteger ran = new AtomicInteger();
        for (int i = 0; i < 20; i++) {
            final int k = i;
            children.add(j -> {
                ran.incrementAndGet();
                if (k % 3 == 0) {
                    throw new IllegalStateException("child " + k + " blew up before arming anything");
                }
                j.childDone();
                if (k % 3 == 1) {
                    j.childDone(); // a misbehaving child reports twice: must admit exactly one successor
                }
            });
        }
        AtomicInteger done = new AtomicInteger();
        Fanout.runBounded(children, 2, done::incrementAndGet, Runnable::run);
        assertEquals(20, ran.get(), "every child ran exactly once");
        assertEquals(1, done.get());
    }

    @Test
    public void runBoundedWithNoChildrenFiresImmediately() {
        AtomicInteger done = new AtomicInteger();
        Fanout.runBounded(Collections.emptyList(), 3, done::incrementAndGet, Runnable::run);
        assertEquals(1, done.get());
    }
}
