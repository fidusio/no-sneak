package io.xlogistx.nosneak.v2.runtime;

import org.junit.jupiter.api.Test;

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
        Fanout.run(children, joined::countDown);
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
        Fanout.run(children, joined::countDown);
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
        Fanout.run(children, joined::countDown);
        assertTrue(joined.await(15, TimeUnit.SECONDS));
    }

    @Test
    public void fanoutWithNoChildrenFiresImmediately() throws Exception {
        CountDownLatch joined = new CountDownLatch(1);
        Fanout.run(Collections.emptyList(), joined::countDown);
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
        Fanout.dispatch(tasks);
        assertTrue(ran.await(15, TimeUnit.SECONDS), "not every dispatched task ran");
    }

    @Test
    public void dispatchToleratesEmptyAndNull() {
        Fanout.dispatch(Collections.emptyList());
        Fanout.dispatch(null);
    }
}
