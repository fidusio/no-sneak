package io.xlogistx.nosneak.runtime;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The counting barrier behind every stage of the scanner. Nothing here blocks: the last child
 * to report runs the continuation on its own thread. {@link CountdownMonitor#addChild()} is what
 * lets a connect callback hand the same barrier a follow-up probe sweep, so the port stage
 * and identification overlap without a second barrier.
 */
public class CountdownMonitorTest {

    @Test
    public void firesExactlyOnceWhenTheLastChildReports() {
        AtomicInteger fired = new AtomicInteger();
        CountdownMonitor j = new CountdownMonitor(3, fired::incrementAndGet);
        j.childDone();
        j.childDone();
        assertEquals(0, fired.get());
        assertEquals(1, j.remaining());
        j.childDone();
        assertEquals(1, fired.get());
        j.childDone(); // an extra report never fires it again
        assertEquals(1, fired.get());
    }

    @Test
    public void zeroChildrenFiresImmediately() {
        AtomicInteger fired = new AtomicInteger();
        new CountdownMonitor(0, fired::incrementAndGet);
        assertEquals(1, fired.get());
    }

    @Test
    public void aChildAddedMidFlightDefersTheFire() {
        AtomicInteger fired = new AtomicInteger();
        CountdownMonitor j = new CountdownMonitor(1, fired::incrementAndGet);
        // The one registered child learns something and hands the barrier a follow-up, then
        // reports its own completion — the shape of "port connected, probe it".
        assertTrue(j.addChild());
        j.childDone();
        assertEquals(0, fired.get(), "the follow-up is still outstanding");
        assertEquals(1, j.remaining());
        j.childDone();
        assertEquals(1, fired.get());
    }

    @Test
    public void aChildCannotBeAddedAfterTheBarrierFired() {
        AtomicInteger fired = new AtomicInteger();
        CountdownMonitor j = new CountdownMonitor(1, fired::incrementAndGet);
        j.childDone();
        assertEquals(1, fired.get());
        assertFalse(j.addChild());
        assertEquals(0, j.remaining(), "a refused add leaves the count untouched");
    }
}
