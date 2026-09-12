package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every compact-constructor rejection, so an invalid option fails at construction and
 * names the field, rather than mid-sweep. §13.3 claimed this was pinned; now it is.
 */
public class SweepOptionsTest {

    private static final Duration SECOND = Duration.ofSeconds(1);

    private static IllegalArgumentException rejects(int inFlight, int pps, Duration timeout,
                                                    int pingCount, long maxHosts) {
        return assertThrows(IllegalArgumentException.class,
                () -> new SweepOptions(inFlight, pps, timeout, true, true, pingCount, maxHosts));
    }

    @Test
    public void rejectsZeroMaxInFlight() {
        assertTrue(rejects(0, 2000, SECOND, 1, 256).getMessage().contains("maxInFlight"));
    }

    @Test
    public void rejectsNegativePacketsPerSecond() {
        assertTrue(rejects(256, -1, SECOND, 1, 256).getMessage().contains("maxPacketsPerSecond"));
    }

    @Test
    public void rejectsZeroPingCount() {
        assertTrue(rejects(256, 2000, SECOND, 0, 256).getMessage().contains("pingCount"));
    }

    @Test
    public void rejectsZeroMaxHosts() {
        assertTrue(rejects(256, 2000, SECOND, 1, 0).getMessage().contains("maxHosts"));
    }

    @Test
    public void rejectsNullZeroOrNegativeTimeout() {
        assertTrue(rejects(256, 2000, null, 1, 256).getMessage().contains("perHostTimeout"));
        assertTrue(rejects(256, 2000, Duration.ZERO, 1, 256).getMessage().contains("perHostTimeout"));
        assertTrue(rejects(256, 2000, Duration.ofMillis(-1), 1, 256).getMessage()
                           .contains("perHostTimeout"));
    }

    /** Zero means unlimited — the pacer is skipped entirely — and must be accepted. */
    @Test
    public void zeroPacketsPerSecondMeansUnlimitedAndIsAccepted() {
        SweepOptions o = new SweepOptions(1, 0, SECOND, false, false, 1, 1);
        assertEquals(0, o.maxPacketsPerSecond());
    }

    @Test
    public void defaultsAreValid() {
        SweepOptions d = SweepOptions.defaults();
        assertEquals(256, d.maxInFlight());
        assertEquals(2000, d.maxPacketsPerSecond());
        assertEquals(Duration.ofMillis(1000), d.perHostTimeout());
        assertTrue(d.doIcmp());
        assertTrue(d.doMac());
        assertEquals(1, d.pingCount());
        assertEquals(65536, d.maxHosts());
    }
}
