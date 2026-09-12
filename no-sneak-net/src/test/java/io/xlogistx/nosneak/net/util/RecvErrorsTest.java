package io.xlogistx.nosneak.net.util;

import org.junit.jupiter.api.Test;

import static io.xlogistx.nosneak.net.util.RecvErrors.Verdict.BACKOFF;
import static io.xlogistx.nosneak.net.util.RecvErrors.Verdict.FATAL;
import static io.xlogistx.nosneak.net.util.RecvErrors.Verdict.TICK;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** The read-error policy every raw-socket reader follows (§4.4). */
public class RecvErrorsTest {

    @Test
    public void timeoutIsATickAndResetsTheCount() {
        RecvErrors g = new RecvErrors();
        assertEquals(BACKOFF, g.next(false, false));
        assertEquals(BACKOFF, g.next(false, false));
        assertEquals(TICK, g.next(true, false));
        assertEquals(0, g.consecutiveErrors());
        assertEquals(BACKOFF, g.next(false, false));
        assertEquals(1, g.consecutiveErrors());
    }

    @Test
    public void deadDescriptorIsFatalOnFirstSight() {
        RecvErrors g = new RecvErrors();
        assertEquals(FATAL, g.next(false, true));
    }

    @Test
    public void fiveConsecutiveTransientErrorsAreFatal() {
        RecvErrors g = new RecvErrors();
        for (int i = 1; i < RecvErrors.MAX_CONSECUTIVE; i++) {
            assertEquals(BACKOFF, g.next(false, false), "error #" + i);
        }
        assertEquals(FATAL, g.next(false, false));
    }

    @Test
    public void aSuccessfulReadResetsTheCount() {
        RecvErrors g = new RecvErrors();
        for (int i = 1; i < RecvErrors.MAX_CONSECUTIVE; i++) {
            g.next(false, false);
        }
        g.success();
        assertEquals(0, g.consecutiveErrors());
        assertEquals(BACKOFF, g.next(false, false));
    }

    /** A timeout that is ALSO flagged dead is still the tick: the fd is only dead if the kernel said so. */
    @Test
    public void timeoutWinsOverAContradictoryDeadFlag() {
        assertEquals(TICK, new RecvErrors().next(true, true));
    }
}
