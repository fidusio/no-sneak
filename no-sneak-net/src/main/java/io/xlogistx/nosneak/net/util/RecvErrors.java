package io.xlogistx.nosneak.net.util;

/**
 * What a blocking reader does with a {@code -1} from {@code recvfrom}: the one policy for
 * every raw-socket loop in the module (§4.4, §13.23-B).
 * <p>
 * Before this, two of the three loops treated every {@code -1} as the {@code SO_RCVTIMEO}
 * tick and looped again — so a descriptor closed underneath the thread ({@code EBADF}, the
 * fd-reuse race §4.4 warns about) or a sticky {@code ENOBUFS} spun a dedicated thread at
 * 100 % forever, silently. The third backed off but never gave up. A reader that cannot read
 * is a backend that cannot answer, and the honest thing is to say so: fail what is pending,
 * degrade {@code capabilities()}, stop.
 * <p>
 * NOT thread-safe; one instance per reader thread, touched only by that thread.
 */
public final class RecvErrors {

    public enum Verdict {
        /** The timeout tick — re-check {@code running} and read again. */
        TICK,
        /** A transient error: sleep one tick on the reader thread (never a pool thread) and retry. */
        BACKOFF,
        /** Dead: fail everything pending, degrade capabilities, leave the loop. */
        FATAL
    }

    /** Consecutive non-timeout errors tolerated before the reader is declared dead. */
    public static final int MAX_CONSECUTIVE = 5;

    private int consecutive;

    /**
     * @param timeout errno is {@code EAGAIN}/{@code EWOULDBLOCK}/{@code EINTR} — the normal tick
     * @param deadFd  errno is {@code EBADF}/{@code ENOTSOCK} — the descriptor is gone
     */
    public Verdict next(boolean timeout, boolean deadFd) {
        if (timeout) {
            consecutive = 0;
            return Verdict.TICK;
        }
        if (deadFd) {
            return Verdict.FATAL;
        }
        consecutive++;
        return consecutive >= MAX_CONSECUTIVE ? Verdict.FATAL : Verdict.BACKOFF;
    }

    /** A successful read resets the transient-error count. */
    public void success() {
        consecutive = 0;
    }

    public int consecutiveErrors() {
        return consecutive;
    }
}
