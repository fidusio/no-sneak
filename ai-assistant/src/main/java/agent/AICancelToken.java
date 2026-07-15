package agent;

import java.io.Closeable;

/**
 * A handle for cancelling a streaming run. Bind the live stream to it once opened, then call
 * {@link #cancel()} to stop it (which closes the bound stream).
 */
public interface AICancelToken {

    /**
     * Requests cancellation and closes the bound stream, if any.
     */
    void cancel();

    /**
     * @return true once {@link #cancel()} has been called.
     */
    boolean cancelled();

    /**
     * Attaches the open stream so {@link #cancel()} can close it.
     */
    void bind(Closeable stream);
}
