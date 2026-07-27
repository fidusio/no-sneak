package io.xlogistx.nosneak.net.common;

import java.io.Closeable;

/**
 * Handle to a registration made through {@link HostDiscovery#observe}. Closing it
 * unsubscribes.
 * <p>
 * {@link #close()} is narrowed to not throw {@link java.io.IOException}, so these
 * can be used in try-with-resources without a pointless catch.
 */
public interface Subscription extends Closeable {

    @Override
    void close();
}
