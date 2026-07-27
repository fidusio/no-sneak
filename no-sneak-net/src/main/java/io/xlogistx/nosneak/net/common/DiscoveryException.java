package io.xlogistx.nosneak.net.common;

/**
 * Thrown when a backend cannot be opened at all: missing privilege, pcap not
 * loadable, interface down, no hardware address for an L2 request, or an
 * unsupported architecture.
 * <p>
 * Checked deliberately. This reports a setup failure the caller must handle, and
 * is distinct from an unreachable host — which is never an exception, but a
 * result with {@code received == 0}.
 */
public final class DiscoveryException extends Exception {

    private static final long serialVersionUID = 1L;

    public DiscoveryException(String msg) {
        super(msg);
    }

    public DiscoveryException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
