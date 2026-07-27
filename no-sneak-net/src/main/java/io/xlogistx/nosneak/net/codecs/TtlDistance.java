package io.xlogistx.nosneak.net.codecs;

import java.util.Optional;

/**
 * Turns an observed TTL into a hop count and a coarse OS hint.
 * <p>
 * Each router decrements the TTL by one, so {@code hopCount = initialTtl -
 * observedTtl}, with the initial value inferred from convention: stacks start at
 * 64, 128, or 255, and the true initial value is the smallest of those that is at
 * least the observed value.
 * <p>
 * TTL is the better of the two distance signals available — RTT includes queuing,
 * target processing delay, and on the first probe the neighbour resolution round
 * trip. But the inferred initial value is CORROBORATING EVIDENCE, NEVER A
 * CONCLUSION: NAT and tunnels rewrite it, tuned stacks depart from the defaults,
 * and it is trivially spoofable.
 * <p>
 * Only feed this a TTL from a backend whose {@code ttlAvailable} capability is
 * set. The {@code -1} sentinel means "this backend cannot tell you" and yields
 * empty here rather than a nonsense distance.
 */
public final class TtlDistance {

    /** Linux, macOS, BSD, and most IoT and embedded stacks. */
    public static final int INITIAL_UNIX = 64;
    /** Windows. */
    public static final int INITIAL_WINDOWS = 128;
    /** Cisco and other network gear, and Solaris. */
    public static final int INITIAL_NETWORK_GEAR = 255;

    private static final int[] INITIAL_VALUES = {
            INITIAL_UNIX, INITIAL_WINDOWS, INITIAL_NETWORK_GEAR};

    private TtlDistance() {
    }

    /**
     * The nearest standard initial TTL at or above {@code observedTtl}, minus the
     * observed value.
     *
     * @return empty when {@code observedTtl <= 0} — which covers the {@code -1}
     *         "unavailable" sentinel — or when it exceeds 255
     */
    public static Optional<Integer> hopCount(int observedTtl) {
        return initialTtl(observedTtl).map(initial -> initial - observedTtl);
    }

    /**
     * The inferred initial TTL, useful on its own for evidence reporting.
     *
     * @return empty for an out-of-range or unavailable TTL
     */
    public static Optional<Integer> initialTtl(int observedTtl) {
        if (observedTtl <= 0 || observedTtl > INITIAL_NETWORK_GEAR) {
            return Optional.empty();
        }
        for (int initial : INITIAL_VALUES) {
            if (observedTtl <= initial) {
                return Optional.of(initial);
            }
        }
        return Optional.empty();
    }

    /**
     * A coarse OS-family hint from the inferred initial TTL. Corroborating
     * evidence only — never report this as a determination.
     */
    public static Optional<String> osHint(int observedTtl) {
        return initialTtl(observedTtl).map(initial -> switch (initial) {
            case INITIAL_UNIX -> "Linux/macOS/BSD";
            case INITIAL_WINDOWS -> "Windows";
            case INITIAL_NETWORK_GEAR -> "network gear/Solaris";
            default -> "unknown";
        });
    }
}
