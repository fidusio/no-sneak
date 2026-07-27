package io.xlogistx.nosneak.net.codecs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** TTL-to-distance inference, concentrated on the boundaries where it flips. */
public class TtlDistanceTest {

    /** A TTL landing exactly on a standard initial value means zero hops — on-link. */
    @ParameterizedTest
    @ValueSource(ints = {64, 128, 255})
    public void standardInitialValuesAreZeroHops(int ttl) {
        assertEquals(Optional.of(0), TtlDistance.hopCount(ttl));
    }

    /** One below each boundary is one hop, not a jump to the next tier. */
    @ParameterizedTest
    @CsvSource({
            "63, 1",
            "127, 1",
            "254, 1",
            "60, 4",
            "120, 8",
            "250, 5"
    })
    public void oneBelowEachBoundary(int observed, int expectedHops) {
        assertEquals(Optional.of(expectedHops), TtlDistance.hopCount(observed));
    }

    /**
     * One ABOVE a boundary must round up to the next tier, not down. A TTL of 65
     * cannot have started at 64, so it started at 128 and has travelled 63 hops.
     */
    @ParameterizedTest
    @CsvSource({
            "65, 128, 63",
            "129, 255, 126",
            "1, 64, 63"
    })
    public void aboveABoundaryRoundsUpToTheNextTier(int observed, int initial, int hops) {
        assertEquals(Optional.of(initial), TtlDistance.initialTtl(observed));
        assertEquals(Optional.of(hops), TtlDistance.hopCount(observed));
    }

    /**
     * The -1 sentinel means "this backend cannot report a TTL" and must never
     * become a distance.
     */
    @ParameterizedTest
    @ValueSource(ints = {-1, 0, -100})
    public void unavailableOrNonPositiveYieldsEmpty(int ttl) {
        assertEquals(Optional.empty(), TtlDistance.hopCount(ttl));
        assertEquals(Optional.empty(), TtlDistance.initialTtl(ttl));
        assertEquals(Optional.empty(), TtlDistance.osHint(ttl));
    }

    /** A TTL is an octet; anything above 255 is corrupt input, not a far-away host. */
    @ParameterizedTest
    @ValueSource(ints = {256, 1000})
    public void outOfRangeYieldsEmpty(int ttl) {
        assertEquals(Optional.empty(), TtlDistance.hopCount(ttl));
    }

    @ParameterizedTest
    @CsvSource({
            "64, Linux/macOS/BSD",
            "60, Linux/macOS/BSD",
            "128, Windows",
            "120, Windows",
            "255, network gear/Solaris",
            "250, network gear/Solaris"
    })
    public void osHintFollowsTheInferredInitialValue(int ttl, String expected) {
        assertEquals(Optional.of(expected), TtlDistance.osHint(ttl));
    }
}
