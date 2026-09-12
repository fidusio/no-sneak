package io.xlogistx.nosneak.service;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The scan counter v1 reported as {@code total-scanned}: seeded from the HTTP server
 * configuration's {@code start-count-at} property (the way {@code http_server_config.json}
 * declares it) through {@code PropertyContainer.setProperties}, ignored when absent or
 * non-positive.
 */
public class CheckerCountTest {

    @Test
    public void startCountAtSeedsTheCounter() {
        Checker checker = new Checker();
        NVGenericMap props = new NVGenericMap();
        props.add(new NVLong("start-count-at", 1279));
        checker.setProperties(props);
        assertEquals(1279L, Checker.scanCount());
    }

    @Test
    public void aMissingOrNonPositiveSeedLeavesTheCounterAlone() {
        Checker checker = new Checker();
        NVGenericMap props = new NVGenericMap();
        props.add(new NVLong("start-count-at", 4242));
        checker.setProperties(props);
        long before = Checker.scanCount();

        checker.setProperties(new NVGenericMap());
        assertEquals(before, Checker.scanCount(), "no property, no change");

        NVGenericMap zero = new NVGenericMap();
        zero.add(new NVLong("start-count-at", 0));
        checker.setProperties(zero);
        assertEquals(before, Checker.scanCount(), "a non-positive seed is ignored");
        assertTrue(Checker.scanCount() > 0);
    }
}
