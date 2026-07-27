package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.common.MacAddress;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code /proc/net/arp} hint parser.
 * <p>
 * These run anywhere: {@link KernelNeighbors#find} takes the file's lines rather than
 * reading them, precisely so the format can be pinned without a Linux {@code /proc} —
 * the same reason the layout tests are host-independent.
 */
class KernelNeighborsTest {

    private static final String HEADER =
            "IP address       HW type     Flags       HW address            Mask     Device";

    /** The real thing, copied verbatim from the segment this was debugged on. */
    private static final List<String> TABLE = List.of(
            HEADER,
            "10.0.0.108       0x1         0x2         94:e6:ba:4d:66:1b     *        eth0",
            "10.0.0.39        0x1         0x2         26:7f:18:c4:32:bf     *        eth0",
            "10.0.0.77        0x1         0x0         00:00:00:00:00:00     *        eth0",
            "10.0.0.200       0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1");

    @Test
    @DisplayName("returns the MAC of a complete entry on the right device")
    void findsCompleteEntry() {
        assertEquals(Optional.of(MacAddress.parse("94:e6:ba:4d:66:1b")),
                     KernelNeighbors.find(TABLE, "10.0.0.108", "eth0"));
    }

    @Test
    @DisplayName("an INCOMPLETE entry yields no hint, not a zero MAC")
    void rejectsIncompleteEntry() {
        // Flags 0x0 means the kernel is still resolving; the MAC column is all zeros
        // and aiming a unicast frame at it would send to nowhere.
        assertTrue(KernelNeighbors.find(TABLE, "10.0.0.77", "eth0").isEmpty());
    }

    @Test
    @DisplayName("an entry on a DIFFERENT interface is not ours to use")
    void ignoresOtherDevice() {
        // Same address space can exist on two segments; a hint from eth1 would aim an
        // eth0 frame at a MAC that is not on eth0's wire.
        assertTrue(KernelNeighbors.find(TABLE, "10.0.0.200", "eth0").isEmpty());
        assertEquals(Optional.of(MacAddress.parse("aa:bb:cc:dd:ee:ff")),
                     KernelNeighbors.find(TABLE, "10.0.0.200", "eth1"));
    }

    @Test
    @DisplayName("an address with no entry yields no hint")
    void missingAddress() {
        assertTrue(KernelNeighbors.find(TABLE, "10.0.0.250", "eth0").isEmpty());
    }

    @Test
    @DisplayName("the header row is never parsed as data")
    void skipsHeader() {
        assertTrue(KernelNeighbors.find(TABLE, "IP", "Device").isEmpty());
        assertTrue(KernelNeighbors.find(List.of(HEADER), "10.0.0.108", "eth0").isEmpty());
    }

    @Test
    @DisplayName("malformed input degrades to no hint rather than throwing")
    void toleratesGarbage() {
        // This is a best-effort hint on a path that has already failed, so every
        // malformed shape must return empty rather than break resolution.
        assertTrue(KernelNeighbors.find(List.of(), "10.0.0.1", "eth0").isEmpty());
        assertTrue(KernelNeighbors.find(null, "10.0.0.1", "eth0").isEmpty());
        assertTrue(KernelNeighbors.find(List.of(HEADER, "truncated row"),
                                        "10.0.0.1", "eth0").isEmpty());
        assertTrue(KernelNeighbors.find(
                List.of(HEADER, "10.0.0.1  0x1  notahexflag  aa:bb:cc:dd:ee:ff  *  eth0"),
                "10.0.0.1", "eth0").isEmpty(), "unparseable flags are not complete");
        assertTrue(KernelNeighbors.find(
                List.of(HEADER, "10.0.0.1  0x1  0x2  not:a:mac  *  eth0"),
                "10.0.0.1", "eth0").isEmpty());
    }

    @Test
    @DisplayName("a broadcast or multicast MAC is never offered as a unicast hint")
    void rejectsNonUnicast() {
        // The point of the hint is to address ONE station. A broadcast hint would
        // silently reproduce the very delivery failure the unicast retry exists to
        // route around.
        assertTrue(KernelNeighbors.find(
                List.of(HEADER, "10.0.0.1  0x1  0x2  ff:ff:ff:ff:ff:ff  *  eth0"),
                "10.0.0.1", "eth0").isEmpty());
        assertTrue(KernelNeighbors.find(
                List.of(HEADER, "10.0.0.1  0x1  0x2  01:00:5e:00:00:01  *  eth0"),
                "10.0.0.1", "eth0").isEmpty());
    }
}
