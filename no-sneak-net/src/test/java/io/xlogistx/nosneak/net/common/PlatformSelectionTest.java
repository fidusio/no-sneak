package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.pcap.PcapPlatform;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two {@code os.name} dispatchers must agree. They did not: {@code PcapPlatform}
 * tested {@code contains("win")} first, and {@code "darwin".contains("win")} is true,
 * so a JVM reporting {@code Darwin} was sent to the Npcap backend by one dispatcher and
 * to macOS by the other (§13.21 S1). The cross-check is worth more than either
 * assertion alone.
 */
public class PlatformSelectionTest {

    private static final Map<String, HostDiscoveryFactory.Platform> FACTORY = Map.of(
            "Mac OS X", HostDiscoveryFactory.Platform.MACOS,
            "Darwin", HostDiscoveryFactory.Platform.MACOS,
            "Windows 11", HostDiscoveryFactory.Platform.WINDOWS,
            "Windows 10", HostDiscoveryFactory.Platform.WINDOWS,
            "Linux", HostDiscoveryFactory.Platform.LINUX);

    private static final Map<String, PcapPlatform> PCAP = Map.of(
            "Mac OS X", PcapPlatform.DARWIN,
            "Darwin", PcapPlatform.DARWIN,
            "Windows 11", PcapPlatform.WINDOWS,
            "Windows 10", PcapPlatform.WINDOWS,
            "Linux", PcapPlatform.LINUX);

    @Test
    public void theTwoDispatchersAgreeOnEveryKnownOsName() throws DiscoveryException {
        for (String os : FACTORY.keySet()) {
            assertEquals(FACTORY.get(os), HostDiscoveryFactory.Platform.forOsName(os), os);
            assertEquals(PCAP.get(os), PcapPlatform.forOsName(os), os);
        }
    }

    @Test
    public void darwinIsNotWindows() throws DiscoveryException {
        assertEquals(PcapPlatform.DARWIN, PcapPlatform.forOsName("Darwin"));
        assertEquals(HostDiscoveryFactory.Platform.MACOS,
                     HostDiscoveryFactory.Platform.forOsName("Darwin"));
    }

    @Test
    public void unknownOsIsRejectedByBothAndNamesIt() {
        DiscoveryException a = assertThrows(DiscoveryException.class,
                () -> PcapPlatform.forOsName("SunOS"));
        DiscoveryException b = assertThrows(DiscoveryException.class,
                () -> HostDiscoveryFactory.Platform.forOsName("SunOS"));
        assertTrue(a.getMessage().contains("SunOS"));
        assertTrue(b.getMessage().contains("SunOS"));
    }

    @Test
    public void nullAndEmptyAreRejected() {
        assertThrows(DiscoveryException.class, () -> PcapPlatform.forOsName(null));
        assertThrows(DiscoveryException.class, () -> PcapPlatform.forOsName(""));
        assertThrows(DiscoveryException.class, () -> HostDiscoveryFactory.Platform.forOsName(null));
        assertThrows(DiscoveryException.class, () -> HostDiscoveryFactory.Platform.forOsName(""));
    }
}
