package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code WindowsPcapBackend.capabilitiesOf}, pure — no handle, no wire (§13.23-B, M4/M7). */
public class WindowsCapabilitiesTest {

    private static final MacAddress MAC = MacAddress.parse("b0:7b:25:82:64:45");
    private static final NicBinding.LocalAddress V4 =
            new NicBinding.LocalAddress(InetAddress.ofLiteral("10.0.0.61"), 24);
    private static final NicBinding.LocalAddress V6 =
            new NicBinding.LocalAddress(InetAddress.ofLiteral("fe80::1"), 64);

    private static NicBinding binding(MacAddress mac, List<NicBinding.LocalAddress> v4,
                                      List<NicBinding.LocalAddress> v6) {
        return new NicBinding("eth0", "\\Device\\NPF_{x}", 4, mac, v4, v6, 1500);
    }

    @Test
    public void dualStackWithInjectionHasEverything() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(V4), List.of(V6)), true);
        assertTrue(c.icmpV4() && c.icmpV6() && c.activeArp() && c.activeNdp());
        assertTrue(c.passiveObservation() && c.rawEvidence() && c.ttlAvailable());
        assertTrue(c.offLinkIcmp());
        assertEquals(DiscoveryCapabilities.Backend.WINDOWS_PCAP, c.backend());
    }

    @Test
    public void ipv6OnlyBindingGetsNdpWithoutArp() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(), List.of(V6)), true);
        assertFalse(c.activeArp());
        assertFalse(c.icmpV4());
        assertTrue(c.activeNdp());
        assertTrue(c.icmpV6());
    }

    @Test
    public void ipv4OnlyBindingGetsArpWithoutNdp() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(V4), List.of()), true);
        assertTrue(c.activeArp() && c.icmpV4());
        assertFalse(c.activeNdp() || c.icmpV6());
    }

    @Test
    public void refusedInjectionLeavesPassiveObservationOnly() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(false, true,
                binding(MAC, List.of(V4), List.of(V6)), true);
        assertFalse(c.anyLayer2());
        assertFalse(c.anyIcmp());
        assertFalse(c.offLinkIcmp());
        assertTrue(c.passiveObservation());
        assertTrue(c.rawEvidence());
    }

    @Test
    public void aDeadReaderReportsNothingActiveOrPassive() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(true, false,
                binding(MAC, List.of(V4), List.of(V6)), true);
        assertFalse(c.anyLayer2() || c.anyIcmp());
        assertFalse(c.passiveObservation() || c.rawEvidence() || c.ttlAvailable() || c.offLinkIcmp());
    }

    @Test
    public void noHardwareAddressMeansNoLayer2() {
        DiscoveryCapabilities c = WindowsPcapBackend.capabilitiesOf(true, true,
                binding(null, List.of(V4), List.of()), true);
        assertFalse(c.anyLayer2() || c.anyIcmp());
        assertTrue(c.passiveObservation());
    }

    @Test
    public void offLinkNeedsBothInjectionAndIphlpapi() {
        NicBinding b = binding(MAC, List.of(V4), List.of());
        assertTrue(WindowsPcapBackend.capabilitiesOf(true, true, b, true).offLinkIcmp());
        assertFalse(WindowsPcapBackend.capabilitiesOf(true, true, b, false).offLinkIcmp());
        assertFalse(WindowsPcapBackend.capabilitiesOf(false, true, b, true).offLinkIcmp());
    }
}
