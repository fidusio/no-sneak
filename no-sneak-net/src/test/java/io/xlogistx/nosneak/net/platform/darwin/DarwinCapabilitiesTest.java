package io.xlogistx.nosneak.net.platform.darwin;

import io.xlogistx.nosneak.net.common.DiscoveryCapabilities;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code DarwinPcapBackend.capabilitiesOf}, pure — no handle, no wire (§13.23-B, M4/M7). */
public class DarwinCapabilitiesTest {

    private static final MacAddress MAC = MacAddress.parse("b0:7b:25:82:64:45");
    private static final NicBinding.LocalAddress V4 =
            new NicBinding.LocalAddress(InetAddress.ofLiteral("10.0.0.61"), 24);
    private static final NicBinding.LocalAddress V6 =
            new NicBinding.LocalAddress(InetAddress.ofLiteral("fe80::1"), 64);

    /** What DarwinIcmpPing reports when both sockets opened. */
    private static final DiscoveryCapabilities PINGER = new DiscoveryCapabilities(
            true, true, false, false, false, false, false, true,
            DiscoveryCapabilities.Backend.MACOS_NATIVE);

    private static NicBinding binding(MacAddress mac, List<NicBinding.LocalAddress> v4,
                                      List<NicBinding.LocalAddress> v6) {
        return new NicBinding("en0", "en0", 4, mac, v4, v6, 1500);
    }

    @Test
    public void noPingerMeansNoIcmpAndNoRawEvidence() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(V4), List.of(V6)), null);
        assertFalse(c.anyIcmp());
        assertFalse(c.rawEvidence());
        assertFalse(c.ttlAvailable());
        assertFalse(c.offLinkIcmp());
        assertTrue(c.activeArp() && c.activeNdp() && c.passiveObservation());
        assertEquals(DiscoveryCapabilities.Backend.MACOS_NATIVE, c.backend());
    }

    /** M4: the old literal {@code true} promised bytes nothing ever delivered. */
    @Test
    public void rawEvidenceFollowsThePingerNotTheCapture() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(V4), List.of(V6)), PINGER);
        assertTrue(c.icmpV4() && c.icmpV6() && c.offLinkIcmp());
        assertFalse(c.rawEvidence(), "DarwinIcmpPing fills rawReply empty; the capture has no delivery path");
        assertFalse(c.ttlAvailable(), "the datagram socket strips the IP header");
    }

    @Test
    public void ipv6OnlyBindingGetsNdpWithoutArp() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(), List.of(V6)), PINGER);
        assertFalse(c.activeArp());
        assertTrue(c.activeNdp());
    }

    @Test
    public void ipv4OnlyBindingGetsArpWithoutNdp() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, true,
                binding(MAC, List.of(V4), List.of()), PINGER);
        assertTrue(c.activeArp());
        assertFalse(c.activeNdp());
    }

    @Test
    public void refusedInjectionLeavesPassiveObservationOnly() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(false, true,
                binding(MAC, List.of(V4), List.of(V6)), PINGER);
        assertFalse(c.anyLayer2());
        assertTrue(c.passiveObservation());
        assertTrue(c.anyIcmp(), "ICMP is the pinger's, and the pinger does not inject");
    }

    @Test
    public void aDeadReaderReportsNothingActiveOrPassive() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, false,
                binding(MAC, List.of(V4), List.of(V6)), PINGER);
        assertFalse(c.anyLayer2());
        assertFalse(c.passiveObservation());
        assertTrue(c.anyIcmp(), "the pinger's sockets are not this reader's");
    }

    @Test
    public void noHardwareAddressMeansNoLayer2() {
        DiscoveryCapabilities c = DarwinPcapBackend.capabilitiesOf(true, true,
                binding(null, List.of(V4), List.of(V6)), PINGER);
        assertFalse(c.anyLayer2());
        assertTrue(c.passiveObservation());
    }
}
