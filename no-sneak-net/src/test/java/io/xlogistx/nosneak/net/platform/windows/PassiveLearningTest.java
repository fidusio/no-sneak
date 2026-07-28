package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The guards on passive learning.
 * <p>
 * These matter more than a missed sighting would: {@code resolve()} serves the
 * cache, so a wrongly-learned entry is REPORTED as a {@code CACHE_HIT} rather than
 * merely wasting a frame. The off-link case is the one that would do real damage —
 * a remote host's frames arrive bearing the router's MAC.
 */
public class PassiveLearningTest {

    private static final MacAddress SENDER = MacAddress.parse("94:e6:ba:4d:66:1b");
    private static final MacAddress OWN = MacAddress.parse("b0:7b:25:82:64:45");

    private static final NicBinding BINDING = new NicBinding(
            "eth0", "eth0", 4, OWN,
            List.of(new NicBinding.LocalAddress(InetAddress.ofLiteral("10.0.0.61"), 24)),
            List.of(), 1500);

    private static boolean learnable(String ip, MacAddress mac) {
        return WindowsPcapBackend.learnable(BINDING, InetAddress.ofLiteral(ip), mac);
    }

    @Test
    public void anOnLinkSenderIsLearned() {
        assertTrue(learnable("10.0.0.108", SENDER));
        assertTrue(learnable("10.0.0.1", SENDER), "the gateway is a neighbour like any other");
    }

    /**
     * The one that would produce a WRONG answer rather than a missing one: an
     * off-link source's frames carry the router's MAC, so learning them would claim
     * a remote host lives at the gateway's address.
     */
    @Test
    public void anOffLinkSenderIsNeverLearned() {
        assertFalse(learnable("8.8.8.8", SENDER));
        assertFalse(learnable("10.0.1.5", SENDER), "outside the /24 is outside the segment");
    }

    @Test
    public void ourOwnAddressIsNotANeighbour() {
        assertFalse(learnable("10.0.0.61", SENDER));
    }

    @Test
    public void addressesThatBelongToNobodyAreSkipped() {
        assertFalse(learnable("0.0.0.0", SENDER), "a DHCP discover has no source address yet");
        assertFalse(learnable("224.0.0.251", SENDER), "mDNS is a group, not a host");
    }

    /** A sent frame can never legitimately carry these as its SOURCE address. */
    @Test
    public void unusableSourceMacsAreSkipped() {
        assertFalse(learnable("10.0.0.108", MacAddress.parse("00:00:00:00:00:00")));
        assertFalse(learnable("10.0.0.108", MacAddress.BROADCAST));
        assertFalse(learnable("10.0.0.108", MacAddress.parse("01:00:5e:00:00:fb")),
                    "a multicast source MAC is invalid; the check also covers broadcast");
        assertFalse(learnable("10.0.0.108", null));
        assertFalse(WindowsPcapBackend.learnable(BINDING, null, SENDER));
    }

    /**
     * A randomised (locally-administered) MAC is a normal phone or laptop, not a
     * malformed frame — two of the hosts this found on a live segment had one.
     */
    @Test
    public void locallyAdministeredMacsAreLearnedLikeAnyOther() {
        assertTrue(learnable("10.0.0.234", MacAddress.parse("1a:aa:b4:c0:bc:f5")));
        assertTrue(learnable("10.0.0.74", MacAddress.parse("66:29:98:60:2b:5e")));
    }
}
