package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Network/broadcast derivation, which sweep relies on to avoid amplification. */
public class NicBindingTest {

    private static InetAddress ip(String s) {
        return InetAddress.ofLiteral(s);
    }

    private static NicBinding.LocalAddress local(String addr, int prefix) {
        return new NicBinding.LocalAddress(ip(addr), prefix);
    }

    private static NicBinding binding(NicBinding.LocalAddress... v4) {
        return new NicBinding("eth0", "eth0", 1, MacAddress.parse("aa:bb:cc:dd:ee:ff"),
                              List.of(v4), List.of(), 1500);
    }

    @Test
    public void broadcastAndNetworkForA24() {
        NicBinding.LocalAddress a = local("192.168.1.10", 24);
        assertEquals(Optional.of(ip("192.168.1.255")), a.broadcastAddress());
        assertEquals(Optional.of(ip("192.168.1.0")), a.networkAddress());
    }

    @Test
    public void broadcastForAnOddPrefix() {
        assertEquals(Optional.of(ip("10.0.7.255")), local("10.0.0.5", 21).broadcastAddress());
        assertEquals(Optional.of(ip("10.0.0.0")), local("10.0.0.5", 21).networkAddress());
    }

    @Test
    public void slash30HasBoth() {
        assertEquals(Optional.of(ip("10.0.0.3")), local("10.0.0.1", 30).broadcastAddress());
        assertEquals(Optional.of(ip("10.0.0.0")), local("10.0.0.1", 30).networkAddress());
    }

    /** /31 and /32 designate no spare addresses, so there is nothing to skip. */
    @Test
    public void slash31AndSlash32HaveNeither() {
        assertTrue(local("10.0.0.0", 31).broadcastAddress().isEmpty());
        assertTrue(local("10.0.0.0", 31).networkAddress().isEmpty());
        assertTrue(local("10.0.0.5", 32).broadcastAddress().isEmpty());
    }

    @Test
    public void ipv6HasNoBroadcast() {
        assertTrue(local("fe80::1", 64).broadcastAddress().isEmpty());
        assertTrue(local("fe80::1", 64).networkAddress().isEmpty());
    }

    @Test
    public void bindingSkipsItsOwnNetworkAndBroadcast() {
        NicBinding b = binding(local("10.0.0.61", 24));

        assertTrue(b.isNetworkOrBroadcast(ip("10.0.0.0")));
        assertTrue(b.isNetworkOrBroadcast(ip("10.0.0.255")));
        assertFalse(b.isNetworkOrBroadcast(ip("10.0.0.1")));
        assertFalse(b.isNetworkOrBroadcast(ip("10.0.0.7")),
                    "an ordinary host inside the /24 must still be swept");
    }

    /**
     * The test is against the INTERFACE's prefix, not the swept range's — sweeping
     * a /29 inside a /24 must not lose two legitimate hosts to a guess.
     */
    @Test
    public void subRangeEdgesAreNotTreatedAsBroadcast() {
        NicBinding b = binding(local("10.0.0.61", 24));
        assertFalse(b.isNetworkOrBroadcast(ip("10.0.0.8")));
        assertFalse(b.isNetworkOrBroadcast(ip("10.0.0.15")));
    }

    @Test
    public void offLinkAddressesAreNotSkipped() {
        NicBinding b = binding(local("10.0.0.61", 24));
        assertFalse(b.isNetworkOrBroadcast(ip("192.168.1.255")));
    }

    /**
     * Our own address is a resolve special case: nothing on the segment answers an ARP
     * request for it, because the only host that owns it is the one asking. Without
     * this test the distinction from {@link NicBinding#isOnLink} is easy to lose, and
     * losing it costs a full timeout on every self-resolve.
     */
    @Test
    public void ownAddressIsLocalButNeighboursAreNot() {
        NicBinding b = binding(local("10.0.0.61", 24));
        assertTrue(b.isLocalAddress(ip("10.0.0.61")));
        assertFalse(b.isLocalAddress(ip("10.0.0.108")), "an on-link neighbour is not us");
        assertTrue(b.isOnLink(ip("10.0.0.108")), "and it is still on-link");
        assertFalse(b.isLocalAddress(ip("192.168.1.61")));
        assertFalse(b.isLocalAddress(null));
    }

    @Test
    public void localAddressDoesNotMatchAcrossFamilies() {
        NicBinding b = new NicBinding("eth0", "eth0", 1, MacAddress.parse("aa:bb:cc:dd:ee:ff"),
                                      List.of(local("10.0.0.61", 24)),
                                      List.of(local("fe80::1", 64)), 1500);
        assertTrue(b.isLocalAddress(ip("fe80::1")));
        assertFalse(b.isLocalAddress(ip("fe80::2")));
        assertTrue(b.isLocalAddress(ip("10.0.0.61")));
    }
}
