package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The block arithmetic every sweep starts from. The {@code toAddress} cases pin the two
 * {@link BigInteger#toByteArray()} traps — a sign byte for high-bit values and dropped
 * leading zeros — which are the only way an iterator over addresses can silently drift.
 */
public class CidrRangeTest {

    private static InetAddress ip(String s) {
        return InetAddress.ofLiteral(s);
    }

    private static List<InetAddress> all(String cidr) {
        return CidrRange.parse(cidr).hosts().toList();
    }

    @Test
    public void parseClearsHostBits() {
        assertEquals(CidrRange.parse("192.168.1.0/24"), CidrRange.parse("192.168.1.5/24"));
        assertEquals("192.168.1.0/24", CidrRange.parse("192.168.1.5/24").toString());
        assertEquals(ip("10.0.0.0"), CidrRange.parse("10.0.7.255/21").networkAddress());
        assertEquals(CidrRange.parse("fe80::/64"), CidrRange.parse("fe80::1234/64"));
        assertEquals(ip("fe80::"), CidrRange.parse("fe80::1234/64").networkAddress());
    }

    @Test
    public void parseRejectsMalformedText() {
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("10.0.0.0"));
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("example.com/24"),
                     "a hostname must never be resolved");
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("10.0.0.0/x"));
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("10.0.0.0/33"));
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("10.0.0.0/-1"));
        assertThrows(IllegalArgumentException.class, () -> CidrRange.parse("::/129"));
        assertEquals(1, CidrRange.parse("10.0.0.5/32").hostCount().intValue());
        assertEquals(1, CidrRange.parse("::1/128").hostCount().intValue());
    }

    @Test
    public void slash32HasOneHostAndSlash31HasTwo() {
        assertEquals(BigInteger.ONE, CidrRange.parse("10.0.0.5/32").hostCount());
        assertEquals(List.of(ip("10.0.0.5")), all("10.0.0.5/32"));
        assertEquals(BigInteger.TWO, CidrRange.parse("10.0.0.0/31").hostCount());
        assertEquals(List.of(ip("10.0.0.0"), ip("10.0.0.1")), all("10.0.0.0/31"));
    }

    /** hosts() yields EVERY address; withholding the edges is sweep policy, not range policy. */
    @Test
    public void slash30YieldsAllFourIncludingEdges() {
        assertEquals(List.of(ip("10.0.0.0"), ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")),
                     all("10.0.0.0/30"));
        assertEquals(256, all("10.0.0.0/24").size());
    }

    @Test
    public void ipv6IterationIsLazyAndOrdered() {
        assertEquals(List.of(ip("2001:db8::"), ip("2001:db8::1"), ip("2001:db8::2"), ip("2001:db8::3")),
                     all("2001:db8::/126"));
        CidrRange slash64 = CidrRange.parse("fe80::/64");
        assertEquals(BigInteger.ONE.shiftLeft(64), slash64.hostCount());
        assertEquals(List.of(ip("fe80::"), ip("fe80::1"), ip("fe80::2")),
                     slash64.hosts().limit(3).toList(),
                     "a /64 must be iterable without materialising 2^64 addresses");
    }

    /** 224.0.0.0 has the high bit set: BigInteger.toByteArray emits a sign byte. */
    @Test
    public void toAddressRightAlignsWhenBigIntegerEmitsASignByte() {
        List<InetAddress> multicast = all("224.0.0.0/24");
        assertEquals(ip("224.0.0.0"), multicast.get(0));
        assertEquals(ip("224.0.0.255"), multicast.get(255));
        assertEquals(ip("ff02::"), CidrRange.parse("ff02::/16").hosts().findFirst().orElseThrow());
        assertEquals(ip("ff02::1"), CidrRange.parse("ff02::/16").hosts().skip(1).findFirst().orElseThrow());
    }

    /** 0.0.0.0 has leading zero bytes: BigInteger.toByteArray drops them. */
    @Test
    public void toAddressPadsWhenBigIntegerDropsLeadingZeros() {
        List<InetAddress> zero = CidrRange.parse("0.0.0.0/8").hosts().limit(2).toList();
        assertEquals(List.of(ip("0.0.0.0"), ip("0.0.0.1")), zero);
        List<InetAddress> unspecified = CidrRange.parse("::/64").hosts().limit(2).toList();
        assertEquals(List.of(ip("::"), ip("::1")), unspecified);
    }

    @Test
    public void containsWithNonOctetPrefix() {
        CidrRange slash21 = CidrRange.parse("10.0.0.0/21");
        assertTrue(slash21.contains(ip("10.0.7.255")));
        assertFalse(slash21.contains(ip("10.0.8.0")));
        CidrRange slash13 = CidrRange.parse("10.8.0.0/13");
        assertTrue(slash13.contains(ip("10.15.255.255")));
        assertFalse(slash13.contains(ip("10.16.0.0")));
        assertFalse(CidrRange.parse("10.0.0.0/8").contains(ip("::1")),
                    "a family mismatch is never contained");
    }

    @Test
    public void lastAddressIsTheAllOnesHost() {
        assertEquals(ip("10.1.0.255"), CidrRange.parse("10.1.0.0/24").lastAddress());
        assertEquals(ip("10.0.7.255"), CidrRange.parse("10.0.0.0/21").lastAddress());
        assertEquals(ip("10.0.0.1"), CidrRange.parse("10.0.0.0/31").lastAddress());
        assertEquals(ip("10.0.0.5"), CidrRange.parse("10.0.0.5/32").lastAddress());
        assertEquals(ip("fe80::ffff:ffff:ffff:ffff"), CidrRange.parse("fe80::/64").lastAddress());
    }
}
