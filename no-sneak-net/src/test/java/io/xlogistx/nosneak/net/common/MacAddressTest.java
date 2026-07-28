package io.xlogistx.nosneak.net.common;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link MacAddress} — value semantics, parsing, and the three predicates the
 * backends branch on.
 * <p>
 * Value equality is the reason this type is a class rather than a record, so it is
 * tested through the collections that depend on it: {@code IpMacCache} stores these
 * and detects conflicts by comparing them, and a reference-identity {@code equals}
 * would make every cached MAC look like a conflict with itself.
 */
public class MacAddressTest {

    private static final byte[] SIX = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC,
                                       (byte) 0xDD, (byte) 0xEE, (byte) 0xFF};

    // ---- construction ----

    @Test
    public void sixBytesRoundTrip() {
        MacAddress mac = new MacAddress(SIX);
        assertArrayEqualsAsHex(SIX, mac.bytes());
        assertEquals("aa:bb:cc:dd:ee:ff", mac.toString());
        assertEquals(6, MacAddress.LENGTH);
    }

    /** The constructor copies: a caller reusing its buffer must not mutate ours. */
    @Test
    public void theConstructorTakesADefensiveCopy() {
        byte[] source = SIX.clone();
        MacAddress mac = new MacAddress(source);
        source[0] = 0x00;
        assertEquals("aa:bb:cc:dd:ee:ff", mac.toString());
    }

    /** And so does the accessor, or a caller could rewrite a cached address. */
    @Test
    public void bytesReturnsACopyEachTime() {
        MacAddress mac = new MacAddress(SIX);
        byte[] first = mac.bytes();
        byte[] second = mac.bytes();
        assertNotSame(first, second);
        first[0] = 0x00;
        assertEquals("aa:bb:cc:dd:ee:ff", mac.toString());
        assertArrayEqualsAsHex(SIX, mac.bytes());
    }

    @Test
    public void wrongLengthsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(null));
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(new byte[5]));
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(new byte[7]));
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(new byte[8]));
    }

    /** The message has to name the problem — these surface in CLI output. */
    @Test
    public void theLengthErrorSaysWhatWasWrong() {
        String message = assertThrows(IllegalArgumentException.class,
                                      () -> new MacAddress(new byte[5])).getMessage();
        assertTrue(message.contains("6"), message);
        assertTrue(message.contains("5"), message);
        assertTrue(assertThrows(IllegalArgumentException.class,
                                () -> new MacAddress(null)).getMessage().contains("null"));
    }

    // ---- parsing ----

    @Test
    public void everyDocumentedFormatParsesToTheSameAddress() {
        MacAddress expected = new MacAddress(SIX);
        assertEquals(expected, MacAddress.parse("aa:bb:cc:dd:ee:ff"));
        assertEquals(expected, MacAddress.parse("aa-bb-cc-dd-ee-ff"));
        assertEquals(expected, MacAddress.parse("aabb.ccdd.eeff"));
        assertEquals(expected, MacAddress.parse("aabbccddeeff"));
    }

    @Test
    public void caseIsIrrelevantOnInput() {
        MacAddress expected = new MacAddress(SIX);
        assertEquals(expected, MacAddress.parse("AA:BB:CC:DD:EE:FF"));
        assertEquals(expected, MacAddress.parse("Aa:bB:Cc:dD:Ee:fF"));
        assertEquals(expected, MacAddress.parse("AABBCCDDEEFF"));
    }

    /** Windows prints dashes, tcpdump prints colons, Cisco prints dots. */
    @Test
    public void realWorldAddressesFromEachPlatformsTooling() {
        assertEquals("42:25:47:35:03:ec", MacAddress.parse("42-25-47-35-03-EC").toString());
        assertEquals("94:e6:ba:4d:66:1b", MacAddress.parse("94:e6:ba:4d:66:1b").toString());
        assertEquals("b8:27:eb:30:40:d7", MacAddress.parse("b827.eb30.40d7").toString());
    }

    /** A leading zero must survive: {@code 00:1e:06} is not {@code 1e:06}. */
    @Test
    public void leadingZeroBytesArePreserved() {
        MacAddress mac = MacAddress.parse("00:1e:06:42:3c:6c");
        assertEquals("00:1e:06:42:3c:6c", mac.toString());
        assertEquals(0x00, mac.bytes()[0]);
        assertEquals(0x1e, mac.bytes()[1]);
    }

    @Test
    public void toStringIsLowerCaseColonDelimitedAndReparses() {
        MacAddress mac = MacAddress.parse("AA-BB-CC-DD-EE-FF");
        assertEquals("aa:bb:cc:dd:ee:ff", mac.toString());
        assertEquals(mac, MacAddress.parse(mac.toString()), "toString must round-trip");
    }

    @Test
    public void wrongDigitCountsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse(""));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aa:bb:cc:dd:ee"));
        assertThrows(IllegalArgumentException.class,
                     () -> MacAddress.parse("aa:bb:cc:dd:ee:ff:00"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aabbccddeef"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aabbccddeeff0"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse(":::::"));
    }

    @Test
    public void nonHexTextIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse(null));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("gg:bb:cc:dd:ee:ff"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("not a mac"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aa:bb:cc:dd:ee:fg"));
    }

    /**
     * Whitespace is NOT a separator, so a padded field fails. Worth pinning: a UI
     * that hands user input straight through has to trim it first, and the failure
     * is an exception rather than a silently different address.
     */
    @Test
    public void surroundingWhitespaceIsNotAccepted() {
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse(" aa:bb:cc:dd:ee:ff"));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aa:bb:cc:dd:ee:ff "));
        assertThrows(IllegalArgumentException.class, () -> MacAddress.parse("aa bb cc dd ee ff"));
    }

    /**
     * The parser strips separators rather than validating their placement, so mixed
     * and misplaced delimiters are accepted. Recorded as the behaviour it is — if a
     * stricter parser is ever wanted, this test is the one that must change
     * deliberately rather than break by surprise.
     */
    @Test
    public void separatorPlacementIsNotValidated() {
        MacAddress expected = new MacAddress(SIX);
        assertEquals(expected, MacAddress.parse("aa:bb-cc.ddeeff"));
        assertEquals(expected, MacAddress.parse("a:abbccddeef:f"));
        assertEquals(expected, MacAddress.parse("--aabbccddeeff--"));
    }

    // ---- predicates ----

    @Test
    public void broadcastIsAllOnes() {
        assertTrue(MacAddress.BROADCAST.isBroadcast());
        assertEquals("ff:ff:ff:ff:ff:ff", MacAddress.BROADCAST.toString());
        assertEquals(MacAddress.BROADCAST, MacAddress.parse("ff:ff:ff:ff:ff:ff"));
        assertFalse(MacAddress.parse("ff:ff:ff:ff:ff:fe").isBroadcast(), "one bit short");
        assertFalse(MacAddress.parse("fe:ff:ff:ff:ff:ff").isBroadcast());
        assertFalse(new MacAddress(SIX).isBroadcast());
    }

    /** The group bit is the LOW bit of the FIRST octet — nothing else. */
    @Test
    public void multicastIsTheGroupBitOfTheFirstOctet() {
        assertTrue(MacAddress.parse("01:00:5e:00:00:fb").isMulticast(), "IPv4 multicast, mDNS");
        assertTrue(MacAddress.parse("33:33:00:00:00:01").isMulticast(), "IPv6 all-nodes");
        assertTrue(MacAddress.BROADCAST.isMulticast(), "broadcast has the group bit set too");
        assertFalse(new MacAddress(SIX).isMulticast(), "0xaa: group bit clear");
        assertFalse(MacAddress.parse("00:00:00:00:00:00").isMulticast());
    }

    /**
     * A locally-administered address — the second-lowest bit — is a normal unicast
     * host, not a group. Phones using MAC randomisation look like this, and treating
     * them as multicast would drop them from passive learning.
     */
    @Test
    public void locallyAdministeredIsNotMulticast() {
        assertFalse(MacAddress.parse("1a:aa:b4:c0:bc:f5").isMulticast());
        assertFalse(MacAddress.parse("66:29:98:60:2b:5e").isMulticast());
        assertFalse(MacAddress.parse("3a:68:7b:31:c8:72").isMulticast());
        assertFalse(MacAddress.parse("02:00:00:00:00:00").isMulticast(), "only bit 1 set");
    }

    /** The ARP "target hardware address unknown" filler, and the cache's INCOMPLETE marker. */
    @Test
    public void zeroIsAllZeroBytes() {
        assertTrue(MacAddress.parse("00:00:00:00:00:00").isZero());
        assertTrue(new MacAddress(new byte[6]).isZero());
        assertFalse(MacAddress.parse("00:00:00:00:00:01").isZero());
        assertFalse(MacAddress.parse("01:00:00:00:00:00").isZero());
        assertFalse(MacAddress.BROADCAST.isZero());
    }

    // ---- value semantics ----

    @Test
    public void equalBytesMeanEqualAddresses() {
        MacAddress a = new MacAddress(SIX);
        MacAddress b = MacAddress.parse("aa:bb:cc:dd:ee:ff");
        assertNotSame(a, b);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals(a, a);
    }

    @Test
    public void differentBytesAreNotEqual() {
        MacAddress a = new MacAddress(SIX);
        assertNotEquals(a, MacAddress.parse("aa:bb:cc:dd:ee:fe"));
        assertNotEquals(a, MacAddress.parse("ab:bb:cc:dd:ee:ff"), "first octet differs");
        assertNotEquals(a, MacAddress.BROADCAST);
    }

    @Test
    public void equalsHandlesNullAndForeignTypes() {
        MacAddress a = new MacAddress(SIX);
        assertNotEquals(null, a);
        assertNotEquals("aa:bb:cc:dd:ee:ff", a);
        assertNotEquals(a, new Object());
    }

    /**
     * The reason this type is not a record: {@code IpMacCache} keeps these in maps
     * and sets, and a reference-identity equals would break every lookup.
     */
    @Test
    public void usableAsAMapKeyAndInASet() {
        Map<MacAddress, String> byMac = new HashMap<>();
        byMac.put(new MacAddress(SIX), "first");
        byMac.put(MacAddress.parse("AA-BB-CC-DD-EE-FF"), "second");
        assertEquals(1, byMac.size(), "the same address parsed twice is one key");
        assertEquals("second", byMac.get(MacAddress.parse("aabbccddeeff")));

        Set<MacAddress> seen = new HashSet<>();
        seen.add(MacAddress.parse("aa:bb:cc:dd:ee:ff"));
        seen.add(new MacAddress(SIX));
        seen.add(MacAddress.BROADCAST);
        assertEquals(2, seen.size());
        assertTrue(seen.contains(MacAddress.parse("ff-ff-ff-ff-ff-ff")));
    }

    /** BROADCAST is shared static state, so a caller must not be able to alter it. */
    @Test
    public void theBroadcastConstantCannotBeMutatedThroughItsAccessor() {
        byte[] stolen = MacAddress.BROADCAST.bytes();
        stolen[0] = 0x00;
        assertTrue(MacAddress.BROADCAST.isBroadcast());
        assertEquals("ff:ff:ff:ff:ff:ff", MacAddress.BROADCAST.toString());
    }

    private static void assertArrayEqualsAsHex(byte[] expected, byte[] actual) {
        assertEquals(java.util.HexFormat.of().formatHex(expected),
                     java.util.HexFormat.of().formatHex(actual));
    }
}
