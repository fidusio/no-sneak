package io.xlogistx.nosneak.net.common;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * An immutable 48-bit Ethernet hardware address.
 * <p>
 * Deliberately a class and not a record: a record's generated {@code equals} and
 * {@code hashCode} would use reference identity for the backing array, so two
 * instances holding the same six bytes would compare unequal. This type compares
 * by value, which is what makes it usable as an {@link io.xlogistx.nosneak.net.util.IpMacCache} value and in
 * conflict detection.
 */
public final class MacAddress {

    /** Length of an Ethernet hardware address, in bytes. */
    public static final int LENGTH = 6;

    /** {@code ff:ff:ff:ff:ff:ff} — the Ethernet broadcast destination. */
    public static final MacAddress BROADCAST =
            new MacAddress(new byte[] {-1, -1, -1, -1, -1, -1});

    private static final HexFormat COLON_HEX = HexFormat.ofDelimiter(":");

    private final byte[] bytes;

    /**
     * @param b exactly six bytes; defensively copied
     * @throws IllegalArgumentException if {@code b} is null or not six bytes long
     */
    public MacAddress(byte[] b) {
        if (b == null || b.length != LENGTH) {
            throw new IllegalArgumentException(
                    "MAC must be " + LENGTH + " bytes, got " + (b == null ? "null" : b.length));
        }
        this.bytes = b.clone();
    }

    /**
     * Accepts {@code aa:bb:cc:dd:ee:ff}, {@code aa-bb-cc-dd-ee-ff},
     * {@code aabb.ccdd.eeff}, and bare {@code aabbccddeeff}, in either case.
     *
     * @throws IllegalArgumentException if the text is not twelve hex digits once
     *                                  separators are removed
     */
    public static MacAddress parse(String s) {
        if (s == null) {
            throw new IllegalArgumentException("MAC text is null");
        }
        StringBuilder hex = new StringBuilder(2 * LENGTH);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ':' || c == '-' || c == '.') {
                continue;
            }
            if (Character.digit(c, 16) < 0) {
                throw new IllegalArgumentException("Not a MAC address: " + s);
            }
            hex.append(c);
        }
        if (hex.length() != 2 * LENGTH) {
            throw new IllegalArgumentException(
                    "MAC must be " + (2 * LENGTH) + " hex digits: " + s);
        }
        return new MacAddress(HexFormat.of().parseHex(hex.toString()));
    }

    /** A copy of the six address bytes. */
    public byte[] bytes() {
        return bytes.clone();
    }

    /** True when every byte is {@code 0xFF}. */
    public boolean isBroadcast() {
        for (byte b : bytes) {
            if (b != (byte) 0xFF) {
                return false;
            }
        }
        return true;
    }

    /** True when the low bit of the first octet is set (includes broadcast). */
    public boolean isMulticast() {
        return (bytes[0] & 0x01) != 0;
    }

    /** True when every byte is zero — the ARP "unknown target hardware address". */
    public boolean isZero() {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MacAddress other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** Lower-case, colon-delimited: {@code aa:bb:cc:dd:ee:ff}. */
    @Override
    public String toString() {
        return COLON_HEX.formatHex(bytes);
    }
}
