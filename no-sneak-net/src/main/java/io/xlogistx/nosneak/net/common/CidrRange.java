package io.xlogistx.nosneak.net.common;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * A CIDR block with a lazy iterator over the addresses it contains, for both
 * IPv4 and IPv6.
 * <p>
 * Address parsing goes through {@link InetAddress#ofLiteral(String)}, never
 * {@code getByName}, so a CIDR string can never trigger a DNS lookup.
 */
public final class CidrRange {

    private final InetAddress networkAddress;
    private final int prefixLength;

    private CidrRange(InetAddress networkAddress, int prefixLength) {
        this.networkAddress = networkAddress;
        this.prefixLength = prefixLength;
    }

    /**
     * Parses {@code "192.168.1.0/24"} or {@code "fe80::/64"}. Host bits in the
     * supplied address are cleared, so {@code "192.168.1.5/24"} and
     * {@code "192.168.1.0/24"} produce the same range.
     *
     * @throws IllegalArgumentException on malformed text or an out-of-range prefix
     */
    public static CidrRange parse(String cidr) {
        Objects.requireNonNull(cidr, "cidr");
        int slash = cidr.indexOf('/');
        if (slash < 0) {
            throw new IllegalArgumentException("Missing '/' in CIDR: " + cidr);
        }
        InetAddress address;
        try {
            address = InetAddress.ofLiteral(cidr.substring(0, slash).trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Not a literal IP address: " + cidr, e);
        }
        int prefix;
        try {
            prefix = Integer.parseInt(cidr.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Not a prefix length: " + cidr, e);
        }
        int bits = address.getAddress().length * 8;
        if (prefix < 0 || prefix > bits) {
            throw new IllegalArgumentException(
                    "Prefix /" + prefix + " out of range for a " + bits + "-bit address: " + cidr);
        }
        return new CidrRange(maskToPrefix(address, prefix), prefix);
    }

    /** The first address of the block, with all host bits cleared. */
    public InetAddress networkAddress() {
        return networkAddress;
    }

    public int prefixLength() {
        return prefixLength;
    }

    public boolean isIpv6() {
        return networkAddress.getAddress().length == 16;
    }

    /**
     * Total addresses in the block, {@code 2^(bits - prefix)}.
     * <p>
     * {@link BigInteger}, not {@code long}: a {@code /64} holds {@code 2^64}
     * addresses, which overflows a signed long. Callers must compare this against
     * {@link SweepOptions#maxHosts()} before expanding the range.
     */
    public BigInteger hostCount() {
        int bits = networkAddress.getAddress().length * 8;
        return BigInteger.ONE.shiftLeft(bits - prefixLength);
    }

    /** True when {@code target} falls inside this block. */
    public boolean contains(InetAddress target) {
        byte[] net = networkAddress.getAddress();
        byte[] other = target.getAddress();
        if (net.length != other.length) {
            return false;
        }
        return samePrefix(net, other, prefixLength);
    }

    /**
     * Every address in the block, in ascending order, evaluated lazily — a
     * {@code /64} is a legal receiver here precisely because nothing is
     * materialised.
     * <p>
     * This yields ALL addresses, including the IPv4 network and broadcast
     * addresses when the prefix is {@code /30} or shorter. Skipping those is
     * {@link HostDiscovery#sweep} policy, not a property of the range — and the
     * broadcast address in particular must not be pinged.
     */
    public Stream<InetAddress> hosts() {
        int length = networkAddress.getAddress().length;
        BigInteger first = new BigInteger(1, networkAddress.getAddress());
        BigInteger end = first.add(hostCount());
        return Stream.iterate(first, i -> i.compareTo(end) < 0, i -> i.add(BigInteger.ONE))
                     .map(i -> toAddress(i, length));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CidrRange other
                && prefixLength == other.prefixLength
                && networkAddress.equals(other.networkAddress);
    }

    @Override
    public int hashCode() {
        return 31 * networkAddress.hashCode() + prefixLength;
    }

    @Override
    public String toString() {
        return networkAddress.getHostAddress() + "/" + prefixLength;
    }

    private static InetAddress maskToPrefix(InetAddress address, int prefix) {
        byte[] raw = address.getAddress();
        for (int i = 0; i < raw.length; i++) {
            int keep = prefix - i * 8;
            if (keep >= 8) {
                continue;
            }
            raw[i] = keep <= 0 ? 0 : (byte) (raw[i] & (0xFF << (8 - keep)));
        }
        return toAddress(raw);
    }

    private static boolean samePrefix(byte[] a, byte[] b, int prefix) {
        int fullBytes = prefix / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        int remainder = prefix % 8;
        if (remainder == 0) {
            return true;
        }
        int mask = (0xFF << (8 - remainder)) & 0xFF;
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }

    /**
     * {@link BigInteger#toByteArray()} emits a sign byte for values with the high
     * bit set and drops leading zeros, so neither end can be trusted to be the
     * right width — right-align into a fixed-length buffer.
     */
    private static InetAddress toAddress(BigInteger value, int length) {
        byte[] raw = new byte[length];
        byte[] magnitude = value.toByteArray();
        int copy = Math.min(magnitude.length, length);
        System.arraycopy(magnitude, magnitude.length - copy, raw, length - copy, copy);
        return toAddress(raw);
    }

    private static InetAddress toAddress(byte[] raw) {
        try {
            return InetAddress.getByAddress(raw);
        } catch (java.net.UnknownHostException e) {
            // getByAddress only rejects lengths other than 4 or 16, and every
            // array reaching here came from an InetAddress of one of those sizes.
            throw new IllegalStateException("Unreachable: bad address length " + raw.length, e);
        }
    }
}
