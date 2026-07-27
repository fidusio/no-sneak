package io.xlogistx.nosneak.net.common;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Local addressing for one bound interface. All of it comes from
 * {@link NetworkInterface} — no native {@code getifaddrs} or {@code ioctl},
 * which eliminates the fiddliest native pointer-walking in the subsystem.
 *
 * @param javaName          {@link NetworkInterface#getName()}, e.g. {@code eth0} / {@code en0}
 * @param backendDeviceName pcap device name on Windows; equal to {@code javaName} elsewhere
 * @param ifIndex           {@link NetworkInterface#getIndex()}
 * @param hardwareAddress   NULLABLE — absent on loopback and some virtual interfaces
 * @param ipv4              local IPv4 addresses with their prefix lengths
 * @param ipv6              local IPv6 addresses, including link-local, which NDP needs
 * @param mtu               {@link NetworkInterface#getMTU()}
 */
public record NicBinding(
        String javaName,
        String backendDeviceName,
        int ifIndex,
        MacAddress hardwareAddress,
        List<LocalAddress> ipv4,
        List<LocalAddress> ipv6,
        int mtu) {

    public NicBinding {
        ipv4 = List.copyOf(ipv4);
        ipv6 = List.copyOf(ipv6);
    }

    /**
     * An address PLUS its prefix length.
     * <p>
     * The prefix is not decoration: it is the only way to answer "is this target
     * on-link for this interface", which the Windows pinger needs before it can
     * pick a NIC to inject through, and which sweep needs in order to know
     * whether ARP applies at all. {@link NetworkInterface#getInterfaceAddresses()}
     * carries both; {@code getInetAddresses()} drops the prefix, so it must not
     * be used to build these.
     */
    public record LocalAddress(InetAddress address, int prefixLength) {

        public LocalAddress {
            if (address == null) {
                throw new IllegalArgumentException("address is null");
            }
            int bits = address.getAddress().length * 8;
            if (prefixLength < 0 || prefixLength > bits) {
                throw new IllegalArgumentException(
                        "Prefix /" + prefixLength + " out of range for " + address);
            }
        }

        /**
         * True when {@code target} falls inside this address's subnet.
         * <p>
         * A subnet test, NOT a routing table: it compares {@code prefixLength}
         * bits and stops. No metrics, no default route, no longest-prefix
         * arbitration across interfaces — on Linux and macOS the kernel already
         * does routing properly, and this exists for the one platform that has no
         * routing available, plus for deciding whether ARP applies.
         */
        /**
         * The all-ones host address of this subnet — the IPv4 directed broadcast.
         * <p>
         * Worth knowing because it MUST NOT be pinged: an echo to a directed
         * broadcast is answered by every host on the segment at once, which is
         * amplification, and on a security appliance it looks exactly like an
         * attack. A sweep whose range covers the local subnet has to skip it.
         *
         * @return empty for IPv6, which has no broadcast, and for {@code /31} and
         *         {@code /32}, which have no spare addresses to designate
         */
        public java.util.Optional<InetAddress> broadcastAddress() {
            byte[] raw = address.getAddress();
            if (raw.length != 4 || prefixLength > 30) {
                return java.util.Optional.empty();
            }
            byte[] out = raw.clone();
            for (int i = 0; i < out.length; i++) {
                int keep = prefixLength - i * 8;
                if (keep >= 8) {
                    continue;
                }
                out[i] = keep <= 0 ? (byte) 0xFF : (byte) (out[i] | (0xFF >>> keep));
            }
            return toAddress(out);
        }

        /** The all-zeros host address of this subnet. Empty for IPv6, {@code /31} and {@code /32}. */
        public java.util.Optional<InetAddress> networkAddress() {
            byte[] raw = address.getAddress();
            if (raw.length != 4 || prefixLength > 30) {
                return java.util.Optional.empty();
            }
            byte[] out = raw.clone();
            for (int i = 0; i < out.length; i++) {
                int keep = prefixLength - i * 8;
                if (keep >= 8) {
                    continue;
                }
                out[i] = keep <= 0 ? 0 : (byte) (out[i] & (0xFF << (8 - keep)));
            }
            return toAddress(out);
        }

        private static java.util.Optional<InetAddress> toAddress(byte[] raw) {
            try {
                return java.util.Optional.of(InetAddress.getByAddress(raw));
            } catch (java.net.UnknownHostException e) {
                return java.util.Optional.empty();
            }
        }

        public boolean onLink(InetAddress target) {
            if (target == null) {
                return false;
            }
            byte[] mine = address.getAddress();
            byte[] theirs = target.getAddress();
            if (mine.length != theirs.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (mine[i] != theirs[i]) {
                    return false;
                }
            }
            int remainder = prefixLength % 8;
            if (remainder == 0) {
                return true;
            }
            int mask = (0xFF << (8 - remainder)) & 0xFF;
            return (mine[fullBytes] & mask) == (theirs[fullBytes] & mask);
        }
    }

    /** The first local address in the same family as {@code target}, or empty. */
    public Optional<LocalAddress> sourceFor(InetAddress target) {
        List<LocalAddress> candidates = familyOf(target);
        return candidates.isEmpty() ? Optional.empty() : Optional.of(candidates.get(0));
    }

    /** True when any local address of the matching family has {@code target} on-link. */
    public boolean isOnLink(InetAddress target) {
        return familyOf(target).stream().anyMatch(a -> a.onLink(target));
    }

    /** True when this binding can originate L2 frames — ARP and NDP need a source MAC. */
    public boolean supportsLayer2() {
        return hardwareAddress != null;
    }

    /**
     * True when {@code target} is the network or directed-broadcast address of one
     * of THIS interface's own subnets.
     * <p>
     * A sweep must skip these. Pinging a directed broadcast is answered by every
     * host on the segment at once — amplification, and indistinguishable from an
     * attack on a security appliance. The test is against the interface's real
     * prefix rather than the swept range's, so sweeping an arbitrary sub-range
     * such as a {@code /29} inside a {@code /24} does not lose two legitimate
     * hosts to a guess.
     */
    public boolean isNetworkOrBroadcast(InetAddress target) {
        for (LocalAddress local : ipv4) {
            if (!local.onLink(target)) {
                continue;
            }
            if (local.broadcastAddress().filter(target::equals).isPresent()
                    || local.networkAddress().filter(target::equals).isPresent()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds a binding from a {@link NetworkInterface} plus a resolver that maps
     * it to the backend's own device name (identity on Linux and macOS; a pcap
     * device lookup on Windows).
     * <p>
     * {@link NetworkInterface#getHardwareAddress()} returns null for loopback and
     * some virtual interfaces. That null is preserved rather than fed to
     * {@link MacAddress}, which would throw — the factory rejects such a binding
     * for L2 operations while ICMP remains available through {@link ICMPPing}.
     *
     * @throws SocketException if the interface cannot be interrogated
     */
    public static NicBinding from(NetworkInterface nif,
                                  Function<NetworkInterface, String> deviceNameResolver)
            throws SocketException {
        MacAddress hardware = null;
        byte[] raw = nif.getHardwareAddress();
        if (raw != null && raw.length == MacAddress.LENGTH) {
            hardware = new MacAddress(raw);
        }

        List<LocalAddress> v4 = new ArrayList<>();
        List<LocalAddress> v6 = new ArrayList<>();
        for (InterfaceAddress ia : nif.getInterfaceAddresses()) {
            InetAddress address = ia.getAddress();
            LocalAddress local = new LocalAddress(address, ia.getNetworkPrefixLength());
            if (address instanceof Inet4Address) {
                v4.add(local);
            } else if (address instanceof Inet6Address) {
                v6.add(local);
            }
        }

        String device = deviceNameResolver == null
                ? nif.getName()
                : deviceNameResolver.apply(nif);

        return new NicBinding(nif.getName(), device, nif.getIndex(), hardware, v4, v6, nif.getMTU());
    }

    private List<LocalAddress> familyOf(InetAddress target) {
        if (target instanceof Inet4Address) {
            return ipv4;
        }
        if (target instanceof Inet6Address) {
            return ipv6;
        }
        return List.of();
    }
}
