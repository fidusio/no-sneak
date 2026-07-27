package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.NicBinding;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Enumerates Npcap devices and matches them to {@link NetworkInterface}s.
 * <p>
 * A pcap device name ({@code \Device\NPF_{GUID}}) has NOTHING in common with what
 * {@link NetworkInterface#getName()} returns, so the two are matched **by IP
 * address** — never by hardcoding or pattern-matching the name.
 */
public final class PcapDevices {

    private PcapDevices() {
    }

    /**
     * One entry from {@code pcap_findalldevs}.
     *
     * @param addresses every address pcap reports for the device; the match key
     */
    public record Device(String name, String description, List<InetAddress> addresses) {

        public Device {
            addresses = List.copyOf(addresses);
        }

        @Override
        public String toString() {
            return name + (description == null ? "" : " (" + description + ")")
                   + " " + addresses.stream().map(InetAddress::getHostAddress).toList();
        }
    }

    /**
     * Walks the {@code pcap_if_t} linked list.
     * <p>
     * The list is owned by pcap and must be released with
     * {@code pcap_freealldevs}, which happens before this returns — everything
     * needed is copied into Java objects first.
     */
    public static List<Device> findAll() throws DiscoveryException {
        Pcap.Handles h = Pcap.load();
        List<Device> devices = new ArrayList<>();

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment head = arena.allocate(ADDRESS);
            MemorySegment errbuf = Pcap.errbuf(arena);

            int rc = (int) h.findAllDevs().invokeExact(head, errbuf);
            if (rc != 0) {
                throw new DiscoveryException(
                        "pcap_findalldevs failed: " + Pcap.errbufText(errbuf));
            }
            MemorySegment first = head.get(ADDRESS, 0);
            try {
                for (MemorySegment dev = first;
                     dev != null && !dev.equals(MemorySegment.NULL);
                     dev = dev.reinterpret(Long.MAX_VALUE).get(ADDRESS, Pcap.IF_NEXT)) {

                    MemorySegment d = dev.reinterpret(Long.MAX_VALUE);
                    devices.add(new Device(
                            Pcap.cString(d.get(ADDRESS, Pcap.IF_NAME)),
                            Pcap.cString(d.get(ADDRESS, Pcap.IF_DESCRIPTION)),
                            readAddresses(d.get(ADDRESS, Pcap.IF_ADDRESSES))));
                }
            } finally {
                if (!first.equals(MemorySegment.NULL)) {
                    h.freeAllDevs().invokeExact(first);
                }
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("pcap device enumeration failed", t);
        }
        return devices;
    }

    /**
     * Finds the pcap device carrying any of the interface's addresses.
     * <p>
     * Matching on address is the only reliable link between the two namings. An
     * interface with no address — or one pcap does not report — cannot be matched,
     * which is a real outcome rather than an error.
     */
    public static Optional<Device> forInterface(List<Device> devices, NetworkInterface nif) {
        Set<InetAddress> wanted = new HashSet<>();
        nif.getInterfaceAddresses().forEach(ia -> wanted.add(ia.getAddress()));
        if (wanted.isEmpty()) {
            return Optional.empty();
        }
        for (Device d : devices) {
            for (InetAddress a : d.addresses()) {
                if (wanted.contains(a)) {
                    return Optional.of(d);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Resolves the backend device name for {@link NicBinding#from}, throwing a
     * clear error rather than returning a name that will not open.
     */
    public static String requireDeviceName(List<Device> devices, NetworkInterface nif)
            throws DiscoveryException {
        return forInterface(devices, nif)
                .map(Device::name)
                .orElseThrow(() -> new DiscoveryException(
                        "No Npcap device matches interface '" + nif.getName()
                        + "'. Devices are matched by IP address; this interface reports "
                        + nif.getInterfaceAddresses().size() + " address(es). "
                        + "A disabled or address-less adapter cannot be bound."));
    }

    /**
     * Walks the {@code pcap_addr} list, keeping only IPv4 and IPv6.
     * <p>
     * Windows {@code sockaddr} has the family as two bytes at offset 0 with no
     * leading length byte — one column now that macOS is off this backend.
     * {@code AF_INET6} is 23 on Windows, not 10 as on Linux or 30 as on Darwin.
     */
    private static List<InetAddress> readAddresses(MemorySegment addrList) {
        List<InetAddress> out = new ArrayList<>();
        for (MemorySegment a = addrList;
             a != null && !a.equals(MemorySegment.NULL);
             a = a.reinterpret(Long.MAX_VALUE).get(ADDRESS, Pcap.ADDR_NEXT)) {

            MemorySegment entry = a.reinterpret(Long.MAX_VALUE);
            MemorySegment sockaddr = entry.get(ADDRESS, Pcap.ADDR_ADDR);
            if (sockaddr.equals(MemorySegment.NULL)) {
                continue;
            }
            MemorySegment sa = sockaddr.reinterpret(28);
            int family = (sa.get(JAVA_BYTE, 0) & 0xFF) | ((sa.get(JAVA_BYTE, 1) & 0xFF) << 8);

            try {
                if (family == Pcap.AF_INET) {
                    byte[] raw = new byte[4];
                    MemorySegment.copy(sa, JAVA_BYTE, 4, raw, 0, 4);
                    out.add(InetAddress.getByAddress(raw));
                } else if (family == Pcap.AF_INET6) {
                    byte[] raw = new byte[16];
                    MemorySegment.copy(sa, JAVA_BYTE, 8, raw, 0, 16);
                    out.add(InetAddress.getByAddress(raw));
                }
            } catch (java.net.UnknownHostException e) {
                // getByAddress only rejects wrong lengths, and these are fixed.
                throw new IllegalStateException("unreachable", e);
            }
        }
        return out;
    }
}
