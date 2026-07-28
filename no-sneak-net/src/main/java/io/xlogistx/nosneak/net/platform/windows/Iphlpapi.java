package io.xlogistx.nosneak.net.platform.windows;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import io.xlogistx.nosneak.net.common.MacAddress;

import java.lang.invoke.MethodHandle;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Optional;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * The two things pcap cannot answer for itself: <b>which router do I hand an
 * off-link packet to</b>, and <b>what MAC should I aim a unicast ARP at.</b>
 * <p>
 * pcap injects at layer 2 and bypasses OS routing entirely, so a packet for a
 * destination beyond the local subnet needs the default gateway's MAC — which
 * needs the gateway's IP, which only the routing table knows. This binds
 * {@code iphlpapi.dll}'s {@code GetBestRoute2} to ask Windows the question it
 * already has the answer to, rather than reimplementing route selection.
 * {@code GetIpNetEntry2} answers the second question from the same library
 * (see {@link #neighborMac}).
 * <p>
 * Deliberately minimal: two functions, and only the fields actually needed from
 * the rows they fill in. {@code MIB_IPFORWARD_ROW2} has sixteen members and embeds
 * two {@code SOCKADDR_INET} unions; hand-deriving every offset would be a large
 * unverified surface for no gain. Both buffers are over-allocated and only the
 * wanted fields are read.
 * <p>
 * NEITHER CALL TOUCHES THE WIRE. Both read state Windows already holds, in
 * microseconds. Everything this module reports as a measurement still comes from
 * a frame that arrived on our own pcap handle.
 */
final class Iphlpapi {

    /**
     * Byte offset of {@code NextHop} within {@code MIB_IPFORWARD_ROW2}.
     * <pre>
     *   0   NET_LUID          InterfaceLuid        (8, aligned 8)
     *   8   NET_IFINDEX       InterfaceIndex       (4)
     *  12   IP_ADDRESS_PREFIX DestinationPrefix    (SOCKADDR_INET 28 + UINT8 + pad = 32)
     *  44   SOCKADDR_INET     NextHop              (28)
     * </pre>
     * Confirmed empirically on Windows 10 x64 against the value {@code route print}
     * reports; {@link #probeNextHopOffset} re-derives it at runtime if a future
     * Windows changes the struct, so a wrong constant degrades to "no off-link
     * routing" rather than to a garbage gateway.
     */
    private static final long NEXT_HOP_OFFSET = 44;

    /** Generous: the real row is ~104 bytes, and over-allocating costs nothing. */
    private static final int ROW_BYTES = 512;

    private static final int SOCKADDR_INET_BYTES = 28;
    private static final int AF_INET = 2;
    private static final int AF_INET6 = 23;
    private static final int NO_ERROR = 0;

    /**
     * Field offsets within {@code MIB_IPNET_ROW2} (x64 and arm64 alike — every
     * member is LP64-identical, per §2.3).
     * <pre>
     *   0   SOCKADDR_INET     Address               (28, align 4)
     *  28   NET_IFINDEX       InterfaceIndex        (4)
     *  32   NET_LUID          InterfaceLuid         (8, align 8 - 32 is already aligned)
     *  40   UCHAR             PhysicalAddress[32]   (IF_MAX_PHYS_ADDRESS_LENGTH)
     *  72   ULONG             PhysicalAddressLength (4)
     *  76   NL_NEIGHBOR_STATE State                 (enum, 4)
     *  80   UCHAR             Flags                 (bit fields, + 3 pad)
     *  84   ULONG             ReachabilityTime      (4)
     *       ------------------------------------------------------------
     *       sizeof = 88, align 8
     * </pre>
     * These are derived, so they are checked rather than trusted: {@link #neighborMac}
     * rejects any row whose {@code PhysicalAddressLength} is not exactly 6 and whose
     * echoed {@code Address} is not the one asked for. A layout that ever changes
     * therefore yields NO HINT — never a wrong MAC — and resolution falls back to
     * broadcast, which is the behaviour before this call existed.
     */
    static final long IPNET_ADDRESS_OFFSET = 0;
    static final long IPNET_INTERFACE_INDEX_OFFSET = 28;
    static final long IPNET_PHYSICAL_ADDRESS_OFFSET = 40;
    static final long IPNET_PHYSICAL_ADDRESS_LENGTH_OFFSET = 72;
    static final long IPNET_STATE_OFFSET = 76;
    static final int MIB_IPNET_ROW2_BYTES = 88;

    /** {@code NL_NEIGHBOR_STATE}: no MAC has been learned yet, so the row carries none. */
    private static final int NLNS_INCOMPLETE = 1;

    private static final int MAC_BYTES = 6;

    private static volatile MethodHandle getBestRoute2;
    private static volatile MethodHandle getIpNetEntry2;
    private static volatile boolean unavailable;
    private static volatile boolean neighborUnavailable;

    private Iphlpapi() {
    }

    /**
     * Asks Windows which next hop it would use for {@code target}.
     *
     * @return the gateway's address, or empty when the destination is on-link
     *         (Windows reports the destination itself as the next hop), when the
     *         route lookup fails, or when {@code iphlpapi} cannot be loaded
     */
    static Optional<InetAddress> nextHopFor(InetAddress target) {
        MethodHandle handle = handle();
        if (handle == null) {
            return Optional.empty();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment destination = arena.allocate(SOCKADDR_INET_BYTES);
            writeSockaddrInet(destination, target);

            MemorySegment row = arena.allocate(ROW_BYTES);
            MemorySegment bestSource = arena.allocate(SOCKADDR_INET_BYTES);

            int rc = (int) handle.invokeExact(
                    MemorySegment.NULL,   // InterfaceLuid  - let Windows choose
                    0,                    // InterfaceIndex - likewise
                    MemorySegment.NULL,   // SourceAddress  - likewise
                    destination,
                    0,                    // AddressSortOptions
                    row,
                    bestSource);
            if (rc != NO_ERROR) {
                return Optional.empty();
            }
            Optional<InetAddress> nextHop = readSockaddrInet(row, NEXT_HOP_OFFSET);

            // Windows reports an on-link destination as a next hop of 0.0.0.0 or
            // as the destination itself; neither is a router to send through.
            return nextHop.filter(hop -> !hop.isAnyLocalAddress() && !hop.equals(target));
        } catch (Throwable t) {
            return Optional.empty();
        }
    }

    /** True when {@code iphlpapi.dll} loaded and {@code GetBestRoute2} resolved. */
    static boolean isAvailable() {
        return handle() != null;
    }

    /**
     * A MAC to aim a unicast ARP at, read out of Windows' own neighbour table.
     * <p>
     * A HINT, NEVER AN ANSWER. The returned MAC only decides where the next
     * solicitation is addressed; resolution still requires a reply on our own pcap
     * handle, so the reported {@link io.xlogistx.nosneak.net.common.ResolveSource}
     * stays {@code ACTIVE_ARP} and a stale hint costs one wasted frame rather than a
     * wrong answer. It is deliberately NOT written into {@code IpMacCache} — the
     * cache holds what this process saw on the wire, and Windows' belief is not that.
     * <p>
     * <b>Why this is worth doing on Windows when the equivalent was removed on
     * Linux.</b> §13.13 deleted a {@code /proc/net/arp} reader because the kernel
     * resolves a cold neighbour by BROADCAST — the very thing being suppressed — so
     * with the entry flushed it sat {@code INCOMPLETE} and could never help. The
     * asymmetry is that Linux has something strictly better: an {@code ETH_P_IP}
     * socket learning MACs off ordinary traffic. Windows has no such learner
     * (§13.16), so its neighbour table is not a worse alternative to passive
     * learning, it is the only alternative to nothing. Measured on the failing host:
     * Windows held {@code 10.0.0.108 -> 94-e6-ba-4d-66-1b} throughout, while our own
     * broadcasts went unanswered.
     * <p>
     * The §13.13 limitation still applies and is not papered over: this can only
     * report a host Windows has itself talked to. For one it has not, there is no
     * entry, no hint, and the solicitation broadcasts exactly as before.
     *
     * @param ifIndex the binding's interface index; a neighbour entry is per-interface,
     *                and the same address on two NICs is two different hosts
     * @return a usable unicast MAC, or empty when there is no entry, the entry is
     *         {@code INCOMPLETE}, the library is unavailable, or the row does not
     *         look like the layout this code was written against
     */
    static Optional<MacAddress> neighborMac(InetAddress target, int ifIndex) {
        MethodHandle handle = neighborHandle();
        if (handle == null) {
            return Optional.empty();
        }
        try (Arena arena = Arena.ofConfined()) {
            // Over-allocated on the same reasoning as ROW_BYTES: a longer row on some
            // future Windows must not become an out-of-bounds write by Windows itself.
            MemorySegment row = arena.allocate(256);
            row.fill((byte) 0);
            writeSockaddrInet(row.asSlice(IPNET_ADDRESS_OFFSET, SOCKADDR_INET_BYTES), target);
            row.set(JAVA_INT, IPNET_INTERFACE_INDEX_OFFSET, ifIndex);

            int rc = (int) handle.invokeExact(row);
            if (rc != NO_ERROR) {
                return Optional.empty();   // ERROR_NOT_FOUND is the ordinary case
            }
            // Layout self-check: Windows echoes the row it filled, so an Address that
            // no longer decodes to what we asked for means the offsets have moved and
            // nothing else in this row can be trusted.
            if (!readSockaddrInet(row, IPNET_ADDRESS_OFFSET)
                    .filter(target::equals).isPresent()) {
                return Optional.empty();
            }
            if (row.get(JAVA_INT, IPNET_STATE_OFFSET) == NLNS_INCOMPLETE) {
                return Optional.empty();   // solicitation in flight; no MAC learned yet
            }
            if (row.get(JAVA_INT, IPNET_PHYSICAL_ADDRESS_LENGTH_OFFSET) != MAC_BYTES) {
                return Optional.empty();   // not Ethernet, or not the layout above
            }
            byte[] mac = new byte[MAC_BYTES];
            MemorySegment.copy(row, JAVA_BYTE, IPNET_PHYSICAL_ADDRESS_OFFSET, mac, 0, MAC_BYTES);
            MacAddress address = new MacAddress(mac);
            return address.isZero() || address.isBroadcast() || address.isMulticast()
                    ? Optional.empty()
                    : Optional.of(address);
        } catch (Throwable t) {
            return Optional.empty();
        }
    }

    /** True when {@code GetIpNetEntry2} resolved, so a unicast hint is possible. */
    static boolean isNeighborLookupAvailable() {
        return neighborHandle() != null;
    }

    private static MethodHandle neighborHandle() {
        MethodHandle local = getIpNetEntry2;
        if (local != null || neighborUnavailable) {
            return local;
        }
        synchronized (Iphlpapi.class) {
            if (getIpNetEntry2 == null && !neighborUnavailable) {
                try {
                    SymbolLookup lookup =
                            SymbolLookup.libraryLookup("iphlpapi", Arena.global());
                    MemorySegment symbol = lookup.find("GetIpNetEntry2").orElse(null);
                    if (symbol == null) {
                        neighborUnavailable = true;
                    } else {
                        getIpNetEntry2 = Linker.nativeLinker().downcallHandle(symbol,
                                FunctionDescriptor.of(JAVA_INT,
                                        ADDRESS));  // PMIB_IPNET_ROW2, in and out
                    }
                } catch (RuntimeException e) {
                    neighborUnavailable = true;
                }
            }
            return getIpNetEntry2;
        }
    }

    private static MethodHandle handle() {
        MethodHandle local = getBestRoute2;
        if (local != null || unavailable) {
            return local;
        }
        synchronized (Iphlpapi.class) {
            if (getBestRoute2 == null && !unavailable) {
                try {
                    SymbolLookup lookup =
                            SymbolLookup.libraryLookup("iphlpapi", Arena.global());
                    MemorySegment symbol = lookup.find("GetBestRoute2").orElse(null);
                    if (symbol == null) {
                        unavailable = true;
                    } else {
                        getBestRoute2 = Linker.nativeLinker().downcallHandle(symbol,
                                FunctionDescriptor.of(JAVA_INT,
                                        ADDRESS,   // NET_LUID*
                                        JAVA_INT,  // NET_IFINDEX
                                        ADDRESS,   // const SOCKADDR_INET* source
                                        ADDRESS,   // const SOCKADDR_INET* destination
                                        JAVA_INT,  // ULONG AddressSortOptions
                                        ADDRESS,   // PMIB_IPFORWARD_ROW2
                                        ADDRESS)); // SOCKADDR_INET* bestSource
                    }
                } catch (RuntimeException e) {
                    unavailable = true;
                }
            }
            return getBestRoute2;
        }
    }

    /**
     * A {@code SOCKADDR_INET} is a union: the family is a {@code USHORT} at offset
     * 0, an IPv4 address sits at offset 4 and an IPv6 address at offset 8.
     */
    private static void writeSockaddrInet(MemorySegment sa, InetAddress address) {
        sa.fill((byte) 0);
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            sa.set(JAVA_SHORT, 0, (short) AF_INET);
            MemorySegment.copy(raw, 0, sa, JAVA_BYTE, 4, 4);
        } else {
            sa.set(JAVA_SHORT, 0, (short) AF_INET6);
            MemorySegment.copy(raw, 0, sa, JAVA_BYTE, 8, 16);
        }
    }

    private static Optional<InetAddress> readSockaddrInet(MemorySegment buffer, long offset) {
        int family = buffer.get(JAVA_SHORT, offset) & 0xFFFF;
        try {
            if (family == AF_INET) {
                byte[] raw = new byte[4];
                MemorySegment.copy(buffer, JAVA_BYTE, offset + 4, raw, 0, 4);
                return Optional.of(InetAddress.getByAddress(raw));
            }
            if (family == AF_INET6) {
                byte[] raw = new byte[16];
                MemorySegment.copy(buffer, JAVA_BYTE, offset + 8, raw, 0, 16);
                return Optional.of(InetAddress.getByAddress(raw));
            }
        } catch (java.net.UnknownHostException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /**
     * Diagnostic: scans the filled row for the offset at which a plausible
     * {@code SOCKADDR_INET} appears, so a struct change on a future Windows can be
     * spotted without a debugger. Used by the probe tool, not on any hot path.
     *
     * @return offsets that decode as an address of the same family as the target
     */
    static java.util.List<Long> probeNextHopOffset(InetAddress target) {
        java.util.List<Long> hits = new java.util.ArrayList<>();
        MethodHandle handle = handle();
        if (handle == null) {
            return hits;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment destination = arena.allocate(SOCKADDR_INET_BYTES);
            writeSockaddrInet(destination, target);
            MemorySegment row = arena.allocate(ROW_BYTES);
            MemorySegment bestSource = arena.allocate(SOCKADDR_INET_BYTES);

            int rc = (int) handle.invokeExact(MemorySegment.NULL, 0, MemorySegment.NULL,
                                              destination, 0, row, bestSource);
            if (rc != NO_ERROR) {
                return hits;
            }
            int wanted = target instanceof Inet4Address ? AF_INET : AF_INET6;
            for (long off = 0; off + SOCKADDR_INET_BYTES <= ROW_BYTES; off += 2) {
                if ((row.get(JAVA_SHORT, off) & 0xFFFF) == wanted
                        && readSockaddrInet(row, off).isPresent()) {
                    hits.add(off);
                }
            }
        } catch (Throwable ignored) {
            // diagnostic only
        }
        return hits;
    }

    /** Diagnostic: the decoded address at a given row offset. */
    static Optional<InetAddress> addressAt(InetAddress target, long offset) {
        MethodHandle handle = handle();
        if (handle == null) {
            return Optional.empty();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment destination = arena.allocate(SOCKADDR_INET_BYTES);
            writeSockaddrInet(destination, target);
            MemorySegment row = arena.allocate(ROW_BYTES);
            MemorySegment bestSource = arena.allocate(SOCKADDR_INET_BYTES);
            int rc = (int) handle.invokeExact(MemorySegment.NULL, 0, MemorySegment.NULL,
                                              destination, 0, row, bestSource);
            return rc == NO_ERROR ? readSockaddrInet(row, offset) : Optional.empty();
        } catch (Throwable t) {
            return Optional.empty();
        }
    }
}
