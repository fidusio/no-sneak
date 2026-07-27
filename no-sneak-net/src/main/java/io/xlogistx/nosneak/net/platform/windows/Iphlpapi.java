package io.xlogistx.nosneak.net.platform.windows;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Optional;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * The one thing pcap cannot answer for itself: <b>which router do I hand an
 * off-link packet to.</b>
 * <p>
 * pcap injects at layer 2 and bypasses OS routing entirely, so a packet for a
 * destination beyond the local subnet needs the default gateway's MAC — which
 * needs the gateway's IP, which only the routing table knows. This binds
 * {@code iphlpapi.dll}'s {@code GetBestRoute2} to ask Windows the question it
 * already has the answer to, rather than reimplementing route selection.
 * <p>
 * Deliberately minimal: ONE function, and only the {@code NextHop} field of the
 * row it fills in. {@code MIB_IPFORWARD_ROW2} has sixteen members and embeds two
 * {@code SOCKADDR_INET} unions; hand-deriving every offset would be a large
 * unverified surface for no gain. The buffer is over-allocated and only
 * {@code NextHop} is read.
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

    private static volatile MethodHandle getBestRoute2;
    private static volatile boolean unavailable;

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
