package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.PingError;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * libc bindings, constants and struct layouts for the Linux backend.
 * <p>
 * Every value here is identical on x86-64 and aarch64 — layouts are selected on
 * {@code os.name} alone, never {@code os.arch} (§2.3).
 * <p>
 * {@code fcntl} and {@code ioctl} are deliberately NOT bound. The reader-thread
 * model uses blocking sockets with {@code SO_RCVTIMEO}, which sidesteps the
 * {@code O_NONBLOCK} value difference and every variadic {@code ioctl} hazard.
 */
final class Libc {

    // ---- constants (§6.2) ----
    static final int AF_INET = 2;
    static final int AF_INET6 = 10;          // 30 on macOS, 23 on Windows
    static final int AF_PACKET = 17;
    static final int SOCK_DGRAM = 2;
    static final int SOCK_RAW = 3;
    static final int IPPROTO_ICMP = 1;
    static final int IPPROTO_ICMPV6 = 58;
    static final int ETH_P_IP = 0x0800;
    static final int ETH_P_ARP = 0x0806;
    static final int ETH_P_IPV6 = 0x86DD;
    static final int SOL_SOCKET = 1;
    static final int SO_RCVTIMEO = 20;
    static final int SOL_PACKET = 263;
    static final int PACKET_ADD_MEMBERSHIP = 1;
    static final int PACKET_DROP_MEMBERSHIP = 2;
    static final int PACKET_MR_PROMISC = 1;
    static final int ICMP6_FILTER = 1;       // level = IPPROTO_ICMPV6

    // ---- errno (§4.7) ----
    static final int EPERM = 1;
    static final int ENXIO = 6;
    static final int EAGAIN = 11;            // == EWOULDBLOCK on Linux
    static final int EACCES = 13;
    static final int EINVAL = 22;
    static final int ENETDOWN = 100;
    static final int ENETUNREACH = 101;
    static final int EHOSTUNREACH = 113;

    /** Receive timeout, in seconds, that bounds how long shutdown can take (§4.4). */
    static final long RECV_TIMEOUT_SEC = 0;
    static final long RECV_TIMEOUT_USEC = 200_000;   // 200 ms

    // ---- layouts (§6.3, §6.4, §4.4) ----

    /** Linux {@code sockaddr_in} — 16 bytes. Family is 2 bytes at offset 0, no {@code sin_len}. */
    static final StructLayout SOCKADDR_IN = MemoryLayout.structLayout(
            JAVA_SHORT.withName("sin_family"),
            JAVA_SHORT.withName("sin_port"),
            JAVA_INT.withName("sin_addr"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero"));

    /** Linux {@code sockaddr_in6} — 28 bytes. */
    static final StructLayout SOCKADDR_IN6 = MemoryLayout.structLayout(
            JAVA_SHORT.withName("sin6_family"),
            JAVA_SHORT.withName("sin6_port"),
            JAVA_INT.withName("sin6_flowinfo"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("sin6_addr"),
            JAVA_INT.withName("sin6_scope_id"));

    /** Linux {@code sockaddr_ll} — 20 bytes. */
    static final StructLayout SOCKADDR_LL = MemoryLayout.structLayout(
            JAVA_SHORT.withName("sll_family"),
            JAVA_SHORT.withName("sll_protocol"),
            JAVA_INT.withName("sll_ifindex"),
            JAVA_SHORT.withName("sll_hatype"),
            JAVA_BYTE.withName("sll_pkttype"),
            JAVA_BYTE.withName("sll_halen"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sll_addr"));

    /** Linux {@code struct timeval} — 16 bytes, both fields 64-bit. */
    static final StructLayout TIMEVAL = MemoryLayout.structLayout(
            JAVA_LONG.withName("tv_sec"),
            JAVA_LONG.withName("tv_usec"));

    /** {@code struct packet_mreq} — 16 bytes. */
    static final StructLayout PACKET_MREQ = MemoryLayout.structLayout(
            JAVA_INT.withName("mr_ifindex"),
            JAVA_SHORT.withName("mr_type"),
            JAVA_SHORT.withName("mr_alen"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("mr_address"));

    /** {@code struct icmp6_filter} — 8 x uint32. */
    static final int ICMP6_FILTER_WORDS = 8;
    static final int ICMP6_FILTER_BYTES = ICMP6_FILTER_WORDS * 4;

    /**
     * Byte offsets into {@code sockaddr_ll}, so callers do not repeat varhandle
     * plumbing.
     * <pre>
     *   0  sll_family    (2)
     *   2  sll_protocol  (2)   ethertype, network order
     *   4  sll_ifindex   (4)
     *   8  sll_hatype    (2)   &lt;-- two bytes, not one
     *  10  sll_pkttype   (1)
     *  11  sll_halen     (1)
     *  12  sll_addr      (8)
     * </pre>
     * {@code sll_hatype} being a SHORT is the easy thing to get wrong here: assume
     * it is one byte and every following offset shifts by two, so the destination
     * MAC gets written into {@code sll_pkttype} and the frame goes nowhere useful.
     * {@code LinuxLayoutTest} pins these against the declared layout.
     */
    static final long SLL_PROTOCOL = 2;
    static final long SLL_IFINDEX = 4;
    static final long SLL_HATYPE = 8;
    static final long SLL_PKTTYPE = 10;
    static final long SLL_HALEN = 11;
    static final long SLL_ADDR = 12;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = LINKER.defaultLookup();
    static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO =
            CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    /**
     * Held in a nested class so libc symbols resolve LAZILY, on first use.
     * Resolving them in {@link Libc}'s own static initialiser would make the
     * constants and layouts above unreadable anywhere but Linux — and those are
     * pure arithmetic that the §11.2 layout tests must be able to check on any
     * developer machine.
     */
    static final class Handles {
        static final MethodHandle SOCKET = bind("socket",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
        static final MethodHandle BIND = bind("bind",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle SENDTO = bind("sendto",
                FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT,
                                      ADDRESS, JAVA_INT));
        static final MethodHandle RECVFROM = bind("recvfrom",
                FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT,
                                      ADDRESS, ADDRESS));
        static final MethodHandle SETSOCKOPT = bind("setsockopt",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle CLOSE = bind("close",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT));
    }

    static MethodHandle socketHandle() {
        return Handles.SOCKET;
    }

    private Libc() {
    }

    private static MethodHandle bind(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = LOOKUP.find(name).orElseThrow(
                () -> new ExceptionInInitializerError("libc symbol not found: " + name));
        return LINKER.downcallHandle(symbol, descriptor, Linker.Option.captureCallState("errno"));
    }

    /** Reads the captured errno. Only meaningful immediately after a {@code -1} return. */
    static int errno(MemorySegment state) {
        return (int) ERRNO.get(state, 0L);
    }

    /** §4.7's mapping. Anything unrecognised is {@link PingError#IO}. */
    static PingError toPingError(int errno) {
        return switch (errno) {
            case EHOSTUNREACH -> PingError.HOST_UNREACHABLE;
            case ENETUNREACH -> PingError.NETWORK_UNREACHABLE;
            case EACCES, EPERM -> PingError.PERMISSION;
            case ENETDOWN, ENXIO -> PingError.INTERFACE_DOWN;
            default -> PingError.IO;
        };
    }

    static String errnoName(int errno) {
        return switch (errno) {
            case EPERM -> "EPERM";
            case ENXIO -> "ENXIO";
            case EAGAIN -> "EAGAIN/EWOULDBLOCK";
            case EACCES -> "EACCES";
            case EINVAL -> "EINVAL";
            case ENETDOWN -> "ENETDOWN";
            case ENETUNREACH -> "ENETUNREACH";
            case EHOSTUNREACH -> "EHOSTUNREACH";
            default -> "errno " + errno;
        };
    }

    /** True when a {@code -1} from {@code recvfrom} is just the receive timeout expiring. */
    static boolean isTimeout(int errno) {
        return errno == EAGAIN;
    }

    /** Host-to-network order for a 16-bit value. */
    static short htons(int value) {
        return (short) (((value & 0xFF) << 8) | ((value >>> 8) & 0xFF));
    }

    /** Network-to-host order for a 16-bit value. */
    static int ntohs(short value) {
        int v = value & 0xFFFF;
        return ((v & 0xFF) << 8) | ((v >>> 8) & 0xFF);
    }

    static int socket(MemorySegment state, int domain, int type, int protocol)
            throws DiscoveryException {
        try {
            int fd = (int) Handles.SOCKET.invokeExact(state, domain, type, protocol);
            if (fd < 0) {
                int errno = errno(state);
                throw new DiscoveryException("socket(" + domain + "," + type + "," + protocol
                        + ") failed: " + errnoName(errno)
                        + (errno == EPERM || errno == EACCES
                                ? " - raw and AF_PACKET sockets require root or CAP_NET_RAW" : ""));
            }
            return fd;
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("socket() downcall failed", t);
        }
    }

    static void closeQuietly(MemorySegment state, int fd) {
        if (fd < 0) {
            return;
        }
        try {
            int ignored = (int) Handles.CLOSE.invokeExact(state, fd);
        } catch (Throwable ignored) {
            // tearing down; nothing useful to add
        }
    }

    /**
     * Sets the receive timeout that makes shutdown possible.
     * <p>
     * Closing a file descriptor does NOT wake a thread blocked in {@code recvfrom}
     * on Linux, and the fd number can be reused underneath it. Since §6.1 forbids
     * binding {@code fcntl} there is no non-blocking escape, so every blocking
     * reader depends on this returning {@code EAGAIN} on a regular tick.
     */
    static void setReceiveTimeout(Arena arena, MemorySegment state, int fd)
            throws DiscoveryException {
        MemorySegment tv = arena.allocate(TIMEVAL);
        tv.set(JAVA_LONG, 0, RECV_TIMEOUT_SEC);
        tv.set(JAVA_LONG, 8, RECV_TIMEOUT_USEC);
        try {
            int rc = (int) Handles.SETSOCKOPT.invokeExact(state, fd, SOL_SOCKET, SO_RCVTIMEO,
                                                  tv, (int) TIMEVAL.byteSize());
            if (rc != 0) {
                throw new DiscoveryException("setsockopt(SO_RCVTIMEO) failed: "
                                             + errnoName(errno(state)));
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("setsockopt(SO_RCVTIMEO) downcall failed", t);
        }
    }

    /**
     * Installs an {@code ICMP6_FILTER} passing only the given ICMPv6 types.
     * <p>
     * A set bit BLOCKS, so this starts from all-ones and clears the bit for each
     * wanted type. Without it the reader sees every ICMPv6 packet on the host,
     * including router advertisements and the neighbour discovery chatter of every
     * other process.
     */
    static void setIcmp6Filter(Arena arena, MemorySegment state, int fd, int... passTypes)
            throws DiscoveryException {
        MemorySegment filter = arena.allocate(ICMP6_FILTER_BYTES);
        for (int word = 0; word < ICMP6_FILTER_WORDS; word++) {
            filter.set(JAVA_INT, word * 4L, 0xFFFFFFFF);
        }
        for (int type : passTypes) {
            int word = (type >>> 5) & 7;
            int bit = type & 31;
            int current = filter.get(JAVA_INT, word * 4L);
            filter.set(JAVA_INT, word * 4L, current & ~(1 << bit));
        }
        try {
            int rc = (int) Handles.SETSOCKOPT.invokeExact(state, fd, IPPROTO_ICMPV6, ICMP6_FILTER,
                                                  filter, ICMP6_FILTER_BYTES);
            if (rc != 0) {
                throw new DiscoveryException("setsockopt(ICMP6_FILTER) failed: "
                                             + errnoName(errno(state)));
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("setsockopt(ICMP6_FILTER) downcall failed", t);
        }
    }

    /** Enables or disables promiscuous mode on an {@code AF_PACKET} socket. */
    static void setPromiscuous(Arena arena, MemorySegment state, int fd, int ifIndex,
                               boolean enable) throws DiscoveryException {
        MemorySegment mreq = arena.allocate(PACKET_MREQ);
        mreq.set(JAVA_INT, 0, ifIndex);
        mreq.set(JAVA_SHORT, 4, (short) PACKET_MR_PROMISC);
        mreq.set(JAVA_SHORT, 6, (short) 0);
        try {
            int rc = (int) Handles.SETSOCKOPT.invokeExact(state, fd, SOL_PACKET,
                    enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
                    mreq, (int) PACKET_MREQ.byteSize());
            if (rc != 0) {
                throw new DiscoveryException("setsockopt(PACKET_MR_PROMISC) failed: "
                                             + errnoName(errno(state)));
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("setsockopt(PACKET_MR_PROMISC) downcall failed", t);
        }
    }

    /** Fills a {@code sockaddr_in}. Port stays zero; ICMP has no ports. */
    static void fillSockaddrIn(MemorySegment sa, byte[] ipv4) {
        sa.fill((byte) 0);
        sa.set(JAVA_SHORT, 0, (short) AF_INET);
        MemorySegment.copy(ipv4, 0, sa, JAVA_BYTE, 4, 4);
    }

    /**
     * Fills a {@code sockaddr_in6}.
     *
     * @param scopeId the interface index, REQUIRED for link-local destinations —
     *                the kernel cannot route {@code fe80::} without it
     */
    static void fillSockaddrIn6(MemorySegment sa, byte[] ipv6, int scopeId) {
        sa.fill((byte) 0);
        sa.set(JAVA_SHORT, 0, (short) AF_INET6);
        MemorySegment.copy(ipv6, 0, sa, JAVA_BYTE, 8, 16);
        sa.set(JAVA_INT, 24, scopeId);
    }

    /**
     * Fills a {@code sockaddr_ll} for SENDING.
     * <p>
     * The on-wire ethertype comes from {@code sll_protocol} in THIS destination
     * sockaddr — not from the {@code protocol} argument given to {@code socket()},
     * which governs receive filtering. Both must be set.
     */
    static void fillSockaddrLl(MemorySegment sa, int ifIndex, int ethertype, byte[] destMac) {
        sa.fill((byte) 0);
        sa.set(JAVA_SHORT, 0, (short) AF_PACKET);
        sa.set(JAVA_SHORT, SLL_PROTOCOL, htons(ethertype));
        sa.set(JAVA_INT, SLL_IFINDEX, ifIndex);
        sa.set(JAVA_BYTE, SLL_HALEN, (byte) destMac.length);
        MemorySegment.copy(destMac, 0, sa, JAVA_BYTE, SLL_ADDR, destMac.length);
    }
}
