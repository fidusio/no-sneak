package io.xlogistx.nosneak.net.platform.darwin;

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
 * libc bindings, constants and struct layouts for the macOS backend.
 * <p>
 * Darwin's {@code sockaddr} structures are the SAME SIZE as Linux's but a
 * DIFFERENT SHAPE — there is a leading {@code sin_len} byte, so the family is one
 * byte at offset 1 rather than two bytes at offset 0. Same size with a different
 * layout is precisely the kind of error that fails silently, which is why these
 * are declared separately rather than shared with {@code platform.linux}.
 * <p>
 * No {@code ioctl} and no BPF. Active L2 on Darwin would mean {@code /dev/bpf*},
 * which is root-owned, exclusive-open and {@code ioctl}-configured — variadic,
 * hitting the arm64 {@code firstVariadicArg} hazard. {@code sysctl} is
 * non-variadic, unprivileged and pure libc, which is the whole argument for the
 * neighbor-table approach.
 */
final class DarwinLibc {

    // ---- constants (§7.1) ----
    static final int AF_INET = 2;
    static final int AF_INET6 = 30;          // NOT 10 as on Linux, nor 23 as on Windows
    static final int AF_LINK = 18;
    static final int SOCK_DGRAM = 2;
    static final int IPPROTO_ICMP = 1;
    static final int IPPROTO_ICMPV6 = 58;
    static final int SOL_SOCKET = 0xFFFF;    // NOT 1 as on Linux
    static final int SO_RCVTIMEO = 0x1006;   // NOT 20 as on Linux
    static final int CTL_NET = 4;
    static final int PF_ROUTE = 17;
    static final int NET_RT_FLAGS = 2;
    static final int RTF_LLINFO = 0x400;

    // ---- errno (BSD values; several differ from Linux) ----
    static final int EPERM = 1;
    static final int ENXIO = 6;
    static final int EACCES = 13;
    static final int EINVAL = 22;
    static final int EAGAIN = 35;            // 11 on Linux
    static final int EPROTONOSUPPORT = 43;   // 93 on Linux
    static final int EAFNOSUPPORT = 47;      // 97 on Linux
    static final int ENETDOWN = 50;          // 100 on Linux
    static final int ENETUNREACH = 51;       // 101 on Linux
    static final int EHOSTUNREACH = 65;      // 113 on Linux

    static final long RECV_TIMEOUT_SEC = 0;
    static final long RECV_TIMEOUT_USEC = 200_000;

    /**
     * Darwin {@code sockaddr_in} — 16 bytes, same as Linux, but with a leading
     * length byte so the family sits at offset 1.
     */
    static final StructLayout SOCKADDR_IN = MemoryLayout.structLayout(
            JAVA_BYTE.withName("sin_len"),
            JAVA_BYTE.withName("sin_family"),
            JAVA_SHORT.withName("sin_port"),
            JAVA_INT.withName("sin_addr"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero"));

    /** Darwin {@code sockaddr_in6} — 28 bytes, same leading-length-byte shape. */
    static final StructLayout SOCKADDR_IN6 = MemoryLayout.structLayout(
            JAVA_BYTE.withName("sin6_len"),
            JAVA_BYTE.withName("sin6_family"),
            JAVA_SHORT.withName("sin6_port"),
            JAVA_INT.withName("sin6_flowinfo"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("sin6_addr"),
            JAVA_INT.withName("sin6_scope_id"));

    /**
     * Darwin {@code struct timeval} — 16 bytes, but {@code tv_usec} is 32-bit and
     * padded, unlike Linux where both fields are 64-bit. Same size, different
     * shape again.
     */
    static final StructLayout TIMEVAL = MemoryLayout.structLayout(
            JAVA_LONG.withName("tv_sec"),
            JAVA_INT.withName("tv_usec"),
            MemoryLayout.paddingLayout(4));

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = LINKER.defaultLookup();
    static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO =
            CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    /**
     * Lazily resolved so the constants and layouts above stay readable on any
     * platform — the §11.2 layout tests must run on a developer machine.
     */
    static final class Handles {
        static final MethodHandle SOCKET = bind("socket",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
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
        /**
         * {@code sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
         * void *newp, size_t newlen)} — non-variadic, which is the entire reason
         * this is reachable from FFM on arm64 at all.
         */
        static final MethodHandle SYSCTL = bind("sysctl",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS,
                                      ADDRESS, JAVA_LONG));
    }

    private DarwinLibc() {
    }

    private static MethodHandle bind(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = LOOKUP.find(name).orElseThrow(
                () -> new ExceptionInInitializerError("libc symbol not found: " + name));
        return LINKER.downcallHandle(symbol, descriptor, Linker.Option.captureCallState("errno"));
    }

    static int errno(MemorySegment state) {
        return (int) ERRNO.get(state, 0L);
    }

    /** §4.7's mapping, against BSD errno values. */
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
            case EACCES -> "EACCES";
            case EINVAL -> "EINVAL";
            case EAGAIN -> "EAGAIN";
            case EPROTONOSUPPORT -> "EPROTONOSUPPORT";
            case EAFNOSUPPORT -> "EAFNOSUPPORT";
            case ENETDOWN -> "ENETDOWN";
            case ENETUNREACH -> "ENETUNREACH";
            case EHOSTUNREACH -> "EHOSTUNREACH";
            default -> "errno " + errno;
        };
    }

    static boolean isTimeout(int errno) {
        return errno == EAGAIN;
    }

    /**
     * Like {@link #socket} but returns {@code -1} instead of throwing, leaving
     * errno readable in {@code state}.
     * <p>
     * Exists because an ICMP family the kernel will not give us is a DEGRADED
     * CAPABILITY, not a fatal error. Darwin hands out {@code SOCK_DGRAM}/
     * {@code IPPROTO_ICMP} to any user, but the ICMPv6 equivalent is not
     * dependably unprivileged, and failing the whole pinger over it would take
     * working IPv4 ICMP down with it.
     */
    static int trySocket(MemorySegment state, int domain, int type, int protocol) {
        try {
            return (int) Handles.SOCKET.invokeExact(state, domain, type, protocol);
        } catch (Throwable t) {
            return -1;
        }
    }

    static void closeQuietly(MemorySegment state, int fd) {
        if (fd < 0) {
            return;
        }
        try {
            int ignored = (int) Handles.CLOSE.invokeExact(state, fd);
        } catch (Throwable ignored) {
            // tearing down
        }
    }

    /** Note the Darwin values: {@code SOL_SOCKET} is 0xFFFF and the timeval is padded. */
    static void setReceiveTimeout(Arena arena, MemorySegment state, int fd)
            throws DiscoveryException {
        MemorySegment tv = arena.allocate(TIMEVAL);
        tv.set(JAVA_LONG, 0, RECV_TIMEOUT_SEC);
        tv.set(JAVA_INT, 8, (int) RECV_TIMEOUT_USEC);
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

    /** Fills a Darwin {@code sockaddr_in}: length byte first, family at offset 1. */
    static void fillSockaddrIn(MemorySegment sa, byte[] ipv4) {
        sa.fill((byte) 0);
        sa.set(JAVA_BYTE, 0, (byte) SOCKADDR_IN.byteSize());
        sa.set(JAVA_BYTE, 1, (byte) AF_INET);
        MemorySegment.copy(ipv4, 0, sa, JAVA_BYTE, 4, 4);
    }

    /** Fills a Darwin {@code sockaddr_in6}. {@code scopeId} is required for {@code fe80::}. */
    static void fillSockaddrIn6(MemorySegment sa, byte[] ipv6, int scopeId) {
        sa.fill((byte) 0);
        sa.set(JAVA_BYTE, 0, (byte) SOCKADDR_IN6.byteSize());
        sa.set(JAVA_BYTE, 1, (byte) AF_INET6);
        MemorySegment.copy(ipv6, 0, sa, JAVA_BYTE, 8, 16);
        sa.set(JAVA_INT, 24, scopeId);
    }
}
