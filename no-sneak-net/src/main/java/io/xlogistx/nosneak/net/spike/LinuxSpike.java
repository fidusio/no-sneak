package io.xlogistx.nosneak.net.spike;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.Icmp4Echo;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.HexFormat;
import java.util.Optional;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * The §13.1 aarch64 appliance spike — the GATE that must pass before any backend
 * work begins.
 * <p>
 * Three things are being proven, and nothing else:
 * <ol>
 *   <li>libc downcalls resolve through {@code defaultLookup()}, and
 *       {@code Linker.Option.captureCallState("errno")} returns a readable errno
 *       on a deliberate {@code -1}.</li>
 *   <li>{@code AF_PACKET}+{@code SOCK_DGRAM} ARP round-trips against an on-link
 *       host, with the ethertype read from {@code sll_protocol} in the
 *       {@code recvfrom} sockaddr and the source MAC from {@code sll_addr}.</li>
 *   <li>{@code SOCK_RAW}/{@code IPPROTO_ICMP} echo returns the FULL IPv4 header
 *       with a plausible TTL at offset 8.</li>
 * </ol>
 * It also reports which {@code --enable-native-access} form this JVM actually
 * needs, which settles the open §12.8 question.
 * <p>
 * MUST RUN ON LINUX AS ROOT. {@code AF_PACKET} does not exist elsewhere and
 * {@code SOCK_RAW} requires {@code CAP_NET_RAW}. This class is diagnostic
 * scaffolding, not part of the subsystem — delete it once the gate has passed and
 * the real backend exists.
 *
 * <pre>
 * mvn -o -pl no-sneak-net compile
 * sudo java --enable-native-access=ALL-UNNAMED \
 *      -cp no-sneak-net/target/classes \
 *      io.xlogistx.nosneak.net.spike.LinuxSpike eth0 192.168.1.1 192.168.1.1
 * </pre>
 */
public final class LinuxSpike {

    // ---- Linux constants (identical on x86-64 and aarch64, §6.2) ----
    private static final int AF_INET = 2;
    private static final int AF_PACKET = 17;
    private static final int SOCK_DGRAM = 2;
    private static final int SOCK_RAW = 3;
    private static final int IPPROTO_ICMP = 1;
    private static final int ETH_P_ARP = 0x0806;
    private static final int SOL_SOCKET = 1;
    private static final int SO_RCVTIMEO = 20;

    private static final StructLayout SOCKADDR_IN = MemoryLayout.structLayout(
            JAVA_SHORT.withName("sin_family"),
            JAVA_SHORT.withName("sin_port"),
            JAVA_INT.withName("sin_addr"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero"));

    private static final StructLayout SOCKADDR_LL = MemoryLayout.structLayout(
            JAVA_SHORT.withName("sll_family"),
            JAVA_SHORT.withName("sll_protocol"),
            JAVA_INT.withName("sll_ifindex"),
            JAVA_SHORT.withName("sll_hatype"),
            JAVA_BYTE.withName("sll_pkttype"),
            JAVA_BYTE.withName("sll_halen"),
            MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sll_addr"));

    private static final StructLayout TIMEVAL = MemoryLayout.structLayout(
            JAVA_LONG.withName("tv_sec"),
            JAVA_LONG.withName("tv_usec"));

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBC = LINKER.defaultLookup();
    private static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO =
            CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    /**
     * Held in a nested class so the JVM resolves these symbols LAZILY, on first
     * use. Resolving them eagerly in a static initialiser would make this tool die
     * with an {@code ExceptionInInitializerError} on any non-Linux box before it
     * could print the far more useful "must run on Linux" message.
     */
    private static final class Libc {
        static final MethodHandle SOCKET = downcall(
                "socket", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
        static final MethodHandle BIND = downcall(
                "bind", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle SENDTO = downcall(
                "sendto", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG,
                                                JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle RECVFROM = downcall(
                "recvfrom", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG,
                                                  JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle SETSOCKOPT = downcall(
                "setsockopt", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                                                    ADDRESS, JAVA_INT));
        static final MethodHandle CLOSE = downcall(
                "close", FunctionDescriptor.of(JAVA_INT, JAVA_INT));
    }

    private static int passed;
    private static int failed;

    private LinuxSpike() {
    }

    public static void main(String[] args) throws Throwable {
        String nicName = args.length > 0 ? args[0] : null;
        String arpTarget = args.length > 1 ? args[1] : null;
        String pingTarget = args.length > 2 ? args[2] : (args.length > 1 ? args[1] : null);

        System.out.println("=== no-sneak-net 13.1 appliance spike ===");
        reportEnvironment();

        if (!System.getProperty("os.name", "").toLowerCase().contains("linux")) {
            System.out.println("\nABORT: this spike must run on Linux. AF_PACKET does not exist "
                               + "elsewhere and SOCK_RAW needs CAP_NET_RAW.");
            System.exit(2);
        }

        checkOne();

        if (nicName == null || arpTarget == null) {
            System.out.println("\nSKIPPED checks 2 and 3: pass <interface> <arpTargetIp> "
                               + "[pingTargetIp], e.g. eth0 192.168.1.1");
        } else {
            NicBinding binding = NicBinding.from(NetworkInterface.getByName(nicName), null);
            System.out.println("\nbinding: " + binding.javaName()
                               + " ifIndex=" + binding.ifIndex()
                               + " mac=" + binding.hardwareAddress()
                               + " mtu=" + binding.mtu());
            checkTwo(binding, InetAddress.ofLiteral(arpTarget));
            checkThree(InetAddress.ofLiteral(pingTarget));
        }

        System.out.println("\n=== " + passed + " passed, " + failed + " failed ===");
        System.out.println(failed == 0
                ? "GATE PASSED - step 6 may begin."
                : "GATE FAILED - do NOT proceed to step 6 (see spec section 13).");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Settles §12.8: which {@code --enable-native-access} form this JVM needs. */
    private static void reportEnvironment() {
        Module m = LinuxSpike.class.getModule();
        System.out.println("java.version = " + System.getProperty("java.version"));
        System.out.println("os           = " + System.getProperty("os.name")
                           + " / " + System.getProperty("os.arch"));
        System.out.println("module       = " + (m.isNamed() ? m.getName() : "UNNAMED (classpath)"));
        System.out.println("native-access form to pin: "
                           + (m.isNamed() ? "--enable-native-access=" + m.getName()
                                          : "--enable-native-access=ALL-UNNAMED"));
        System.out.println("layout sizes : sockaddr_in=" + SOCKADDR_IN.byteSize()
                           + " sockaddr_ll=" + SOCKADDR_LL.byteSize()
                           + " timeval=" + TIMEVAL.byteSize()
                           + "  (expect 16 / 20 / 16)");
    }

    // ---- check 1: libc + errno ----

    private static void checkOne() throws Throwable {
        System.out.println("\n[1] libc downcalls and captureCallState(\"errno\")");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CAPTURE);

            // A deliberately invalid domain: must return -1 and set errno.
            int fd = (int) Libc.SOCKET.invokeExact(state, -1, -1, -1);
            int errno = (int) ERRNO.get(state, 0L);

            if (fd == -1 && errno != 0) {
                pass("socket(-1,-1,-1) returned -1 with errno=" + errno
                     + " (" + errnoName(errno) + ") - errno capture works");
            } else {
                fail("expected -1 with a non-zero errno, got fd=" + fd + " errno=" + errno);
            }

            // And a call that must succeed, proving the same handle works both ways.
            int ok = (int) Libc.SOCKET.invokeExact(state, AF_INET, SOCK_DGRAM, 0);
            if (ok >= 0) {
                pass("socket(AF_INET,SOCK_DGRAM,0) = " + ok);
                closeFd(state, ok);
            } else {
                fail("could not open even a UDP socket: errno=" + (int) ERRNO.get(state, 0L));
            }
        }
    }

    // ---- check 2: AF_PACKET ARP ----

    private static void checkTwo(NicBinding binding, InetAddress target) throws Throwable {
        System.out.println("\n[2] AF_PACKET/SOCK_DGRAM ARP round-trip to " + target.getHostAddress());

        if (binding.hardwareAddress() == null) {
            fail("interface has no hardware address; cannot build an ARP request");
            return;
        }
        Optional<NicBinding.LocalAddress> source = binding.sourceFor(target);
        if (source.isEmpty()) {
            fail("interface has no IPv4 address to use as the ARP sender");
            return;
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CAPTURE);
            int fd = (int) Libc.SOCKET.invokeExact(state, AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
            if (fd < 0) {
                fail("socket(AF_PACKET,SOCK_DGRAM,ETH_P_ARP) failed, errno="
                     + (int) ERRNO.get(state, 0L) + " - are we root?");
                return;
            }
            try {
                setReceiveTimeout(arena, state, fd, 2);

                // Bind so this socket only sees THIS interface (§6.4).
                MemorySegment bindAddr = arena.allocate(SOCKADDR_LL);
                putShortHostOrder(bindAddr, 0, AF_PACKET);
                putShortRaw(bindAddr, 2, htons(ETH_P_ARP));
                bindAddr.set(JAVA_INT, 4, binding.ifIndex());
                int rc = (int) Libc.BIND.invokeExact(state, fd, bindAddr, (int) SOCKADDR_LL.byteSize());
                if (rc != 0) {
                    fail("bind to ifIndex " + binding.ifIndex() + " failed, errno="
                         + (int) ERRNO.get(state, 0L));
                    return;
                }

                byte[] request = ArpPacket.request(binding.hardwareAddress(),
                                                   source.get().address().getAddress(),
                                                   target.getAddress());
                MemorySegment payload = arena.allocateFrom(JAVA_BYTE, request);

                MemorySegment dest = arena.allocate(SOCKADDR_LL);
                putShortHostOrder(dest, 0, AF_PACKET);
                putShortRaw(dest, 2, htons(ETH_P_ARP));
                dest.set(JAVA_INT, 4, binding.ifIndex());
                dest.set(JAVA_BYTE, 9, (byte) 6);                 // sll_halen
                for (int i = 0; i < 6; i++) {
                    dest.set(JAVA_BYTE, 10 + i, (byte) 0xFF);     // sll_addr = broadcast
                }

                long sent = (long) Libc.SENDTO.invokeExact(state, fd, payload, (long) request.length,
                                                      0, dest, (int) SOCKADDR_LL.byteSize());
                if (sent < 0) {
                    fail("sendto failed, errno=" + (int) ERRNO.get(state, 0L));
                    return;
                }
                pass("sent " + sent + "-byte ARP request for " + target.getHostAddress());

                MemorySegment buf = arena.allocate(2048);
                MemorySegment from = arena.allocate(SOCKADDR_LL);
                MemorySegment fromLen = arena.allocate(JAVA_INT);
                boolean sawReply = false;

                for (int attempt = 0; attempt < 8 && !sawReply; attempt++) {
                    fromLen.set(JAVA_INT, 0, (int) SOCKADDR_LL.byteSize());
                    long n = (long) Libc.RECVFROM.invokeExact(state, fd, buf, 2048L, 0, from, fromLen);
                    if (n < 0) {
                        continue; // EAGAIN from SO_RCVTIMEO, or nothing for us
                    }
                    int ethertype = ntohs(from.get(JAVA_SHORT, 2));
                    byte[] srcMacRaw = new byte[6];
                    MemorySegment.copy(from, JAVA_BYTE, 10, srcMacRaw, 0, 6);

                    byte[] frame = buf.asSlice(0, n).toArray(JAVA_BYTE);
                    Optional<ArpPacket.ArpView> view = ArpPacket.parse(frame, 0, frame.length);
                    if (view.isEmpty() || view.get().oper() != ArpPacket.OPER_REPLY) {
                        continue;
                    }
                    ArpPacket.ArpView arp = view.get();
                    if (!java.util.Arrays.equals(arp.spa(), target.getAddress())) {
                        continue;
                    }

                    sawReply = true;
                    MacAddress fromSll = new MacAddress(srcMacRaw);
                    pass("ARP reply: " + target.getHostAddress() + " is at " + arp.sha());
                    pass("ethertype from sll_protocol = 0x"
                         + Integer.toHexString(ethertype)
                         + (ethertype == ETH_P_ARP ? " (correct - NOT read from the payload)"
                                                   : " (WRONG, expected 0x806)"));
                    if (ethertype != ETH_P_ARP) {
                        fail("sll_protocol did not carry the ethertype");
                    }
                    pass("source MAC from sll_addr = " + fromSll
                         + (fromSll.equals(arp.sha()) ? " (matches payload SHA)"
                                                      : " (MISMATCH vs payload SHA " + arp.sha()
                                                        + " - spoofing evidence)"));
                }
                if (!sawReply) {
                    fail("no ARP reply from " + target.getHostAddress()
                         + " - is it on-link and up?");
                }
            } finally {
                closeFd(state, fd);
            }
        }
    }

    // ---- check 3: SOCK_RAW ICMP ----

    private static void checkThree(InetAddress target) throws Throwable {
        System.out.println("\n[3] SOCK_RAW/IPPROTO_ICMP echo to " + target.getHostAddress());

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CAPTURE);
            int fd = (int) Libc.SOCKET.invokeExact(state, AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (fd < 0) {
                fail("socket(AF_INET,SOCK_RAW,IPPROTO_ICMP) failed, errno="
                     + (int) ERRNO.get(state, 0L) + " - are we root?");
                return;
            }
            try {
                setReceiveTimeout(arena, state, fd, 2);

                int id = 0x5A5A;
                byte[] echo = Icmp4Echo.request(id, 1, "no-sneak-spike".getBytes());
                MemorySegment payload = arena.allocateFrom(JAVA_BYTE, echo);

                MemorySegment dest = arena.allocate(SOCKADDR_IN);
                putShortHostOrder(dest, 0, AF_INET);
                putShortRaw(dest, 2, (short) 0);
                MemorySegment.copy(target.getAddress(), 0, dest, JAVA_BYTE, 4, 4);

                long sent = (long) Libc.SENDTO.invokeExact(state, fd, payload, (long) echo.length,
                                                      0, dest, (int) SOCKADDR_IN.byteSize());
                if (sent < 0) {
                    fail("sendto failed, errno=" + (int) ERRNO.get(state, 0L));
                    return;
                }
                pass("sent " + sent + "-byte ICMP echo request, id=0x" + Integer.toHexString(id));

                MemorySegment buf = arena.allocate(65536);
                boolean sawReply = false;

                for (int attempt = 0; attempt < 8 && !sawReply; attempt++) {
                    long n = (long) Libc.RECVFROM.invokeExact(state, fd, buf, 65536L, 0,
                                                         MemorySegment.NULL, MemorySegment.NULL);
                    if (n < 20) {
                        continue;
                    }
                    byte[] pkt = buf.asSlice(0, n).toArray(JAVA_BYTE);

                    int version = (pkt[0] & 0xFF) >>> 4;
                    int ihl = (pkt[0] & 0x0F) * 4;
                    int ttl = pkt[8] & 0xFF;
                    if (version != 4 || ihl < 20 || n < ihl + 8) {
                        continue;
                    }
                    Optional<Icmp4Echo.EchoView> view =
                            Icmp4Echo.parseReply(pkt, ihl, (int) n - ihl);
                    if (view.isEmpty() || view.get().id() != id) {
                        continue; // another process's ICMP - this is why we filter on id
                    }

                    sawReply = true;
                    System.out.println("    IP header: "
                                       + HexFormat.of().formatHex(pkt, 0, Math.min(ihl, 20)));
                    pass("full IPv4 header present: version=" + version + " ihl=" + ihl
                         + " bytes - SOCK_RAW delivers it, so no recvmsg is needed");
                    if (ttl > 0 && ttl <= 255) {
                        pass("TTL at offset 8 = " + ttl + " (plausible; hopCount="
                             + io.xlogistx.nosneak.net.codecs.TtlDistance.hopCount(ttl)
                                     .map(String::valueOf).orElse("n/a")
                             + ", osHint="
                             + io.xlogistx.nosneak.net.codecs.TtlDistance.osHint(ttl)
                                     .orElse("n/a") + ")");
                    } else {
                        fail("implausible TTL at offset 8: " + ttl);
                    }
                }
                if (!sawReply) {
                    fail("no echo reply from " + target.getHostAddress());
                }
            } finally {
                closeFd(state, fd);
            }
        }
    }

    // ---- helpers ----

    private static void setReceiveTimeout(Arena arena, MemorySegment state, int fd, long seconds)
            throws Throwable {
        MemorySegment tv = arena.allocate(TIMEVAL);
        tv.set(JAVA_LONG, 0, seconds);
        tv.set(JAVA_LONG, 8, 0L);
        int rc = (int) Libc.SETSOCKOPT.invokeExact(state, fd, SOL_SOCKET, SO_RCVTIMEO,
                                              tv, (int) TIMEVAL.byteSize());
        if (rc != 0) {
            System.out.println("    warning: SO_RCVTIMEO failed, errno="
                               + (int) ERRNO.get(state, 0L) + " - a hang is possible");
        }
    }

    private static void closeFd(MemorySegment state, int fd) throws Throwable {
        int ignored = (int) Libc.CLOSE.invokeExact(state, fd);
    }

    private static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = LIBC.find(name).orElseThrow(
                () -> new ExceptionInInitializerError("libc symbol not found: " + name));
        return LINKER.downcallHandle(symbol, descriptor, Linker.Option.captureCallState("errno"));
    }

    /** Host-order 16-bit field, as sockaddr family fields are. */
    private static void putShortHostOrder(MemorySegment seg, long offset, int value) {
        seg.set(ValueLayout.JAVA_SHORT, offset, (short) value);
    }

    /** Writes an already-network-ordered 16-bit value without further byte swapping. */
    private static void putShortRaw(MemorySegment seg, long offset, short networkOrdered) {
        seg.set(ValueLayout.JAVA_SHORT, offset, networkOrdered);
    }

    private static short htons(int value) {
        return (short) (((value & 0xFF) << 8) | ((value >>> 8) & 0xFF));
    }

    private static int ntohs(short value) {
        int v = value & 0xFFFF;
        return ((v & 0xFF) << 8) | ((v >>> 8) & 0xFF);
    }

    private static String errnoName(int errno) {
        return switch (errno) {
            case 1 -> "EPERM";
            case 9 -> "EBADF";
            case 13 -> "EACCES";
            case 22 -> "EINVAL";
            case 93 -> "EPROTONOSUPPORT";
            case 97 -> "EAFNOSUPPORT";
            default -> "errno " + errno;
        };
    }

    private static void pass(String message) {
        passed++;
        System.out.println("  PASS  " + message);
    }

    private static void fail(String message) {
        failed++;
        System.out.println("  FAIL  " + message);
    }
}
