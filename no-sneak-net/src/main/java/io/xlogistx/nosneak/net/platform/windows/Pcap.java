package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.common.DiscoveryException;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * FFM bindings for Npcap's {@code wpcap.dll}, and the constants and struct
 * layouts that go with them.
 * <p>
 * Loading is the fiddly part. {@code wpcap.dll} installs to
 * {@code %SystemRoot%\System32\Npcap\}, which is NOT on the default DLL search
 * path, and it depends on {@code Packet.dll} sitting beside it — so loading it by
 * absolute path alone fails at dependency resolution with an unhelpful error.
 * {@link #load()} therefore tries the plain name first, which succeeds when Npcap
 * was installed in WinPcap-compatibility mode (a copy in {@code System32}), and
 * only then falls back to the Npcap subdirectory.
 * <p>
 * Override the location with {@code -Dio.xlogistx.nosneak.net.platform.windows.lib=<path>}.
 */
public final class Pcap {

    /** System property overriding where {@code wpcap.dll} is loaded from. */
    public static final String LIB_PROPERTY = "io.xlogistx.nosneak.net.platform.windows.lib";

    /**
     * MANDATORY minimum error-buffer allocation. Under-allocating this is a
     * native buffer overflow into JVM memory — always allocate exactly this.
     */
    public static final int PCAP_ERRBUF_SIZE = 256;

    /** Pass as {@code pcap_compile}'s netmask when the real one is unknown. */
    public static final int PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF;

    /** Ethernet. The ONLY datalink this backend supports. */
    public static final int DLT_EN10MB = 1;

    /** {@code pcap_next_ex} returned a packet. */
    public static final int PCAP_NEXT_OK = 1;
    /** {@code pcap_next_ex} timed out — a normal tick, not an error. */
    public static final int PCAP_NEXT_TIMEOUT = 0;

    /**
     * {@code struct bpf_program} — 16 bytes on LLP64 ({@code u_int} plus padding
     * plus a pointer).
     */
    public static final StructLayout BPF_PROGRAM = MemoryLayout.structLayout(
            JAVA_INT.withName("bf_len"),
            MemoryLayout.paddingLayout(4),
            ADDRESS.withName("bf_insns"));

    /**
     * {@code struct pcap_pkthdr} on Windows (LLP64) — 16 bytes, with a
     * {@code timeval} of two 32-bit longs. Identical on x86-64 and arm64. With
     * macOS off this backend, this is the only variant that is live.
     */
    public static final StructLayout PKTHDR = MemoryLayout.structLayout(
            JAVA_INT.withName("tv_sec"),
            JAVA_INT.withName("tv_usec"),
            JAVA_INT.withName("caplen"),
            JAVA_INT.withName("len"));

    /** Offsets into {@code pcap_if_t} — a linked list of devices. */
    static final long IF_NEXT = 0;
    static final long IF_NAME = 8;
    static final long IF_DESCRIPTION = 16;
    static final long IF_ADDRESSES = 24;

    /** Offsets into {@code pcap_addr}. */
    static final long ADDR_NEXT = 0;
    static final long ADDR_ADDR = 8;

    /** Windows address families. Note AF_INET6 is 23 here, not 10 or 30. */
    static final int AF_INET = 2;
    static final int AF_INET6 = 23;

    private static volatile Handles handles;

    private Pcap() {
    }

    /** The bound {@code wpcap.dll} entry points. */
    record Handles(
            MethodHandle findAllDevs,
            MethodHandle freeAllDevs,
            MethodHandle openLive,
            MethodHandle datalink,
            MethodHandle sendPacket,
            MethodHandle nextEx,
            MethodHandle compile,
            MethodHandle setFilter,
            MethodHandle freeCode,
            MethodHandle close,
            MethodHandle getErr) {
    }

    /**
     * Loads {@code wpcap.dll} and binds every entry point this backend needs.
     * Idempotent; the result is cached.
     *
     * @throws DiscoveryException when Npcap is not installed, naming the library
     *                            and where to get it. Never bundle the installer
     */
    public static Handles load() throws DiscoveryException {
        Handles local = handles;
        if (local != null) {
            return local;
        }
        synchronized (Pcap.class) {
            if (handles != null) {
                return handles;
            }
            SymbolLookup lookup = openLibrary();
            Linker linker = Linker.nativeLinker();

            handles = new Handles(
                    bind(linker, lookup, "pcap_findalldevs",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS)),
                    bind(linker, lookup, "pcap_freealldevs",
                         FunctionDescriptor.ofVoid(ADDRESS)),
                    bind(linker, lookup, "pcap_open_live",
                         FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT,
                                               JAVA_INT, ADDRESS)),
                    bind(linker, lookup, "pcap_datalink",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS)),
                    bind(linker, lookup, "pcap_sendpacket",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT)),
                    bind(linker, lookup, "pcap_next_ex",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS)),
                    bind(linker, lookup, "pcap_compile",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS,
                                               JAVA_INT, JAVA_INT)),
                    bind(linker, lookup, "pcap_setfilter",
                         FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS)),
                    bind(linker, lookup, "pcap_freecode",
                         FunctionDescriptor.ofVoid(ADDRESS)),
                    bind(linker, lookup, "pcap_close",
                         FunctionDescriptor.ofVoid(ADDRESS)),
                    bind(linker, lookup, "pcap_geterr",
                         FunctionDescriptor.of(ADDRESS, ADDRESS)));
            return handles;
        }
    }

    /** True when Npcap can be loaded, for capability probing without throwing. */
    public static boolean isAvailable() {
        try {
            load();
            return true;
        } catch (DiscoveryException e) {
            return false;
        }
    }

    private static SymbolLookup openLibrary() throws DiscoveryException {
        Arena global = Arena.global();

        String override = System.getProperty(LIB_PROPERTY);
        if (override != null && !override.isBlank()) {
            try {
                return SymbolLookup.libraryLookup(Path.of(override), global);
            } catch (IllegalArgumentException e) {
                throw new DiscoveryException(
                        LIB_PROPERTY + " points at an unloadable library: " + override, e);
            }
        }

        // Plain name first: this resolves when Npcap was installed in
        // WinPcap-compatibility mode, which also puts Packet.dll where the
        // loader will find it.
        try {
            return SymbolLookup.libraryLookup("wpcap", global);
        } catch (IllegalArgumentException ignored) {
            // fall through to the Npcap subdirectory
        }

        Path npcap = Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"),
                             "System32", "Npcap", "wpcap.dll");
        if (Files.isReadable(npcap)) {
            try {
                return SymbolLookup.libraryLookup(npcap, global);
            } catch (IllegalArgumentException e) {
                throw new DiscoveryException(
                        "Found " + npcap + " but could not load it. Npcap's wpcap.dll depends on "
                        + "Packet.dll in the same directory; install Npcap in "
                        + "WinPcap-compatible mode, or set " + LIB_PROPERTY, e);
            }
        }

        throw new DiscoveryException(
                "Npcap is not installed: wpcap.dll was not found on the DLL search path or at "
                + npcap + ". Install it from https://npcap.com/ (do not bundle the installer), "
                + "or set " + LIB_PROPERTY + " to an explicit path.");
    }

    private static MethodHandle bind(Linker linker, SymbolLookup lookup,
                                     String name, FunctionDescriptor descriptor)
            throws DiscoveryException {
        MemorySegment symbol = lookup.find(name).orElseThrow(() -> new DiscoveryException(
                "wpcap.dll loaded but is missing " + name
                + " - is this a WinPcap install rather than Npcap?"));
        return linker.downcallHandle(symbol, descriptor);
    }

    /** Reads a NUL-terminated C string, tolerating a null pointer. */
    static String cString(MemorySegment pointer) {
        if (pointer == null || pointer.equals(MemorySegment.NULL)) {
            return null;
        }
        return pointer.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /** Allocates an error buffer at exactly {@link #PCAP_ERRBUF_SIZE}. */
    static MemorySegment errbuf(Arena arena) {
        return arena.allocate(PCAP_ERRBUF_SIZE);
    }

    /** Reads whatever a pcap call left in an error buffer. */
    static String errbufText(MemorySegment errbuf) {
        String s = errbuf.getString(0);
        return s == null || s.isBlank() ? "(no detail)" : s;
    }

    /** Follows a {@code pcap_t*} error string. */
    static String lastError(Handles h, MemorySegment pcap) {
        try {
            MemorySegment msg = (MemorySegment) h.getErr().invokeExact(pcap);
            String s = cString(msg);
            return s == null ? "(no detail)" : s;
        } catch (Throwable t) {
            return "(pcap_geterr failed: " + t + ")";
        }
    }

    /** Reads {@code caplen} from a {@code pcap_pkthdr}. */
    static int caplen(MemorySegment pkthdr) {
        return pkthdr.get(JAVA_INT, 8);
    }

    /** Reads the on-wire {@code len} from a {@code pcap_pkthdr}. */
    static int wireLen(MemorySegment pkthdr) {
        return pkthdr.get(JAVA_INT, 12);
    }

    /**
     * The §8.5 defensive check. If a future Npcap build changes the struct this
     * catches it immediately rather than yielding silently corrupt frames.
     */
    static boolean plausibleHeader(MemorySegment pkthdr, int snaplen) {
        int caplen = caplen(pkthdr);
        int len = wireLen(pkthdr);
        return caplen > 0 && caplen <= len && len <= snaplen;
    }

    /** Copies the captured bytes out of pcap's buffer, which it reuses. */
    static byte[] copyPacket(MemorySegment dataPointer, int caplen) {
        return dataPointer.reinterpret(caplen).toArray(JAVA_BYTE);
    }
}
