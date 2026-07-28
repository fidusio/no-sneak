package io.xlogistx.nosneak.net.pcap;

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
 * FFM bindings for libpcap, shared by every backend that speaks it.
 * <p>
 * The API is identical across implementations — Npcap on Windows is libpcap-compatible
 * by design, and Darwin ships the reference implementation — so the eleven entry points,
 * the constants and {@code bpf_program} are written once here. Everything that genuinely
 * varies is behind {@link PcapPlatform}: which file to load, the {@code pcap_pkthdr}
 * layout, and how to read a {@code sockaddr} family.
 * <p>
 * {@code pcap_loop} and {@code pcap_dispatch} are deliberately NOT bound. They take a C
 * callback, which needs an FFM upcall stub and {@code pcap_breakloop} to escape;
 * {@code pcap_next_ex} with a positive read timeout does the same job with a plain
 * blocking loop (§4.4).
 * <p>
 * Override the library location with
 * {@code -Dio.xlogistx.nosneak.net.pcap.lib=<path>}.
 */
public final class Pcap {

    /** System property overriding where the pcap library is loaded from. */
    public static final String LIB_PROPERTY = "io.xlogistx.nosneak.net.pcap.lib";

    /**
     * The property this class used before it was shared with Darwin. Still honoured so
     * existing Windows launch scripts keep working; prefer {@link #LIB_PROPERTY}.
     */
    public static final String LEGACY_LIB_PROPERTY =
            "io.xlogistx.nosneak.net.platform.windows.lib";

    /**
     * MANDATORY minimum error-buffer allocation. Under-allocating this is a native
     * buffer overflow into JVM memory — always allocate exactly this.
     */
    public static final int PCAP_ERRBUF_SIZE = 256;

    /** Pass as {@code pcap_compile}'s netmask when the real one is unknown. */
    public static final int PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF;

    /** Ethernet. The ONLY datalink these backends support. */
    public static final int DLT_EN10MB = 1;

    /** {@code pcap_next_ex} returned a packet. */
    public static final int PCAP_NEXT_OK = 1;
    /** {@code pcap_next_ex} timed out — a normal tick, not an error. */
    public static final int PCAP_NEXT_TIMEOUT = 0;

    /**
     * {@code struct bpf_program} — 16 bytes on both LLP64 and LP64 ({@code u_int} plus
     * padding plus a pointer), so unlike {@code pcap_pkthdr} this one does not vary.
     */
    public static final StructLayout BPF_PROGRAM = MemoryLayout.structLayout(
            JAVA_INT.withName("bf_len"),
            MemoryLayout.paddingLayout(4),
            ADDRESS.withName("bf_insns"));

    /** Offsets into {@code pcap_if_t} — a linked list of devices. Pointer-sized, so LP64/LLP64 agree. */
    static final long IF_NEXT = 0;
    static final long IF_NAME = 8;
    static final long IF_DESCRIPTION = 16;
    static final long IF_ADDRESSES = 24;

    /** Offsets into {@code pcap_addr}. */
    static final long ADDR_NEXT = 0;
    static final long ADDR_ADDR = 8;

    private static volatile Handles handles;
    private static volatile PcapPlatform platform;

    private Pcap() {
    }

    /** The bound library entry points. */
    public record Handles(
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
     * Loads the platform's pcap library and binds every entry point these backends need.
     * Idempotent; the result is cached.
     *
     * @throws DiscoveryException when pcap is not installed, naming the library and how
     *                            to get it. Never bundle an installer
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
            PcapPlatform p = PcapPlatform.current();
            SymbolLookup lookup = openLibrary(p);
            Linker linker = Linker.nativeLinker();

            Handles bound = new Handles(
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
            // Publish the platform only once binding has succeeded, so a failed load
            // never leaves layout accessors answering for a library that is not there.
            platform = p;
            handles = bound;
            return handles;
        }
    }

    /** The platform whose layouts apply. Requires {@link #load()} to have succeeded. */
    public static PcapPlatform platform() throws DiscoveryException {
        PcapPlatform p = platform;
        if (p == null) {
            load();
            p = platform;
        }
        return p;
    }

    /** True when pcap can be loaded, for capability probing without throwing. */
    public static boolean isAvailable() {
        try {
            load();
            return true;
        } catch (DiscoveryException e) {
            return false;
        }
    }

    private static SymbolLookup openLibrary(PcapPlatform p) throws DiscoveryException {
        Arena global = Arena.global();

        String override = System.getProperty(LIB_PROPERTY);
        if (override == null || override.isBlank()) {
            override = System.getProperty(LEGACY_LIB_PROPERTY);
        }
        if (override != null && !override.isBlank()) {
            try {
                return SymbolLookup.libraryLookup(Path.of(override), global);
            } catch (IllegalArgumentException e) {
                throw new DiscoveryException(
                        LIB_PROPERTY + " points at an unloadable library: " + override, e);
            }
        }

        // Bare name first: it resolves through the normal loader search, which is also
        // where any co-located dependency (Npcap's Packet.dll) will be found.
        try {
            return SymbolLookup.libraryLookup(p.libraryName(), global);
        } catch (IllegalArgumentException ignored) {
            // fall through to the explicit locations
        }

        for (Path candidate : p.searchPaths()) {
            if (!Files.isReadable(candidate)) {
                continue;
            }
            try {
                return SymbolLookup.libraryLookup(candidate, global);
            } catch (IllegalArgumentException e) {
                throw new DiscoveryException(
                        "Found " + candidate + " but could not load it. " + p.installHint()
                        + ", or set " + LIB_PROPERTY, e);
            }
        }

        throw new DiscoveryException(
                "libpcap is not available: '" + p.libraryName() + "' was not found on the "
                + "library search path or at " + p.searchPaths() + ". " + p.installHint()
                + ", or set " + LIB_PROPERTY + " to an explicit path.");
    }

    private static MethodHandle bind(Linker linker, SymbolLookup lookup,
                                     String name, FunctionDescriptor descriptor)
            throws DiscoveryException {
        MemorySegment symbol = lookup.find(name).orElseThrow(() -> new DiscoveryException(
                "pcap library loaded but is missing " + name
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

    /** Reads {@code caplen} from a {@code pcap_pkthdr} at the platform's offset. */
    static int caplen(PcapPlatform p, MemorySegment pkthdr) {
        return pkthdr.get(JAVA_INT, p.caplenOffset());
    }

    /** Reads the on-wire {@code len} from a {@code pcap_pkthdr}. */
    static int wireLen(PcapPlatform p, MemorySegment pkthdr) {
        return pkthdr.get(JAVA_INT, p.wireLenOffset());
    }

    /**
     * The §8.5 defensive check. If a future build changes the struct — or the wrong
     * platform's offsets are in use — this catches it immediately instead of yielding
     * silently corrupt frames.
     */
    static boolean plausibleHeader(PcapPlatform p, MemorySegment pkthdr, int snaplen) {
        int caplen = caplen(p, pkthdr);
        int len = wireLen(p, pkthdr);
        return caplen > 0 && caplen <= len && len <= snaplen;
    }

    /** Copies the captured bytes out of pcap's buffer, which it reuses. */
    static byte[] copyPacket(MemorySegment dataPointer, int caplen) {
        return dataPointer.reinterpret(caplen).toArray(JAVA_BYTE);
    }
}
