package io.xlogistx.nosneak.net.pcap;

import io.xlogistx.nosneak.net.common.DiscoveryException;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Everything about libpcap that differs between operating systems, in one place.
 * <p>
 * The libpcap API itself is identical everywhere — same eleven entry points, same
 * semantics — so {@link Pcap}, {@link PcapHandle} and {@link PcapDevices} are shared
 * verbatim. Three things are not portable, and they all live here:
 * <ol>
 *   <li>which library file to load, and where it hides;</li>
 *   <li>the {@code pcap_pkthdr} layout, which depends on {@code struct timeval} and so
 *       on the data model — 16 bytes on Windows LLP64, 24 on a 64-bit Unix;</li>
 *   <li>how to read the address family out of a {@code sockaddr}, because the BSDs put
 *       a length byte in front of it and Windows does not.</li>
 * </ol>
 * Selection is on {@code os.name} only, never {@code os.arch} — the same rule §2.3
 * applies to every other layout in this module.
 */
public enum PcapPlatform {

    /**
     * Npcap. {@code wpcap.dll} installs to {@code %SystemRoot%\System32\Npcap\}, which
     * is NOT on the default DLL search path, and it depends on {@code Packet.dll} beside
     * it — so loading it by absolute path alone fails at dependency resolution with an
     * unhelpful error. The plain name is tried first, which succeeds when Npcap was
     * installed in WinPcap-compatibility mode (a copy in {@code System32}, where the
     * loader also finds {@code Packet.dll}).
     */
    WINDOWS("wpcap") {
        @Override
        public List<Path> searchPaths() {
            return List.of(Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"),
                                   "System32", "Npcap", "wpcap.dll"));
        }

        /** LLP64: {@code timeval} is two 32-bit longs, so the header is 16 bytes. */
        @Override
        public StructLayout pktHdr() {
            return MemoryLayout.structLayout(
                    JAVA_INT.withName("tv_sec"),
                    JAVA_INT.withName("tv_usec"),
                    JAVA_INT.withName("caplen"),
                    JAVA_INT.withName("len"));
        }

        @Override
        public long caplenOffset() {
            return 8;
        }

        @Override
        public long wireLenOffset() {
            return 12;
        }

        /** No {@code sa_len}: the family is a 16-bit field at offset 0. */
        @Override
        public int readFamily(MemorySegment sockaddr) {
            return (sockaddr.get(JAVA_BYTE, 0) & 0xFF)
                    | ((sockaddr.get(JAVA_BYTE, 1) & 0xFF) << 8);
        }

        @Override
        public int afInet6() {
            return 23;
        }

        @Override
        public String installHint() {
            return "Install it from https://npcap.com/ (do not bundle the installer)";
        }
    },

    /**
     * Darwin's system libpcap, at {@code /usr/lib/libpcap.dylib}. Preinstalled — unlike
     * Npcap this is not a dependency the operator has to satisfy, which is most of the
     * argument for using it here at all.
     * <p>
     * Capture still needs root: {@code /dev/bpf*} is mode 0600.
     */
    DARWIN("pcap") {
        @Override
        public List<Path> searchPaths() {
            return List.of(Path.of("/usr/lib/libpcap.dylib"),
                           Path.of("/usr/lib/libpcap.A.dylib"));
        }

        /**
         * LP64: {@code timeval} is an 8-byte {@code tv_sec} plus a 32-bit
         * {@code tv_usec} padded to 8, so the header is 24 bytes and {@code caplen}
         * sits at 16 rather than 8. Reading it at the Windows offset would return the
         * top half of a timestamp and be rejected by the plausibility check — which is
         * exactly what that check is for.
         */
        @Override
        public StructLayout pktHdr() {
            return MemoryLayout.structLayout(
                    JAVA_LONG.withName("tv_sec"),
                    JAVA_INT.withName("tv_usec"),
                    MemoryLayout.paddingLayout(4),
                    JAVA_INT.withName("caplen"),
                    JAVA_INT.withName("len"));
        }

        @Override
        public long caplenOffset() {
            return 16;
        }

        @Override
        public long wireLenOffset() {
            return 20;
        }

        /** BSD {@code sockaddr} leads with {@code sa_len}, so the family is ONE byte at 1. */
        @Override
        public int readFamily(MemorySegment sockaddr) {
            return sockaddr.get(JAVA_BYTE, 1) & 0xFF;
        }

        @Override
        public int afInet6() {
            return 30;
        }

        @Override
        public String installHint() {
            return "libpcap ships with macOS; check /usr/lib/libpcap.dylib exists";
        }
    },

    /**
     * Linux libpcap. **Nothing uses this today** — the Linux backend talks to
     * {@code AF_PACKET} directly, which needs no library, gives ICMP kernel routing for
     * free, and is verified on x86-64 and aarch64. This entry exists so that choosing
     * libpcap on Linux later is a backend decision rather than an ABI excavation.
     * <p>
     * Were it ever adopted, the trade is known: one BPF-filtered handle would replace
     * three typed {@code AF_PACKET} sockets, taking readers from {@code 2+3N} to
     * {@code 2+N}, at the cost of a runtime dependency on {@code libpcap.so} and — if
     * ICMP were moved across too — reimplementing the next-hop routing that the kernel
     * currently does for nothing.
     */
    LINUX("pcap") {
        /**
         * The bare name resolves to {@code libpcap.so}, which on many distributions is a
         * symlink shipped only with the {@code -dev} package; a runtime-only host has
         * just the versioned soname. Hence the explicit fallbacks.
         * <p>
         * These paths mention an architecture, which is NOT a violation of §2.3 — that
         * rule is about struct layouts and constants being selected on {@code os.name}
         * alone, and none are selected here. This is a filesystem search list, and
         * Debian multiarch genuinely puts the file under a triplet directory.
         */
        @Override
        public List<Path> searchPaths() {
            List<Path> out = new java.util.ArrayList<>();
            for (String dir : List.of("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                                      "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
                                      "/usr/lib64", "/usr/lib", "/lib")) {
                for (String name : List.of("libpcap.so.1", "libpcap.so.0.8", "libpcap.so")) {
                    out.add(Path.of(dir, name));
                }
            }
            return List.copyOf(out);
        }

        /**
         * LP64, 24 bytes — the same size and offsets as Darwin, but for a different
         * reason worth writing down: Linux {@code suseconds_t} is a full {@code long},
         * so {@code timeval} is two 8-byte fields with no padding, where Darwin's is
         * 8 + 4 + 4 padding. Identical arithmetic, different struct.
         */
        @Override
        public StructLayout pktHdr() {
            return MemoryLayout.structLayout(
                    JAVA_LONG.withName("tv_sec"),
                    JAVA_LONG.withName("tv_usec"),
                    JAVA_INT.withName("caplen"),
                    JAVA_INT.withName("len"));
        }

        @Override
        public long caplenOffset() {
            return 16;
        }

        @Override
        public long wireLenOffset() {
            return 20;
        }

        /** No {@code sa_len} on Linux: a 16-bit family at offset 0, as on Windows. */
        @Override
        public int readFamily(MemorySegment sockaddr) {
            return (sockaddr.get(JAVA_BYTE, 0) & 0xFF)
                    | ((sockaddr.get(JAVA_BYTE, 1) & 0xFF) << 8);
        }

        @Override
        public int afInet6() {
            return 10;
        }

        @Override
        public String installHint() {
            return "Install libpcap (Debian/Ubuntu: apt install libpcap0.8)";
        }
    };

    /** Same on every platform this module supports. */
    public static final int AF_INET = 2;

    /**
     * The IPv4 address sits at offset 4 and the IPv6 address at offset 8 in
     * {@code sockaddr_in}/{@code sockaddr_in6} on BOTH shapes — the BSD length byte
     * consumes space the Windows family field also uses, so the payload offsets happen
     * to agree even though the headers do not. Only {@link #readFamily} differs.
     */
    public static final long SIN_ADDR_OFFSET = 4;
    public static final long SIN6_ADDR_OFFSET = 8;

    private final String libraryName;

    PcapPlatform(String libraryName) {
        this.libraryName = libraryName;
    }

    /** The bare name to hand {@code SymbolLookup.libraryLookup} first. */
    public String libraryName() {
        return libraryName;
    }

    /** Absolute fallbacks, tried in order when the bare name does not resolve. */
    public abstract List<Path> searchPaths();

    public abstract StructLayout pktHdr();

    public abstract long caplenOffset();

    public abstract long wireLenOffset();

    /** Reads {@code sa_family} from a {@code sockaddr}, honouring the BSD length byte. */
    public abstract int readFamily(MemorySegment sockaddr);

    /** 23 on Windows, 30 on Darwin — and 10 on Linux, which is why this is never assumed. */
    public abstract int afInet6();

    /** Appended to the "library not found" error, so the message is actionable. */
    public abstract String installHint();

    /**
     * Selects on {@code os.name}.
     *
     * @throws DiscoveryException on a platform with no pcap backend, naming it rather
     *                            than failing later inside a downcall
     */
    public static PcapPlatform current() throws DiscoveryException {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return WINDOWS;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return DARWIN;
        }
        if (os.contains("linux")) {
            // Reachable only if something deliberately calls into this package on Linux.
            // HostDiscoveryFactory does not: it routes Linux to the AF_PACKET backend.
            return LINUX;
        }
        throw new DiscoveryException(
                "No pcap layout is defined for os.name='" + System.getProperty("os.name")
                + "'. Supported: Windows (Npcap), macOS and Linux (libpcap).");
    }
}
