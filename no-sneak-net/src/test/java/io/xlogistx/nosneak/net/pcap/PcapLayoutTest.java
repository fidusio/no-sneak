package io.xlogistx.nosneak.net.pcap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The pcap struct layouts and {@code sockaddr} shapes, pinned per platform.
 * <p>
 * Host-independent by construction — {@link PcapPlatform} is an enum of pure arithmetic,
 * so both variants can be checked from any machine. That is the whole point: §11.2 asks
 * for these assertions precisely so a layout mistake is caught on a developer box rather
 * than as silently corrupt frames on the only hardware that runs it. Nothing here loads a
 * library or opens a device.
 */
class PcapLayoutTest {

    @Test
    @DisplayName("Windows pcap_pkthdr is 16 bytes with caplen at 8")
    void windowsPktHdr() {
        assertEquals(16, PcapPlatform.WINDOWS.pktHdr().byteSize());
        assertEquals(8, PcapPlatform.WINDOWS.caplenOffset());
        assertEquals(12, PcapPlatform.WINDOWS.wireLenOffset());
    }

    /**
     * Darwin's {@code timeval} is an 8-byte {@code tv_sec} plus a 32-bit {@code tv_usec}
     * padded out to 8, so the header is half again as long and {@code caplen} moves from
     * 8 to 16. Reading it at the Windows offset would return the high half of a
     * timestamp — a large number that the plausibility check rejects, which is how this
     * mistake surfaces if it is ever made.
     */
    @Test
    @DisplayName("Darwin pcap_pkthdr is 24 bytes with caplen at 16")
    void darwinPktHdr() {
        assertEquals(24, PcapPlatform.DARWIN.pktHdr().byteSize());
        assertEquals(16, PcapPlatform.DARWIN.caplenOffset());
        assertEquals(20, PcapPlatform.DARWIN.wireLenOffset());
    }

    /**
     * Linux agrees with Darwin on size and offsets but NOT on why: {@code suseconds_t}
     * is a full {@code long} here, so {@code timeval} is two 8-byte fields with no
     * padding, where Darwin's is 8 + 4 + 4. Identical arithmetic, different struct —
     * which is exactly the kind of coincidence worth pinning, so nobody later "unifies"
     * them and then breaks one by editing the other.
     * <p>
     * These numbers are not derived from documentation: they were confirmed by opening a
     * live handle on Linux and capturing real frames through {@link PcapHandle}.
     */
    @Test
    @DisplayName("Linux pcap_pkthdr is 24 bytes with caplen at 16, like Darwin")
    void linuxPktHdr() {
        assertEquals(24, PcapPlatform.LINUX.pktHdr().byteSize());
        assertEquals(16, PcapPlatform.LINUX.caplenOffset());
        assertEquals(20, PcapPlatform.LINUX.wireLenOffset());
        assertEquals(PcapPlatform.DARWIN.caplenOffset(), PcapPlatform.LINUX.caplenOffset());
    }

    @Test
    @DisplayName("the platforms genuinely disagree — this is not a copy-paste")
    void layoutsDiffer() {
        assertNotEquals(PcapPlatform.WINDOWS.pktHdr().byteSize(),
                        PcapPlatform.DARWIN.pktHdr().byteSize());
        assertNotEquals(PcapPlatform.WINDOWS.caplenOffset(),
                        PcapPlatform.DARWIN.caplenOffset());
        // AF_INET6 is the classic one: 23 / 30 / 10, no two alike.
        assertNotEquals(PcapPlatform.WINDOWS.afInet6(), PcapPlatform.DARWIN.afInet6());
        assertNotEquals(PcapPlatform.DARWIN.afInet6(), PcapPlatform.LINUX.afInet6());
        assertNotEquals(PcapPlatform.WINDOWS.afInet6(), PcapPlatform.LINUX.afInet6());
        assertEquals(10, PcapPlatform.LINUX.afInet6());
    }

    /**
     * Linux has no {@code sa_len}, so it reads the family exactly as Windows does. Pinned
     * because the BSD/non-BSD split is the thing to get right, not "Unix versus Windows"
     * — grouping Linux with Darwin because both are Unix would silently shift the family
     * read by one byte.
     */
    @Test
    @DisplayName("Linux reads sockaddr like Windows, not like Darwin")
    void linuxSockaddrIsNotBsdShaped() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sa = arena.allocate(28);
            sa.fill((byte) 0);
            sa.set(JAVA_BYTE, 0, (byte) 2);
            assertEquals(PcapPlatform.AF_INET, PcapPlatform.LINUX.readFamily(sa));
            assertEquals(PcapPlatform.WINDOWS.readFamily(sa), PcapPlatform.LINUX.readFamily(sa));
            assertNotEquals(PcapPlatform.DARWIN.readFamily(sa), PcapPlatform.LINUX.readFamily(sa));
        }
    }

    @Test
    @DisplayName("bpf_program is 16 bytes on both — u_int, padding, pointer")
    void bpfProgramIsPortable() {
        assertEquals(16, Pcap.BPF_PROGRAM.byteSize());
    }

    /**
     * The error buffer is not a tuning knob: {@code pcap_findalldevs} and
     * {@code pcap_open_live} write up to this many bytes unconditionally, so
     * under-allocating is a native overflow into JVM memory.
     */
    @Test
    @DisplayName("PCAP_ERRBUF_SIZE is exactly 256")
    void errbufSize() {
        assertEquals(256, Pcap.PCAP_ERRBUF_SIZE);
    }

    /**
     * Windows has a 16-bit family at offset 0; the BSDs lead with {@code sa_len} and put
     * a one-byte family at offset 1. Same size, different shape — the class of error that
     * fails silently, so it gets an explicit test.
     */
    @Test
    @DisplayName("sockaddr family is read at the right place on each platform")
    void sockaddrFamilyShape() {
        try (Arena arena = Arena.ofConfined()) {
            // A Windows sockaddr_in: family 2 little-endian at offset 0.
            MemorySegment win = arena.allocate(28);
            win.fill((byte) 0);
            win.set(JAVA_BYTE, 0, (byte) 2);
            assertEquals(PcapPlatform.AF_INET, PcapPlatform.WINDOWS.readFamily(win));

            // A Darwin sockaddr_in: sin_len=16 at 0, family 2 at offset 1.
            MemorySegment mac = arena.allocate(28);
            mac.fill((byte) 0);
            mac.set(JAVA_BYTE, 0, (byte) 16);
            mac.set(JAVA_BYTE, 1, (byte) 2);
            assertEquals(PcapPlatform.AF_INET, PcapPlatform.DARWIN.readFamily(mac));

            // Reading a Darwin sockaddr with the Windows rule sees the length byte and
            // gets nonsense — the concrete failure this test exists to prevent.
            assertNotEquals(PcapPlatform.AF_INET, PcapPlatform.WINDOWS.readFamily(mac));

            // AF_INET6 differs too: 30 on Darwin, 23 on Windows.
            MemorySegment mac6 = arena.allocate(28);
            mac6.fill((byte) 0);
            mac6.set(JAVA_BYTE, 0, (byte) 28);
            mac6.set(JAVA_BYTE, 1, (byte) 30);
            assertEquals(PcapPlatform.DARWIN.afInet6(), PcapPlatform.DARWIN.readFamily(mac6));
            assertEquals(23, PcapPlatform.WINDOWS.afInet6());
        }
    }

    @Test
    @DisplayName("address payload offsets agree across platforms")
    void addressOffsetsAreShared() {
        // The BSD length byte consumes space the Windows family field also uses, so the
        // payloads land in the same place even though the headers differ. Worth pinning:
        // it is the reason readFamily is the ONLY per-platform sockaddr accessor.
        assertEquals(4, PcapPlatform.SIN_ADDR_OFFSET);
        assertEquals(8, PcapPlatform.SIN6_ADDR_OFFSET);
    }

    @Test
    @DisplayName("every platform names a library and a usable install hint")
    void platformsAreFullyDescribed() {
        for (PcapPlatform p : PcapPlatform.values()) {
            assertTrue(p.libraryName() != null && !p.libraryName().isBlank(), p.name());
            assertTrue(p.installHint() != null && !p.installHint().isBlank(), p.name());
            assertTrue(p.searchPaths() != null, p.name());
        }
    }
}
