package io.xlogistx.nosneak.net.pcap;

import io.xlogistx.nosneak.net.common.DiscoveryException;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * One open {@code pcap_t}: capture, injection, and teardown.
 * <p>
 * This class owns the §12.7 serialization choke point. Every injection goes
 * through {@link #send}, which is {@code synchronized} — libpcap handles are not
 * thread-safe, and two threads filling the same native buffer produce a corrupt
 * frame. Keeping it to this ONE method is what makes the mechanism swappable: if
 * global pacing is ever needed, a writer thread replaces the body here and
 * nothing else changes.
 * <p>
 * NOT thread-safe for capture: {@link #nextPacket} must be called from exactly
 * one reader thread.
 */
public final class PcapHandle implements AutoCloseable {

    /** Big enough for any Ethernet frame; §6.4's "use 65536 and be done with it". */
    public static final int SNAPLEN = 65536;

    /**
     * Capture read timeout in milliseconds. MUST be positive — zero means wait
     * forever, which would make shutdown hang (§4.4).
     * <p>
     * DELIBERATELY SMALL, and not the 200 ms the draft suggested. This value is
     * not just a shutdown knob: libpcap batches captured packets until the timeout
     * expires, so it puts a floor under every measured RTT. Measured on real
     * hardware at 200 ms, a gateway one hop away reported ~197 ms with a 495 us
     * spread — the spread was real, the 197 ms was the read timeout. At 10 ms the
     * same path reports sub-millisecond times, and an idle reader wakes 100 times
     * a second instead of 5, which costs nothing measurable.
     */
    public static final int READ_TIMEOUT_MS = 10;

    private final Pcap.Handles h;
    private final PcapPlatform platform;
    private final String deviceName;
    private final MemorySegment pcap;
    private final Arena arena;

    /** Reused by the reader thread only, so it needs no synchronization. */
    private final MemorySegment headerHolder;
    private final MemorySegment dataHolder;

    private volatile boolean closed;

    private PcapHandle(Pcap.Handles h, PcapPlatform platform, String deviceName,
                       MemorySegment pcap, Arena arena) {
        this.h = h;
        this.platform = platform;
        this.deviceName = deviceName;
        this.pcap = pcap;
        this.arena = arena;
        this.headerHolder = arena.allocate(ADDRESS);
        this.dataHolder = arena.allocate(ADDRESS);
    }

    /**
     * Opens a device and verifies it is Ethernet.
     *
     * @param promiscuous pass true ONLY when an observe() subscription exists —
     *                    promiscuous mode raises capture volume substantially and
     *                    is detectable on the segment
     */
    public static PcapHandle open(String deviceName, boolean promiscuous) throws DiscoveryException {
        Pcap.Handles h = Pcap.load();
        PcapPlatform platform = Pcap.platform();
        // Shared, not confined: the reader thread touches segments allocated here,
        // and a confined arena would throw WrongThreadException (spec section 4.1).
        Arena arena = Arena.ofShared();
        try {
            MemorySegment name = arena.allocateFrom(deviceName);
            MemorySegment errbuf = Pcap.errbuf(arena);

            MemorySegment pcap = (MemorySegment) h.openLive().invokeExact(
                    name, SNAPLEN, promiscuous ? 1 : 0, READ_TIMEOUT_MS, errbuf);
            if (pcap.equals(MemorySegment.NULL)) {
                throw new DiscoveryException("pcap_open_live(" + deviceName + ") failed: "
                                             + Pcap.errbufText(errbuf));
            }

            int datalink = (int) h.datalink().invokeExact(pcap);
            if (datalink != Pcap.DLT_EN10MB) {
                h.close().invokeExact(pcap);
                throw new DiscoveryException(
                        "Device " + deviceName + " has datalink type " + datalink
                        + ", not DLT_EN10MB (" + Pcap.DLT_EN10MB + "). The codecs assume an "
                        + "Ethernet header unconditionally; loopback and tunnel interfaces "
                        + "would be parsed as garbage.");
            }
            return new PcapHandle(h, platform, deviceName, pcap, arena);
        } catch (DiscoveryException e) {
            arena.close();
            throw e;
        } catch (Throwable t) {
            arena.close();
            throw new DiscoveryException("pcap_open_live(" + deviceName + ") failed", t);
        }
    }

    /**
     * Installs a BPF filter so the kernel discards what we do not want before it
     * ever reaches the reader thread.
     * <p>
     * Note this does NOT match 802.1Q-tagged frames — prefix the expression with
     * {@code vlan} on a tagged segment, and remember a tag shifts every subsequent
     * offset by four bytes.
     */
    public void setFilter(String expression) throws DiscoveryException {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment program = scratch.allocate(Pcap.BPF_PROGRAM);
            MemorySegment text = scratch.allocateFrom(expression);

            int rc = (int) h.compile().invokeExact(pcap, program, text, 1,
                                                   Pcap.PCAP_NETMASK_UNKNOWN);
            if (rc != 0) {
                throw new DiscoveryException("pcap_compile(\"" + expression + "\") failed: "
                                             + Pcap.lastError(h, pcap));
            }
            try {
                rc = (int) h.setFilter().invokeExact(pcap, program);
                if (rc != 0) {
                    throw new DiscoveryException("pcap_setfilter failed: "
                                                 + Pcap.lastError(h, pcap));
                }
            } finally {
                // Always free the compiled program, or it leaks.
                h.freeCode().invokeExact(program);
            }
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            throw new DiscoveryException("installing BPF filter failed", t);
        }
    }

    /**
     * Injects a complete Ethernet frame.
     * <p>
     * SYNCHRONIZED: this is the one place sends are serialized for this handle
     * (§12.7). Do not add a second injection path.
     *
     * @return true when the frame was accepted by the driver
     */
    public synchronized boolean send(byte[] frame) {
        if (closed) {
            return false;
        }
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment buf = scratch.allocateFrom(JAVA_BYTE, frame);
            int rc = (int) h.sendPacket().invokeExact(pcap, buf, frame.length);
            return rc == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    /** The driver's explanation for the last failure, for diagnostics. */
    public String lastError() {
        return Pcap.lastError(h, pcap);
    }

    /**
     * Reads one packet. Call from ONE reader thread only.
     *
     * @return the captured bytes, or null on a timeout tick or a rejected header —
     *         both are normal and mean "loop again and re-check the running flag"
     * @throws DiscoveryException on a genuine capture error, which ends the loop
     */
    public byte[] nextPacket() throws DiscoveryException {
        if (closed) {
            return null;
        }
        try {
            int rc = (int) h.nextEx().invokeExact(pcap, headerHolder, dataHolder);
            if (rc == Pcap.PCAP_NEXT_TIMEOUT) {
                return null;
            }
            if (rc != Pcap.PCAP_NEXT_OK) {
                if (closed) {
                    return null;
                }
                throw new DiscoveryException("pcap_next_ex returned " + rc + ": " + lastError());
            }
            MemorySegment header = headerHolder.get(ADDRESS, 0)
                                              .reinterpret(platform.pktHdr().byteSize());
            if (!Pcap.plausibleHeader(platform, header, SNAPLEN)) {
                // Defensive: catches a pcap_pkthdr layout change immediately
                // instead of yielding silently corrupt frames.
                return null;
            }
            return Pcap.copyPacket(dataHolder.get(ADDRESS, 0), Pcap.caplen(platform, header));
        } catch (DiscoveryException e) {
            throw e;
        } catch (Throwable t) {
            if (closed) {
                return null;
            }
            throw new DiscoveryException("pcap_next_ex failed", t);
        }
    }

    public String deviceName() {
        return deviceName;
    }

    public boolean isClosed() {
        return closed;
    }

    /**
     * Idempotent.
     * <p>
     * THE READER THREAD MUST BE STOPPED FIRST. The header and data holders live in
     * a shared arena, and passing them to {@code pcap_next_ex} acquires that
     * arena's session for the duration of the call — so closing the arena while
     * the reader is inside a downcall throws
     * {@code IllegalStateException: Session is acquired by 1 clients} and leaves
     * the memory unfreed. The positive {@link #READ_TIMEOUT_MS} is what bounds how
     * long that wait can be. The catch below is belt-and-braces for a reader that
     * overran its join.
     */
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            h.close().invokeExact(pcap);
        } catch (Throwable ignored) {
            // Nothing useful to do while tearing down.
        }
        try {
            arena.close();
        } catch (IllegalStateException e) {
            // A reader still inside a downcall. The handle is closed, so it will
            // return promptly; the arena is reclaimed when the JVM exits.
        }
    }
}
