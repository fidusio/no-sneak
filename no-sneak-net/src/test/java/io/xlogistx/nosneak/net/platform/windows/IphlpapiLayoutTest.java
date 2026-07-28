package io.xlogistx.nosneak.net.platform.windows;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code MIB_IPNET_ROW2}'s layout, re-derived from member sizes rather than copied
 * from the constants under test, plus the degradation contract that keeps a wrong
 * layout harmless.
 * <p>
 * The offsets themselves were confirmed empirically on Windows 10 x64 by reading
 * back MACs already known from {@code arp -a} (§13.16); this test is the guard that
 * stops one of them being edited to a plausible-looking wrong number afterwards.
 * It runs everywhere — it is arithmetic, not a native call.
 */
public class IphlpapiLayoutTest {

    // Member sizes, x64 and arm64 alike: both are LP64/LLP64 with identical
    // alignment for every type in this struct (§2.3).
    private static final long SOCKADDR_INET = 28;   // union; widest arm is sockaddr_in6
    private static final long NET_IFINDEX = 4;      // ULONG
    private static final long NET_LUID = 8;         // union over ULONG64, so 8-aligned
    private static final long PHYSICAL_ADDRESS = 32; // IF_MAX_PHYS_ADDRESS_LENGTH
    private static final long ULONG = 4;
    private static final long NL_NEIGHBOR_STATE = 4; // enum

    private static long align(long offset, long alignment) {
        long remainder = offset % alignment;
        return remainder == 0 ? offset : offset + (alignment - remainder);
    }

    @Test
    public void offsetsFollowFromMemberSizesAndAlignment() {
        long address = 0;
        long interfaceIndex = address + SOCKADDR_INET;              // 28
        long interfaceLuid = align(interfaceIndex + NET_IFINDEX, 8); // 32, already aligned
        long physicalAddress = interfaceLuid + NET_LUID;            // 40
        long physicalAddressLength = physicalAddress + PHYSICAL_ADDRESS; // 72
        long state = physicalAddressLength + ULONG;                 // 76

        assertEquals(address, Iphlpapi.IPNET_ADDRESS_OFFSET);
        assertEquals(interfaceIndex, Iphlpapi.IPNET_INTERFACE_INDEX_OFFSET);
        assertEquals(physicalAddress, Iphlpapi.IPNET_PHYSICAL_ADDRESS_OFFSET);
        assertEquals(physicalAddressLength, Iphlpapi.IPNET_PHYSICAL_ADDRESS_LENGTH_OFFSET);
        assertEquals(state, Iphlpapi.IPNET_STATE_OFFSET);
    }

    /** Flags byte plus its padding, then ReachabilityTime, then the trailing 8-alignment. */
    @Test
    public void sizeAccountsForEveryMemberAndTheTrailingPad() {
        long afterState = Iphlpapi.IPNET_STATE_OFFSET + NL_NEIGHBOR_STATE;  // 80
        long afterFlags = align(afterState + 1, ULONG);                     // 84
        long afterReachabilityTime = afterFlags + ULONG;                    // 88
        assertEquals(align(afterReachabilityTime, 8), Iphlpapi.MIB_IPNET_ROW2_BYTES);
        assertEquals(0, Iphlpapi.MIB_IPNET_ROW2_BYTES % 8,
                     "a struct containing a NET_LUID must be a multiple of its 8-byte alignment");
    }

    /**
     * The whole point of the hint being optional: on any platform where the library
     * or the symbol is missing, this must report "no hint" rather than throwing, so
     * solicitation falls back to broadcast — the behaviour before it existed.
     */
    @Test
    public void neighborLookupDegradesInsteadOfThrowing() {
        assertNotNull(Iphlpapi.neighborMac(InetAddress.ofLiteral("10.255.255.254"), 1));
        assertTrue(Iphlpapi.neighborMac(InetAddress.ofLiteral("10.255.255.254"), 1).isEmpty(),
                   "an address with no neighbour entry must yield no hint");
        // An interface index nothing owns cannot have neighbours either. This also
        // proves InterfaceIndex is read where we think: at a wrong offset Windows
        // would ignore the value and could still answer for a real address.
        assertTrue(Iphlpapi.neighborMac(InetAddress.ofLiteral("127.0.0.1"), 999_999).isEmpty());
    }

    @Test
    public void availabilityIsConsistentWithThePlatform() {
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT)
                                .contains("windows");
        if (!windows) {
            assertTrue(Iphlpapi.neighborMac(InetAddress.ofLiteral("10.0.0.1"), 1).isEmpty(),
                       "iphlpapi cannot load off Windows, so there is never a hint");
        }
    }
}
