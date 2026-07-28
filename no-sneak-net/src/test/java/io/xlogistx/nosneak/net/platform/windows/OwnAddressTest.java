package io.xlogistx.nosneak.net.platform.windows;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Which addresses this host answers for itself.
 * <p>
 * A pcap ping cannot observe its own loopback reply, so these are answered from the
 * binding instead of the wire. Getting the SET wrong is the risk: too narrow and a
 * self-ping still reports a live host as 100% lost; too wide and we would claim a
 * real neighbour is alive without ever probing it.
 */
public class OwnAddressTest {

    private static NicBinding nic(String name, int index, String ipv4, int prefix) {
        return new NicBinding(name, name, index, MacAddress.parse("b0:7b:25:82:64:45"),
                              List.of(new NicBinding.LocalAddress(
                                      InetAddress.ofLiteral(ipv4), prefix)),
                              List.of(), 1500);
    }

    /** Two NICs, as on the machine this was built against. */
    private static final List<NicBinding> BINDINGS = List.of(
            nic("ethernet_32769", 4, "10.0.0.61", 24),
            nic("ethernet_32770", 16, "192.168.56.1", 24));

    private static boolean own(String ip) {
        return WindowsPcapBackend.ownAddress(InetAddress.ofLiteral(ip), BINDINGS);
    }

    @Test
    public void ourOwnAddressOnTheBoundInterface() {
        assertTrue(own("10.0.0.61"));
    }

    /** One pinger serves every NIC, so the second adapter's address is ours too. */
    @Test
    public void anotherInterfacesAddressIsStillThisHost() {
        assertTrue(own("192.168.56.1"));
    }

    /**
     * Loopback has no binding at all — {@code usableInterfaces()} filters it out — so
     * it must be recognised from the address. Before this it failed with
     * NETWORK_UNREACHABLE rather than merely timing out.
     */
    @Test
    public void loopbackIsRecognisedWithoutABinding() {
        assertTrue(own("127.0.0.1"));
        assertTrue(own("127.0.0.53"), "the whole 127/8 range, not just .1");
        assertTrue(own("::1"));
    }

    /** A neighbour on our own subnet is emphatically not us. */
    @Test
    public void aNeighbourOnTheSameSubnetIsNotUs() {
        assertFalse(own("10.0.0.108"));
        assertFalse(own("10.0.0.1"), "the gateway shares our subnet and is still a real host");
        assertFalse(own("192.168.56.2"));
    }

    @Test
    public void offLinkAddressesAreNotUs() {
        assertFalse(own("8.8.8.8"));
        assertFalse(own("2001:4860:4860::8888"));
    }

    @Test
    public void nullAndEmptyBindingsAreHandled() {
        assertFalse(WindowsPcapBackend.ownAddress(null, BINDINGS));
        assertFalse(WindowsPcapBackend.ownAddress(InetAddress.ofLiteral("10.0.0.61"), List.of()),
                    "with no bindings only loopback can be recognised");
        assertTrue(WindowsPcapBackend.ownAddress(InetAddress.ofLiteral("127.0.0.1"), List.of()));
    }
}
