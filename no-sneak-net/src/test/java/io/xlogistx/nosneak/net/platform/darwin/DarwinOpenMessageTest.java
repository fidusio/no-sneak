package io.xlogistx.nosneak.net.platform.darwin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** M5: open() blames privilege only when the cause plausibly is privilege (§13.23-B). */
public class DarwinOpenMessageTest {

    private static final String ROOT_ADVICE = "requires root";

    @Test
    public void permissionDeniedExplainsBpfAndRoot() {
        String m = DarwinPcapBackend.openFailureMessage("en0",
                "en0: (cannot open BPF device) /dev/bpf0: Permission denied");
        assertTrue(m.contains(ROOT_ADVICE), m);
        assertTrue(m.contains("/dev/bpf*"), m);
        assertTrue(m.contains("openIcmpOnly()"), m);
        assertTrue(m.contains("Permission denied"), "pcap's own text is kept: " + m);
    }

    @Test
    public void operationNotPermittedExplainsBpfAndRoot() {
        String m = DarwinPcapBackend.openFailureMessage("en0",
                "pcap_open_live(en0) failed: Operation not permitted");
        assertTrue(m.contains(ROOT_ADVICE), m);
    }

    @Test
    public void datalinkMismatchLeadsWithPcapTextAndNoRootAdvice() {
        String m = DarwinPcapBackend.openFailureMessage("utun3",
                "utun3 is not an Ethernet device (datalink 12); this backend speaks Ethernet only");
        assertFalse(m.contains(ROOT_ADVICE), m);
        assertTrue(m.startsWith("Could not open utun3 for capture on macOS: utun3 is not"), m);
    }

    @Test
    public void deviceNotConfiguredLeadsWithPcapText() {
        String m = DarwinPcapBackend.openFailureMessage("en5",
                "pcap_open_live(en5) failed: en5: Device not configured");
        assertFalse(m.contains(ROOT_ADVICE), m);
        assertTrue(m.contains("Device not configured"), m);
    }

    @Test
    public void deviceNameIsAlwaysPresent() {
        assertTrue(DarwinPcapBackend.openFailureMessage("en7", null).contains("en7"));
        assertTrue(DarwinPcapBackend.openFailureMessage("en7", null).contains("(no detail)"));
    }
}
