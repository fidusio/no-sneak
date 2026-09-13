package io.xlogistx.nosneak.net.platform.linux;

import io.xlogistx.nosneak.net.codecs.Icmp6;
import io.xlogistx.nosneak.net.codecs.Ipv6Header;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the frame-level test {@code discoverIpv6Segment} uses for {@code icmpAlive}
 * (§13.24): an ICMPv6 echo REPLY, addressed to one of OUR addresses, from an on-link
 * sender the passive-learning guard accepts. Pure — no socket, runs anywhere.
 */
class Ipv6SegmentEchoTest {

    private static final MacAddress OUR_MAC = MacAddress.parse("aa:bb:cc:dd:ee:ff");
    private static final MacAddress THEIR_MAC = MacAddress.parse("42:25:47:35:03:ec");
    private static final byte[] OURS = ip("fe80::ea8b:7c7d:1c4c:6a56");
    private static final byte[] THEIRS = ip("fe80::4025:47ff:fe35:3ec");
    private static final byte[] SOMEONE_ELSE = ip("fe80::1");

    private static final NicBinding BINDING = new NicBinding("eth0", "eth0", 2, OUR_MAC,
            List.of(new NicBinding.LocalAddress(addr("10.0.0.61"), 24)),
            List.of(new NicBinding.LocalAddress(addr("fe80::ea8b:7c7d:1c4c:6a56"), 64)),
            1500);

    @Test
    void anEchoReplyToOneOfOurAddressesCounts() {
        byte[] frame = frame(THEIRS, OURS, echo(Icmp6.TYPE_ECHO_REPLY));
        assertTrue(classify(frame, THEIR_MAC));
    }

    @Test
    void anEchoReplyToSomeoneElseDoesNot() {
        // Only visible in promiscuous mode, and never evidence that WE were answered.
        byte[] frame = frame(THEIRS, SOMEONE_ELSE, echo(Icmp6.TYPE_ECHO_REPLY));
        assertFalse(classify(frame, THEIR_MAC));
    }

    @Test
    void anEchoRequestDoesNot() {
        byte[] frame = frame(THEIRS, OURS, echo(Icmp6.TYPE_ECHO_REQUEST));
        assertFalse(classify(frame, THEIR_MAC));
    }

    @Test
    void aNeighborSolicitationDoesNot() {
        byte[] ns = Icmp6.neighborSolicitation(THEIRS, OURS, THEIR_MAC);
        byte[] frame = frame(THEIRS, OURS, ns);
        assertFalse(classify(frame, THEIR_MAC));
    }

    @Test
    void ourOwnReplyLoopedBackDoesNot() {
        // The learner's guard rejects our own address and our own MAC.
        byte[] frame = frame(OURS, OURS, echo(Icmp6.TYPE_ECHO_REPLY));
        assertFalse(classify(frame, OUR_MAC));
    }

    @Test
    void aReplyFromAnOffLinkSenderDoesNot() {
        // Its frame carries the router's MAC, which is the case the on-link guard exists for.
        byte[] frame = frame(ip("2001:db8::9"), OURS, echo(Icmp6.TYPE_ECHO_REPLY));
        assertFalse(classify(frame, THEIR_MAC));
    }

    @Test
    void aTruncatedPayloadDoesNot() {
        byte[] frame = frame(THEIRS, OURS, new byte[] {(byte) Icmp6.TYPE_ECHO_REPLY, 0, 0});
        assertFalse(classify(frame, THEIR_MAC));
    }

    private static boolean classify(byte[] frame, MacAddress frameSource) {
        Ipv6Header.View ip = Ipv6Header.parse(frame, 0, frame.length).orElseThrow();
        int off = Ipv6Header.LENGTH;
        int len = Math.min(ip.payloadLength(), frame.length - off);
        return LinuxHostDiscovery.isEchoReplyToUs(BINDING, ip, frame, off, len, frameSource);
    }

    /** An IPv6 frame body as the SOCK_DGRAM reader sees it: header, then ICMPv6. */
    private static byte[] frame(byte[] src, byte[] dst, byte[] icmp) {
        byte[] header = Ipv6Header.build(src, dst, Ipv6Header.NEXT_HEADER_ICMPV6, 64, icmp.length);
        byte[] out = new byte[header.length + icmp.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(icmp, 0, out, header.length, icmp.length);
        return out;
    }

    /** An 8-byte ICMPv6 echo header of the given type plus a short payload. */
    private static byte[] echo(int type) {
        byte[] e = Icmp6.echoRequestUnchecksummed(0x1234, 7, new byte[] {1, 2, 3, 4});
        e[0] = (byte) type;
        return e;
    }

    private static byte[] ip(String literal) {
        return addr(literal).getAddress();
    }

    private static InetAddress addr(String literal) {
        return InetAddress.ofLiteral(literal);
    }
}
