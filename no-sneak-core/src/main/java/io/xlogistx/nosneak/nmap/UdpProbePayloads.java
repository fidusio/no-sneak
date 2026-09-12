package io.xlogistx.nosneak.nmap;

import java.nio.charset.StandardCharsets;

/**
 * The datagram a UDP port probe sends, by port. Every payload is the minimal protocol-legal
 * request a well-behaved client would send first, and nothing more:
 * <ul>
 *   <li><b>53 (DNS)</b> — one standard recursive query, type A, for a fixed name;</li>
 *   <li><b>123 (NTP)</b> — a 48-byte client (mode 3) request, version 4;</li>
 *   <li><b>everything else</b> — an empty datagram. Silence is then reported as
 *       {@code open|filtered}, which is the honest answer for a service we did not speak to.</li>
 * </ul>
 * Deliberately absent: SNMP. An SNMP GET carries a community string, and sending {@code public}
 * to see who answers is a credential guess — out of scope for assessment tooling (repo root
 * {@code CLAUDE.md}, <i>Operating scope</i>). SNMP on 161 gets the empty datagram like any other
 * port.
 */
public final class UdpProbePayloads {

    /** The name the DNS probe asks for. Any resolver answers a query for it; a non-resolver ignores it. */
    public static final String DNS_QUERY_NAME = "xlogistx.io";
    /** Fixed transaction id ({@code "NS"}), so a reply can be matched by the caller if it wishes. */
    public static final int DNS_TRANSACTION_ID = 0x4E53;

    private static final byte[] EMPTY = new byte[0];

    private UdpProbePayloads() {
    }

    public static byte[] forPort(int port) {
        return switch (port) {
            case 53 -> dnsQueryA(DNS_QUERY_NAME, DNS_TRANSACTION_ID);
            case 123 -> ntpClientRequest();
            default -> EMPTY;
        };
    }

    /**
     * A standard query (RFC 1035 §4.1): header with RD set, one question of type A, class IN.
     */
    public static byte[] dnsQueryA(String name, int transactionId) {
        String[] labels = name.split("\\.");
        int qnameLen = 1; // the terminating root label
        for (String l : labels) {
            qnameLen += 1 + l.length();
        }
        byte[] out = new byte[12 + qnameLen + 4];
        int i = 0;
        out[i++] = (byte) (transactionId >>> 8);
        out[i++] = (byte) transactionId;
        out[i++] = 0x01;                  // flags: QR=0, opcode=0, RD=1
        out[i++] = 0x00;
        out[i++] = 0x00; out[i++] = 0x01; // QDCOUNT = 1
        out[i++] = 0x00; out[i++] = 0x00; // ANCOUNT
        out[i++] = 0x00; out[i++] = 0x00; // NSCOUNT
        out[i++] = 0x00; out[i++] = 0x00; // ARCOUNT
        for (String l : labels) {
            byte[] b = l.getBytes(StandardCharsets.US_ASCII);
            out[i++] = (byte) b.length;
            System.arraycopy(b, 0, out, i, b.length);
            i += b.length;
        }
        out[i++] = 0x00;                  // root
        out[i++] = 0x00; out[i++] = 0x01; // QTYPE  A
        out[i++] = 0x00; out[i++] = 0x01; // QCLASS IN
        return out;
    }

    /** An NTPv4 client request: LI=0, VN=4, Mode=3 in the first byte, the rest zero (RFC 5905 §7.3). */
    public static byte[] ntpClientRequest() {
        byte[] out = new byte[48];
        out[0] = 0x23;
        return out;
    }
}
