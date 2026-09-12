package io.xlogistx.nosneak.v2.nmap;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/** The UDP probe datagrams, parsed back against their wire formats. */
public class UdpProbePayloadsTest {

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    @Test
    public void dnsQueryIsAStandardRecursiveAQueryForTheFixedName() {
        byte[] q = UdpProbePayloads.forPort(53);
        assertEquals(UdpProbePayloads.DNS_TRANSACTION_ID, u16(q, 0), "transaction id");
        assertEquals(0x0100, u16(q, 2), "flags: standard query, RD set");
        assertEquals(1, u16(q, 4), "QDCOUNT");
        assertEquals(0, u16(q, 6), "ANCOUNT");
        assertEquals(0, u16(q, 8), "NSCOUNT");
        assertEquals(0, u16(q, 10), "ARCOUNT");

        // QNAME: labels of the fixed name, then the root
        int i = 12;
        StringBuilder name = new StringBuilder();
        while (q[i] != 0) {
            int len = q[i++] & 0xFF;
            if (name.length() > 0) name.append('.');
            name.append(new String(q, i, len, StandardCharsets.US_ASCII));
            i += len;
        }
        i++; // root label
        assertEquals(UdpProbePayloads.DNS_QUERY_NAME, name.toString());
        assertEquals(1, u16(q, i), "QTYPE A");
        assertEquals(1, u16(q, i + 2), "QCLASS IN");
        assertEquals(i + 4, q.length, "nothing after the question");
    }

    @Test
    public void ntpRequestIsAVersion4ClientPacket() {
        byte[] p = UdpProbePayloads.forPort(123);
        assertEquals(48, p.length);
        assertEquals(0x23, p[0] & 0xFF, "LI=0, VN=4, Mode=3");
        for (int i = 1; i < p.length; i++) {
            assertEquals(0, p[i], "byte " + i + " is zero");
        }
    }

    @Test
    public void everyOtherPortGetsAnEmptyDatagramIncludingSnmp() {
        assertEquals(0, UdpProbePayloads.forPort(161).length, "no community string is ever sent");
        assertEquals(0, UdpProbePayloads.forPort(162).length);
        assertEquals(0, UdpProbePayloads.forPort(5353).length);
        assertSame(UdpProbePayloads.forPort(1).getClass(), byte[].class);
    }
}
