package io.xlogistx.nosneak.nmap.util;

public class PacketDataConst {
    private PacketDataConst() {}
    // UDP probe payloads for common services
    public static final byte[] DNS_PROBE = new byte[]{
            0x00, 0x00,  // Transaction ID
            0x01, 0x00,  // Flags: standard query
            0x00, 0x01,  // Questions: 1
            0x00, 0x00,  // Answer RRs: 0
            0x00, 0x00,  // Authority RRs: 0
            0x00, 0x00,  // Additional RRs: 0
            0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',  // Query: version
            0x04, 'b', 'i', 'n', 'd',                  // .bind
            0x00,        // Root
            0x00, 0x10,  // Type: TXT
            0x00, 0x03   // Class: CH
    };

    public static final byte[] SNMP_PROBE = new byte[]{
            0x30, 0x26,              // Sequence
            0x02, 0x01, 0x00,        // Version: 1
            0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',  // Community: public
            (byte) 0xa0, 0x19,       // Get-Request PDU
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00,  // Request ID
            0x02, 0x01, 0x00,        // Error status
            0x02, 0x01, 0x00,        // Error index
            0x30, 0x0b,              // Varbind list
            0x30, 0x09,              // Varbind
            0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  // OID: 1.3.6.1.2.1
            0x05, 0x00               // Value: NULL
    };

}
