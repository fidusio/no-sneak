package io.xlogistx.nosneak.v2.nmap;

import java.util.HashMap;
import java.util.Map;

/**
 * Well-known port → service-name table (fallback when no probe identifies the service) plus
 * nmap-style top-ports lists for {@code --top-ports}.
 */
public final class WellKnownPorts {

    private static final Map<Integer, String> TCP = new HashMap<>();
    private static final Map<Integer, String> UDP = new HashMap<>();

    /** nmap's most-common TCP ports, frequency order (top 100). */
    public static final int[] TOP_100_TCP = {
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111,
            995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514,
            5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008,
            49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121,
            1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009,
            3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646,
            49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000
    };

    /** nmap's most-common UDP ports (top 20). */
    public static final int[] TOP_20_UDP = {
            53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434,
            1900, 4500, 49152
    };

    static {
        TCP.put(20, "ftp-data"); TCP.put(21, "ftp"); TCP.put(22, "ssh"); TCP.put(23, "telnet");
        TCP.put(25, "smtp"); TCP.put(53, "domain"); TCP.put(80, "http"); TCP.put(110, "pop3");
        TCP.put(111, "rpcbind"); TCP.put(135, "msrpc"); TCP.put(139, "netbios-ssn");
        TCP.put(143, "imap"); TCP.put(443, "https"); TCP.put(445, "microsoft-ds");
        TCP.put(465, "smtps"); TCP.put(587, "submission"); TCP.put(993, "imaps");
        TCP.put(995, "pop3s"); TCP.put(1433, "ms-sql-s"); TCP.put(1723, "pptp");
        TCP.put(3306, "mysql"); TCP.put(3389, "ms-wbt-server"); TCP.put(5432, "postgresql");
        TCP.put(5900, "vnc"); TCP.put(6379, "redis"); TCP.put(8080, "http-proxy");
        TCP.put(8443, "https-alt"); TCP.put(27017, "mongodb"); TCP.put(9200, "elasticsearch");
        TCP.put(11211, "memcache"); TCP.put(6443, "https");

        UDP.put(53, "domain"); UDP.put(67, "dhcps"); UDP.put(68, "dhcpc"); UDP.put(69, "tftp");
        UDP.put(123, "ntp"); UDP.put(137, "netbios-ns"); UDP.put(138, "netbios-dgm");
        UDP.put(161, "snmp"); UDP.put(162, "snmptrap"); UDP.put(500, "isakmp");
        UDP.put(514, "syslog"); UDP.put(1900, "upnp"); UDP.put(5353, "mdns");
    }

    private WellKnownPorts() {
    }

    /** Service name for {@code port}/{@code protocol}, or {@code "unknown"}. */
    public static String name(int port, String protocol) {
        Map<Integer, String> m = "udp".equalsIgnoreCase(protocol) ? UDP : TCP;
        return m.getOrDefault(port, "unknown");
    }

    /** First {@code n} top TCP ports. */
    public static int[] topTcp(int n) {
        return slice(TOP_100_TCP, n);
    }

    /** First {@code n} top UDP ports. */
    public static int[] topUdp(int n) {
        return slice(TOP_20_UDP, n);
    }

    private static int[] slice(int[] src, int n) {
        int len = Math.max(0, Math.min(n, src.length));
        int[] out = new int[len];
        System.arraycopy(src, 0, out, 0, len);
        return out;
    }
}
