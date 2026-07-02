package io.xlogistx.nosneak.nmap.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles target specification parsing similar to nmap.
 * Supports:
 * - Single host: 192.168.1.1 or example.com
 * - CIDR notation: 192.168.1.0/24
 * - IP ranges: 192.168.1.1-254
 * - Octet ranges: 192.168.1-5.1-254
 * - Multiple targets (space or comma separated)
 */
public class TargetSpecification {

    private static final Pattern CIDR_PATTERN = Pattern.compile(
        "^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/(\\d{1,2})$"
    );

    private static final Pattern IP_RANGE_PATTERN = Pattern.compile(
        "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})-(\\d{1,3})$"
    );

    private static final Pattern OCTET_RANGE_PATTERN = Pattern.compile(
        "^(\\d{1,3}(?:-\\d{1,3})?)\\.(" +
        "\\d{1,3}(?:-\\d{1,3})?)\\.(" +
        "\\d{1,3}(?:-\\d{1,3})?)\\.(" +
        "\\d{1,3}(?:-\\d{1,3})?)$"
    );

    private final List<String> targets;
    private final List<String> originalSpecs;

    private TargetSpecification(List<String> targets, List<String> originalSpecs) {
        this.targets = Collections.unmodifiableList(new ArrayList<>(targets));
        this.originalSpecs = Collections.unmodifiableList(new ArrayList<>(originalSpecs));
    }

    /**
     * Get all resolved target IP addresses/hostnames
     */
    public List<String> getTargets() {
        return targets;
    }

    /**
     * Get the original specification strings
     */
    public List<String> getOriginalSpecs() {
        return originalSpecs;
    }

    public int getTargetCount() {
        return targets.size();
    }

    public boolean isEmpty() {
        return targets.isEmpty();
    }

    /**
     * Parse target specification string(s)
     */
    public static TargetSpecification parse(String... specs) {
        List<String> allTargets = new ArrayList<>();
        List<String> originals = new ArrayList<>();

        for (String spec : specs) {
            if (spec == null || spec.trim().isEmpty()) continue;

            // Split by comma or whitespace
            String[] parts = spec.split("[,\\s]+");
            for (String part : parts) {
                part = part.trim();
                if (part.isEmpty()) continue;

                originals.add(part);
                allTargets.addAll(expandTarget(part));
            }
        }

        return new TargetSpecification(allTargets, originals);
    }

    /**
     * Create from a single host
     */
    public static TargetSpecification single(String host) {
        return new TargetSpecification(
            Collections.singletonList(host),
            Collections.singletonList(host)
        );
    }

    /**
     * Create from a list of hosts
     */
    public static TargetSpecification fromList(List<String> hosts) {
        return new TargetSpecification(hosts, hosts);
    }

    private static List<String> expandTarget(String target) {
        List<String> result = new ArrayList<>();

        // Try CIDR notation
        Matcher cidrMatcher = CIDR_PATTERN.matcher(target);
        if (cidrMatcher.matches()) {
            result.addAll(expandCidr(cidrMatcher.group(1), Integer.parseInt(cidrMatcher.group(2))));
            return result;
        }

        // Try IP range (192.168.1.1-254)
        Matcher rangeMatcher = IP_RANGE_PATTERN.matcher(target);
        if (rangeMatcher.matches()) {
            String base = rangeMatcher.group(1) + "." + rangeMatcher.group(2) + "." + rangeMatcher.group(3) + ".";
            int start = Integer.parseInt(rangeMatcher.group(4));
            int end = Integer.parseInt(rangeMatcher.group(5));
            for (int i = start; i <= end && i <= 255; i++) {
                result.add(base + i);
            }
            return result;
        }

        // Try octet range pattern
        Matcher octetMatcher = OCTET_RANGE_PATTERN.matcher(target);
        if (octetMatcher.matches()) {
            result.addAll(expandOctetRanges(
                octetMatcher.group(1),
                octetMatcher.group(2),
                octetMatcher.group(3),
                octetMatcher.group(4)
            ));
            return result;
        }

        // Plain hostname or IP
        result.add(target);
        return result;
    }

    private static List<String> expandCidr(String baseIp, int prefixLength) {
        List<String> result = new ArrayList<>();

        try {
            byte[] baseBytes = InetAddress.getByName(baseIp).getAddress();
            int baseInt = bytesToInt(baseBytes);

            // Calculate network mask
            int mask = prefixLength == 0 ? 0 : (-1 << (32 - prefixLength));
            int network = baseInt & mask;
            int broadcast = network | ~mask;

            // Generate all IPs in range (skip network and broadcast for /24 and smaller)
            int start = (prefixLength >= 24) ? network + 1 : network;
            int end = (prefixLength >= 24) ? broadcast - 1 : broadcast;

            // Limit to reasonable size
            int count = end - start + 1;
            if (count > 65536) {
                // For large ranges, just return the CIDR notation
                result.add(baseIp + "/" + prefixLength);
                return result;
            }

            for (int ip = start; ip <= end; ip++) {
                result.add(intToIp(ip));
            }
        } catch (UnknownHostException e) {
            result.add(baseIp);
        }

        return result;
    }

    private static List<String> expandOctetRanges(String o1, String o2, String o3, String o4) {
        List<String> result = new ArrayList<>();

        int[] range1 = parseOctetRange(o1);
        int[] range2 = parseOctetRange(o2);
        int[] range3 = parseOctetRange(o3);
        int[] range4 = parseOctetRange(o4);

        // Limit expansion to prevent memory issues
        long total = (long)(range1[1] - range1[0] + 1) *
                     (range2[1] - range2[0] + 1) *
                     (range3[1] - range3[0] + 1) *
                     (range4[1] - range4[0] + 1);

        if (total > 65536) {
            // Too large, return pattern as-is
            result.add(o1 + "." + o2 + "." + o3 + "." + o4);
            return result;
        }

        for (int a = range1[0]; a <= range1[1]; a++) {
            for (int b = range2[0]; b <= range2[1]; b++) {
                for (int c = range3[0]; c <= range3[1]; c++) {
                    for (int d = range4[0]; d <= range4[1]; d++) {
                        result.add(a + "." + b + "." + c + "." + d);
                    }
                }
            }
        }

        return result;
    }

    private static int[] parseOctetRange(String octet) {
        if (octet.contains("-")) {
            String[] parts = octet.split("-");
            int start = Integer.parseInt(parts[0]);
            int end = Integer.parseInt(parts[1]);
            return new int[]{Math.max(0, start), Math.min(255, end)};
        } else {
            int val = Integer.parseInt(octet);
            return new int[]{val, val};
        }
    }

    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }

    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }

    /**
     * Resolve hostname to IP address
     */
    public static String resolveHost(String host) throws UnknownHostException {
        InetAddress addr = InetAddress.getByName(host);
        return addr.getHostAddress();
    }

    /**
     * Check if string is a valid IP address
     */
    public static boolean isIpAddress(String host) {
        return host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    }

    @Override
    public String toString() {
        if (originalSpecs.size() == 1) {
            return originalSpecs.get(0) + " (" + targets.size() + " hosts)";
        }
        return originalSpecs.size() + " specs -> " + targets.size() + " hosts";
    }
}
