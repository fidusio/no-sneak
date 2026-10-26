package io.xlogistx.nosneak.app.ui.scan;

import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;
import org.zoxweb.shared.util.NVStringList;
import org.zoxweb.shared.util.SharedBase64;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A scan report as the result tables read it (2026-10-24, Phase 3 of the UI redesign): the
 * engine's JSON ({@code ScanReport.toNVGenericMap} rendered by {@code JSONFormatter}) parsed back
 * into plain records, with the derived facts the screen shows — open ports, TLS endpoints, and a
 * per-host <b>posture</b> (the worst letter among its TLS ports, with the PQC readiness the engine
 * recorded). Nothing here grades: the letter, the PQC status and the trust verdict are the
 * engine's own ({@code grade.Grade}), read from each port's {@code grade} / {@code pqc} fields.
 * Pure and Swing-free, so {@code ReportViewTest} pins it without a display.
 */
public final class ReportView {

    private ReportView() {
    }

    /** How a host's posture reads on screen. */
    public enum Tone {OK, NEUTRAL, WARN, DANGER}

    public record Posture(String letter, String pqc, String label, Tone tone) {
        /** True when the host has at least one TLS endpoint. */
        public boolean hasTls() {
            return letter != null;
        }
    }

    public record Port(int port, String protocol, String state, String reason, long rttMs,
                       String service, String version, String banner, String probeName,
                       String tls, String pqc, String gradeLetter, String trust, List<String> advisories,
                       String certValidity, String certChainTrust, String tlsVersion, String cipherSuite,
                       String kexGroup, String kexAlgorithm, String certSubject, String certIssuer,
                       String certNotAfter, String chainMessage, List<String> supportedProtocols,
                       List<String> supportedGroups) {

        public boolean isOpen() {
            return "open".equalsIgnoreCase(state);
        }

        public boolean hasTls() {
            return tls != null && !"NONE".equalsIgnoreCase(tls);
        }

        /** {@code 443/tcp}. */
        public String portLabel() {
            return port + "/" + (protocol != null ? protocol : "tcp");
        }

        /** The version and the probe that found it, for the detail column; empty when neither is known. */
        public String detail() {
            StringBuilder sb = new StringBuilder();
            if (version != null && !version.isBlank()) sb.append(version);
            if (probeName != null && !probeName.isBlank()) {
                if (!sb.isEmpty()) sb.append(" · ");
                sb.append(probeName);
            }
            return sb.toString();
        }

        /** {@code TLS 1.3 · X25519MLKEM768} or the TLS state when the probe recorded no version. */
        public String tlsSummary() {
            if (!hasTls()) return "";
            StringBuilder sb = new StringBuilder(tlsVersion != null ? tlsVersion.replace("TLSv", "TLS ") : tls);
            if (kexGroup != null && !kexGroup.isBlank()) sb.append(" · ").append(kexGroup);
            else if (kexAlgorithm != null && !kexAlgorithm.isBlank()) sb.append(" · ").append(kexAlgorithm);
            return sb.toString();
        }
    }

    /** {@code macVendor} is the engine's vendor name for the MAC (2026-10-25), null when the report has none. */
    public record Host(String host, String ip, String hostname, boolean up, String reason, String mac,
                       String macVendor, long latencyMs, List<Port> ports) {

        /** The address to show: the resolved IP, else the target as typed. */
        public String address() {
            return ip != null && !ip.isBlank() ? ip : host;
        }

        public List<Port> openPorts() {
            List<Port> out = new ArrayList<>();
            for (Port p : ports) if (p.isOpen()) out.add(p);
            return out;
        }

        public List<Port> tlsPorts() {
            List<Port> out = new ArrayList<>();
            for (Port p : ports) if (p.hasTls()) out.add(p);
            return out;
        }

        /** The TLS port that decides the host's posture: the worst graded one. */
        public Port worstTlsPort() {
            Port worst = null;
            for (Port p : tlsPorts()) {
                if (worst == null || letterRank(p.gradeLetter) > letterRank(worst.gradeLetter)) worst = p;
            }
            return worst;
        }

        /** The service names of the open ports, comma separated. */
        public String serviceList() {
            List<String> names = new ArrayList<>();
            for (Port p : openPorts()) {
                String s = p.service != null && !p.service.isBlank() ? p.service : Integer.toString(p.port);
                if (!names.contains(s)) names.add(s);
            }
            return String.join(", ", names);
        }

        public Posture posture() {
            return postureOf(this);
        }
    }

    public record Report(String command, String startTime, long durationMs, int targets, int up,
                         boolean cancelled, List<String> warnings, List<Host> hosts) {

        public List<Host> upHosts() {
            List<Host> out = new ArrayList<>();
            for (Host h : hosts) if (h.up) out.add(h);
            return out;
        }

        public int openPortCount() {
            int n = 0;
            for (Host h : hosts) n += h.openPorts().size();
            return n;
        }

        public int tlsEndpointCount() {
            int n = 0;
            for (Host h : hosts) n += h.tlsPorts().size();
            return n;
        }

        /** TLS endpoints that negotiated a hybrid post-quantum key exchange. */
        public int pqcReadyCount() {
            int n = 0;
            for (Host h : hosts) for (Port p : h.tlsPorts()) if (isPqcReady(p)) n++;
            return n;
        }

        /** {@code 6.2 s}. */
        public String durationLabel() {
            return String.format(java.util.Locale.US, "%.1f s", durationMs / 1000.0);
        }
    }

    // ---- parsing ----

    /**
     * Parses the engine's JSON.
     *
     * @throws IllegalArgumentException when the text is not a report
     */
    public static Report parse(String json) {
        NVGenericMap m;
        try {
            m = GSONUtil.fromJSONGenericMap(json, null, SharedBase64.Base64Type.DEFAULT);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not a scan report: " + e.getMessage(), e);
        }
        if (m == null) throw new IllegalArgumentException("not a scan report");
        List<Host> hosts = new ArrayList<>();
        for (NVGenericMap h : maps(m, "hosts")) hosts.add(host(h));
        return new Report(str(m, "command"), str(m, "startTime"), lng(m, "durationMs"),
                (int) lng(m, "targets"), (int) lng(m, "up"), bool(m, "cancelled"),
                strings(m, "warnings"), Collections.unmodifiableList(hosts));
    }

    private static Host host(NVGenericMap h) {
        List<Port> ports = new ArrayList<>();
        for (NVGenericMap p : maps(h, "ports")) ports.add(port(p));
        return new Host(str(h, "host"), str(h, "ip"), str(h, "hostname"), bool(h, "up"), str(h, "reason"),
                str(h, "mac"), str(h, "macVendor"), lngOr(h, "latencyMs", -1), Collections.unmodifiableList(ports));
    }

    private static final Pattern GRADE = Pattern.compile("grade=(\\S+)\\s+pqc=(\\S+)\\s+trust=(\\S+)(?:\\s+advisories=\\[(.*)\\])?");

    private static Port port(NVGenericMap p) {
        NVGenericMap probe = map(p, "probe");
        String letter = null, trust = null;
        List<String> advisories = List.of();
        String grade = str(p, "grade");
        if (grade != null) {
            Matcher mm = GRADE.matcher(grade.trim());
            if (mm.matches()) {
                letter = "N/A".equals(mm.group(1)) ? null : mm.group(1);
                trust = mm.group(3);
                if (mm.group(4) != null && !mm.group(4).isBlank()) {
                    advisories = List.of(mm.group(4).split(",\\s*"));
                }
            }
        }
        return new Port((int) lng(p, "port"), str(p, "protocol"), str(p, "state"), str(p, "reason"),
                lngOr(p, "rttMs", -1), str(p, "service"), str(p, "version"), str(p, "banner"),
                probe != null ? str(probe, "probe") : null,
                str(p, "tls"), str(p, "pqc"), letter, trust, advisories,
                str(p, "certValidity"), str(p, "certChainTrust"),
                probe != null ? str(probe, "tls-version") : null,
                probe != null ? str(probe, "cipher-suite") : null,
                probe != null ? str(probe, "key-exchange-group") : null,
                probe != null ? str(probe, "key-exchange-algorithm") : null,
                probe != null ? str(probe, "cert-subject") : null,
                probe != null ? str(probe, "cert-issuer") : null,
                probe != null ? str(probe, "cert-not-after") : null,
                probe != null ? str(probe, "cert-chain-trust-message") : null,
                probe != null ? strings(probe, "supported-protocol-versions") : List.of(),
                probe != null ? strings(probe, "supported-groups") : List.of());
    }

    // ---- posture ----

    /** Letters rank A best; an unknown letter ranks worst so it is never hidden behind a good one. */
    static int letterRank(String letter) {
        if (letter == null || letter.isEmpty()) return 9;
        return switch (Character.toUpperCase(letter.charAt(0))) {
            case 'A' -> 0;
            case 'B' -> 1;
            case 'C' -> 2;
            case 'D' -> 3;
            case 'E' -> 4;
            case 'F' -> 5;
            default -> 8;
        };
    }

    static boolean isPqcReady(Port p) {
        return p.pqc != null && p.pqc.toUpperCase().startsWith("PQC");
    }

    static Posture postureOf(Host h) {
        Port worst = h.worstTlsPort();
        if (worst == null) return new Posture(null, null, "No TLS", Tone.NEUTRAL);
        boolean anyPqc = false;
        for (Port p : h.tlsPorts()) if (isPqcReady(p)) anyPqc = true;
        String letter = worst.gradeLetter != null ? worst.gradeLetter : "?";
        String pqcWord = anyPqc ? "Hybrid PQC"
                : worst.pqc == null ? ""
                : switch (worst.pqc.toUpperCase()) {
            case "CLASSICAL" -> "Classical";
            case "NOT_READY" -> "Not ready";
            default -> "";
        };
        Tone tone = switch (letterRank(letter)) {
            case 0 -> Tone.OK;
            case 1 -> Tone.NEUTRAL;
            case 2 -> Tone.WARN;
            default -> Tone.DANGER;
        };
        String label = pqcWord.isEmpty() ? letter : letter + " · " + pqcWord;
        return new Posture(letter, anyPqc ? "PQC" : worst.pqc, label, tone);
    }

    // ---- NVGenericMap helpers ----

    private static String str(NVGenericMap m, String key) {
        Object v = value(m, key);
        if (v == null) return null;
        String s = v.toString();
        return s.isEmpty() ? null : s;
    }

    private static long lng(NVGenericMap m, String key) {
        return lngOr(m, key, 0);
    }

    private static long lngOr(NVGenericMap m, String key, long dflt) {
        Object v = value(m, key);
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s) {
            try {
                return Long.parseLong(s.trim());
            } catch (NumberFormatException ignore) {
                return dflt;
            }
        }
        return dflt;
    }

    private static boolean bool(NVGenericMap m, String key) {
        Object v = value(m, key);
        if (v instanceof Boolean b) return b;
        return v != null && Boolean.parseBoolean(v.toString());
    }

    private static Object value(NVGenericMap m, String key) {
        GetNameValue<?> gnv = m.get(key);
        return gnv != null ? gnv.getValue() : null;
    }

    private static NVGenericMap map(NVGenericMap m, String key) {
        GetNameValue<?> gnv = m.get(key);
        return gnv instanceof NVGenericMap sub ? sub : null;
    }

    @SuppressWarnings("unchecked")
    private static List<NVGenericMap> maps(NVGenericMap m, String key) {
        GetNameValue<?> gnv = m.get(key);
        if (gnv instanceof NVGenericMapList l && l.getValue() != null) return l.getValue();
        if (gnv != null && gnv.getValue() instanceof List<?> raw) {
            List<NVGenericMap> out = new ArrayList<>();
            for (Object o : raw) if (o instanceof NVGenericMap sub) out.add(sub);
            return out;
        }
        return List.of();
    }

    private static List<String> strings(NVGenericMap m, String key) {
        GetNameValue<?> gnv = m.get(key);
        if (gnv instanceof NVStringList l && l.getValue() != null) return List.copyOf(l.getValue());
        if (gnv != null && gnv.getValue() instanceof List<?> raw) {
            List<String> out = new ArrayList<>();
            for (Object o : raw) if (o != null) out.add(o.toString());
            return out;
        }
        return List.of();
    }
}
