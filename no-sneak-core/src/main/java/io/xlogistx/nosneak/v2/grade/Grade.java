package io.xlogistx.nosneak.v2.grade;

import io.xlogistx.nosneak.v2.result.ProbeResult;

import java.util.List;

/**
 * Derives an SSL-Labs-style letter grade and a PQC-readiness rating from a
 * {@link ProbeResult}'s facts. This is the post-record "rules" layer the engine was designed
 * to feed — it makes no network calls, only interprets recorded facts.
 * <p>
 * Grading (simplified): {@code T} for a chain-trust failure; {@code F} for a revoked cert or
 * SSLv3; {@code C}/{@code B} when deprecated TLS 1.0/1.1 are accepted; a weak-cipher (RSA-kx,
 * CBC, 3DES, RC4, NULL/EXPORT) presence caps at {@code B}; otherwise {@code A}. Non-TLS
 * services grade {@code null} (not applicable).
 */
public final class Grade {

    public enum Pqc { PQC_READY, PQC_CAPABLE, CLASSICAL_ONLY, UNKNOWN }

    private final String letter;   // null = not a TLS service
    private final Pqc pqc;

    private Grade(String letter, Pqc pqc) {
        this.letter = letter;
        this.pqc = pqc;
    }

    /** @return the letter grade (A/B/C/F/T), or {@code null} for a non-TLS service. */
    public String letter() {
        return letter;
    }

    public Pqc pqc() {
        return pqc;
    }

    @Override
    public String toString() {
        return "grade=" + (letter != null ? letter : "N/A") + " pqc=" + pqc;
    }

    public static Grade of(ProbeResult r) {
        Pqc pqc = pqcReadiness(r);
        if (r.getTlsState() == ProbeResult.TlsState.NONE) {
            return new Grade(null, pqc); // not a TLS service
        }
        // Trust and revocation dominate.
        if ("REVOKED".equalsIgnoreCase(r.getRevocationStatus())) {
            return new Grade("F", pqc);
        }
        String trust = r.getCertChainTrust();
        if (trust != null && !"TRUSTED".equalsIgnoreCase(trust) && !"UNKNOWN".equalsIgnoreCase(trust)) {
            return new Grade("T", pqc); // trust anchor / chain problem
        }

        List<String> versions = r.getSupportedProtocolVersions();
        String letter;
        if (contains(versions, "SSLv3")) {
            letter = "F";
        } else if (contains(versions, "TLSv1.0")) {
            letter = "C";
        } else if (contains(versions, "TLSv1.1")) {
            letter = "B";
        } else {
            letter = "A";
        }
        if (hasWeakCipher(r.getSupportedCipherSuites())) {
            letter = worseOf(letter, "B");
        }
        return new Grade(letter, pqc);
    }

    private static Pqc pqcReadiness(ProbeResult r) {
        if (r.getPqcStatus() == null) return Pqc.UNKNOWN;
        switch (r.getPqcStatus()) {
            case PQC: return Pqc.PQC_READY;
            case PQC_READY: return Pqc.PQC_CAPABLE;
            case CLASSICAL: return Pqc.CLASSICAL_ONLY;
            default: return Pqc.UNKNOWN;
        }
    }

    private static boolean contains(List<String> list, String v) {
        return list != null && list.contains(v);
    }

    private static boolean hasWeakCipher(List<String> ciphers) {
        if (ciphers == null) return false;
        for (String c : ciphers) {
            String u = c.toUpperCase();
            if (u.contains("_RSA_WITH") || u.contains("CBC") || u.contains("3DES")
                    || u.contains("RC4") || u.contains("NULL") || u.contains("EXPORT")) {
                return true;
            }
        }
        return false;
    }

    // Return the worse (later in A..F) of two letter grades (ignoring T which is handled earlier).
    private static String worseOf(String a, String b) {
        return rank(a) >= rank(b) ? a : b;
    }

    private static int rank(String g) {
        switch (g) {
            case "A": return 0;
            case "B": return 1;
            case "C": return 2;
            case "D": return 3;
            case "E": return 4;
            case "F": return 5;
            default: return 0;
        }
    }
}
