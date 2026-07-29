package io.xlogistx.nosneak.v2.grade;

import io.xlogistx.nosneak.v2.result.ProbeResult;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVStringList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Derives an SSL-Labs-style letter grade and a PQC-readiness rating from a
 * {@link ProbeResult}'s facts. This is the post-record "rules" layer the engine was designed
 * to feed — it makes no network calls, only interprets recorded facts.
 * <p>
 * Grading (simplified): {@code T} for a chain-trust failure; {@code F} for a revoked cert or
 * SSLv3; {@code C}/{@code B} when deprecated TLS 1.0/1.1 are accepted; a weak-cipher
 * (static-RSA kx, anonymous kx, CBC, 3DES/DES, RC4, NULL/EXPORT) presence caps at {@code B};
 * otherwise {@code A}.
 * <p>
 * A letter is only awarded on evidence. {@code A} requires that the protocol-version
 * enumeration actually ran ({@code enumerate-versions}); a shallow probe that merely
 * negotiated TLSv1.3 grades {@code null}, because a single negotiation cannot show whether
 * the server still accepts TLSv1.0. A negotiated *deprecated* version does downgrade, since
 * that is positive evidence of a bad posture. Non-TLS services also grade {@code null}.
 */
public final class Grade {

    public enum Pqc { PQC_READY, PQC_CAPABLE, CLASSICAL_ONLY, UNKNOWN }

    /**
     * The single authoritative certificate-trust verdict, so a consumer reads one value instead
     * of re-deriving trust from {@code cert-validity}, {@code cert-chain-trust},
     * {@code cert-chain-time-valid} and {@code revocation-status} separately.
     */
    public enum TrustVerdict {
        TRUSTED,
        EXPIRED,
        NOT_YET_VALID,
        UNTRUSTED_CHAIN,
        CHAIN_TIME_INVALID,
        REVOKED,
        UNKNOWN
    }

    private final String letter;   // null = not a TLS service
    private final Pqc pqc;
    private final TrustVerdict verdict;
    private final String reason;
    private final List<String> advisories;

    private Grade(String letter, Pqc pqc, TrustVerdict verdict, String reason, List<String> advisories) {
        this.letter = letter;
        this.pqc = pqc;
        this.verdict = verdict;
        this.reason = reason;
        this.advisories = advisories == null ? Collections.emptyList() : advisories;
    }

    /** @return the letter grade (A/B/C/F/T), or {@code null} for a non-TLS service. */
    public String letter() {
        return letter;
    }

    public Pqc pqc() {
        return pqc;
    }

    /** The certificate-trust verdict; {@link TrustVerdict#UNKNOWN} when trust was not established. */
    public TrustVerdict verdict() {
        return verdict;
    }

    /** Human-readable explanation of {@link #verdict()}. */
    public String reason() {
        return reason;
    }

    /** Report-only findings (e.g. hostname mismatch) that do not change the verdict. */
    public List<String> advisories() {
        return advisories;
    }

    @Override
    public String toString() {
        return "grade=" + (letter != null ? letter : "N/A") + " pqc=" + pqc + " trust=" + verdict;
    }

    /** Render the derived verdict for an API response, alongside the recorded facts. */
    public NVGenericMap toNVGenericMap() {
        NVGenericMap nvgm = new NVGenericMap("Grade");
        if (letter != null) nvgm.add("grade", letter);
        nvgm.add("pqc-readiness", pqc.name());
        nvgm.add("trust-verdict", verdict.name());
        if (reason != null) nvgm.add("trust-reason", reason);
        if (!advisories.isEmpty()) nvgm.add(new NVStringList("advisories", advisories));
        return nvgm;
    }

    public static Grade of(ProbeResult r) {
        Pqc pqc = pqcReadiness(r);
        List<String> advisories = advisoriesOf(r);
        if (r.getTlsState() == ProbeResult.TlsState.NONE) {
            // Not a TLS service: no letter and no trust judgement to make.
            return new Grade(null, pqc, TrustVerdict.UNKNOWN, null, advisories);
        }

        Grade trust = trustOf(r, pqc, advisories);
        if (trust != null) {
            return trust; // a trust failure outranks protocol/cipher posture
        }

        List<String> versions = r.getSupportedProtocolVersions();
        boolean enumerated = versions != null && !versions.isEmpty();
        // Without the enumeration sweep the only protocol evidence is the version that was
        // actually negotiated. That can prove a bad posture (a server that negotiates TLSv1.0)
        // but never a good one — negotiating TLSv1.3 says nothing about whether TLSv1.0 is
        // still accepted — so a shallow probe gets no letter rather than an unearned A.
        List<String> evidence = enumerated
                ? versions
                : (r.getTlsVersion() != null
                        ? Collections.singletonList(r.getTlsVersion())
                        : Collections.<String>emptyList());
        String letter;
        if (contains(evidence, "SSLv3")) {
            letter = "F";
        } else if (contains(evidence, "TLSv1.0")) {
            letter = "C";
        } else if (contains(evidence, "TLSv1.1")) {
            letter = "B";
        } else {
            letter = enumerated ? "A" : null;
        }
        if (hasWeakCipher(r.getSupportedCipherSuites())) {
            letter = letter == null ? "B" : worseOf(letter, "B");
        }
        boolean anchored = "TRUSTED".equalsIgnoreCase(r.getCertChainTrust());
        return new Grade(letter, pqc,
                anchored ? TrustVerdict.TRUSTED : TrustVerdict.UNKNOWN,
                anchored
                        ? "Certificate chain anchors to a trusted Root CA [" + r.getCertChainTrust() + "]"
                        : "Certificate trust could not be established"
                          + (r.getCertChainTrust() != null ? " [" + r.getCertChainTrust() + "]" : ""),
                advisories);
    }

    /**
     * The trust failures that outrank everything else, in v1's precedence order: an expired or
     * not-yet-valid leaf, a chain that does not anchor to a trusted Root CA, an expired
     * intermediate/root, or a confirmed revocation. Hostname mismatch is deliberately absent —
     * it is report-only. Returns {@code null} when no failure applies.
     */
    private static Grade trustOf(ProbeResult r, Pqc pqc, List<String> advisories) {
        String validity = r.getCertValidity();
        if ("EXPIRED".equalsIgnoreCase(validity)) {
            return new Grade("T", pqc, TrustVerdict.EXPIRED,
                    "Certificate is EXPIRED (notAfter " + r.getCertNotAfter() + ") - renew immediately",
                    advisories);
        }
        if ("NOT_YET_VALID".equalsIgnoreCase(validity)) {
            return new Grade("T", pqc, TrustVerdict.NOT_YET_VALID,
                    "Certificate is NOT YET VALID (notBefore " + r.getCertNotBefore()
                            + ") - check server clock / issuance",
                    advisories);
        }
        String trust = r.getCertChainTrust();
        if (trust != null && !"TRUSTED".equalsIgnoreCase(trust) && !"UNKNOWN".equalsIgnoreCase(trust)) {
            return new Grade("T", pqc, TrustVerdict.UNTRUSTED_CHAIN,
                    "Certificate chain does not anchor to a trusted Root CA [" + trust + "]"
                            + (r.getCertChainTrustMessage() != null ? ": " + r.getCertChainTrustMessage() : ""),
                    advisories);
        }
        if (Boolean.FALSE.equals(r.getCertChainTimeValid())) {
            return new Grade("T", pqc, TrustVerdict.CHAIN_TIME_INVALID,
                    "An intermediate/root certificate in the chain is expired or not yet valid",
                    advisories);
        }
        if ("REVOKED".equalsIgnoreCase(r.getRevocationStatus())) {
            return new Grade("F", pqc, TrustVerdict.REVOKED, "Certificate is REVOKED", advisories);
        }
        return null;
    }

    /** Report-only findings: recorded and surfaced, but never a trust failure on their own. */
    private static List<String> advisoriesOf(ProbeResult r) {
        List<String> out = new ArrayList<>();
        if (Boolean.FALSE.equals(r.getCertHostnameValid())) {
            out.add("Certificate does not match the scanned hostname"
                    + (r.getCertHostnameMessage() != null ? ": " + r.getCertHostnameMessage() : ""));
        }
        if (Boolean.FALSE.equals(r.getCertPqcReady()) && r.getPqcStatus() == ProbeResult.PqcStatus.PQC) {
            out.add("Key exchange is PQC-hybrid but the certificate signature is classical "
                    + "- consider an ML-DSA certificate for full quantum resistance");
        }
        return out;
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

    /**
     * True when any accepted suite is weak. The key-exchange test is deliberately anchored:
     * {@code TLS_RSA_WITH_*} is static RSA (no forward secrecy), whereas
     * {@code TLS_ECDHE_RSA_WITH_*} is a healthy ephemeral suite that merely authenticates with
     * an RSA certificate. A substring test for {@code _RSA_WITH} flags both, which capped
     * every modern ECDHE server at B while the genuinely weak suites went unnoticed.
     */
    private static boolean hasWeakCipher(List<String> ciphers) {
        if (ciphers == null) return false;
        for (String c : ciphers) {
            if (c == null) continue;
            String u = c.toUpperCase();
            boolean staticRsaKx = u.startsWith("TLS_RSA_WITH") || u.startsWith("SSL_RSA_WITH");
            boolean anonymousKx = u.contains("_ANON_");
            if (staticRsaKx || anonymousKx || u.contains("CBC") || u.contains("3DES")
                    || u.contains("DES_") || u.contains("RC4") || u.contains("NULL")
                    || u.contains("EXPORT")) {
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
