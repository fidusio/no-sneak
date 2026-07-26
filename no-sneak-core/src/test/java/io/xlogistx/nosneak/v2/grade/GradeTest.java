package io.xlogistx.nosneak.v2.grade;

import io.xlogistx.nosneak.v2.result.ProbeResult;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.NVGenericMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure tests for the rules layer: the trust verdict derived from recorded certificate facts,
 * its precedence, the letter grade, and the report-only advisories. No network, no I/O — the
 * grading layer only interprets facts.
 */
public class GradeTest {

    /** A TLS result with everything healthy; individual tests spoil one fact at a time. */
    private static ProbeResult.Builder healthy() {
        return ProbeResult.builder("example.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.PQC)
                .tlsVersion("TLSv1.3")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .certChainTimeValid(true)
                .certHostname(true, null)
                .revocation("GOOD", "OCSP_STAPLED")
                .addProtocolVersion("TLSv1.3")
                .addProtocolVersion("TLSv1.2")
                .addCipherSuite("TLS_AES_256_GCM_SHA384")
                .complete(true);
    }

    @Test
    public void healthyTlsGradesA() {
        Grade g = Grade.of(healthy().build());
        assertEquals("A", g.letter());
        assertEquals(Grade.TrustVerdict.TRUSTED, g.verdict());
        assertEquals(Grade.Pqc.PQC_READY, g.pqc());
        assertTrue(g.advisories().isEmpty());
    }

    @Test
    public void nonTlsServiceHasNoLetter() {
        ProbeResult r = ProbeResult.builder("example.com", 22, "tcp")
                .service("ssh").complete(true).build();
        Grade g = Grade.of(r);
        assertNull(g.letter(), "a non-TLS service must not be graded");
        assertEquals(Grade.TrustVerdict.UNKNOWN, g.verdict());
    }

    // ==================== Trust verdicts ====================

    @Test
    public void expiredLeafGradesT() {
        Grade g = Grade.of(healthy().certValidity("EXPIRED").build());
        assertEquals("T", g.letter());
        assertEquals(Grade.TrustVerdict.EXPIRED, g.verdict());
        assertNotNull(g.reason());
    }

    @Test
    public void notYetValidLeafGradesT() {
        Grade g = Grade.of(healthy().certValidity("NOT_YET_VALID").build());
        assertEquals("T", g.letter());
        assertEquals(Grade.TrustVerdict.NOT_YET_VALID, g.verdict());
    }

    @Test
    public void untrustedChainGradesT() {
        Grade g = Grade.of(healthy().certChainTrust("UNTRUSTED_ROOT", "anchor not found").build());
        assertEquals("T", g.letter());
        assertEquals(Grade.TrustVerdict.UNTRUSTED_CHAIN, g.verdict());
        assertTrue(g.reason().contains("UNTRUSTED_ROOT"));
        assertTrue(g.reason().contains("anchor not found"), "the PKIX detail must reach the reason");
    }

    @Test
    public void expiredIntermediateGradesT() {
        Grade g = Grade.of(healthy().certChainTimeValid(false).build());
        assertEquals("T", g.letter());
        assertEquals(Grade.TrustVerdict.CHAIN_TIME_INVALID, g.verdict());
    }

    @Test
    public void revokedGradesF() {
        Grade g = Grade.of(healthy().revocation("REVOKED", "OCSP_STAPLED").build());
        assertEquals("F", g.letter());
        assertEquals(Grade.TrustVerdict.REVOKED, g.verdict());
    }

    /** An expired leaf outranks every other trust failure, matching the v1 precedence. */
    @Test
    public void expiryOutranksOtherTrustFailures() {
        Grade g = Grade.of(healthy()
                .certValidity("EXPIRED")
                .certChainTrust("UNTRUSTED_ROOT", "anchor not found")
                .certChainTimeValid(false)
                .revocation("REVOKED", "OCSP_STAPLED")
                .build());
        assertEquals(Grade.TrustVerdict.EXPIRED, g.verdict());
    }

    @Test
    public void trustFailureOutranksProtocolPosture() {
        // SSLv3 alone would be F; an untrusted chain must still report T.
        Grade g = Grade.of(healthy()
                .certChainTrust("SELF_SIGNED", "self signed")
                .addProtocolVersion("SSLv3")
                .build());
        assertEquals("T", g.letter());
    }

    /** A soft UNKNOWN chain result (no trust store) must not be reported as a trust failure. */
    @Test
    public void unknownChainTrustIsNotAFailure() {
        Grade g = Grade.of(healthy().certChainTrust("UNKNOWN", "trust store unavailable").build());
        assertEquals("A", g.letter());
        assertEquals(Grade.TrustVerdict.UNKNOWN, g.verdict());
    }

    /** Trust was never examined (shallow probe): not a failure, but not TRUSTED either. */
    @Test
    public void unexaminedChainIsUnknown() {
        ProbeResult r = ProbeResult.builder("example.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.PQC)
                .certValidity("VALID")
                .complete(true)
                .build();
        assertEquals(Grade.TrustVerdict.UNKNOWN, Grade.of(r).verdict());
    }

    // ==================== Report-only advisories ====================

    @Test
    public void hostnameMismatchIsReportOnly() {
        Grade g = Grade.of(healthy()
                .certHostname(false, "host wrong.example.com does not match [DNS:example.com]")
                .build());
        assertEquals("A", g.letter(), "a hostname mismatch must not change the letter");
        assertEquals(Grade.TrustVerdict.TRUSTED, g.verdict(),
                "a hostname mismatch must not change the trust verdict");
        assertEquals(1, g.advisories().size());
        assertTrue(g.advisories().get(0).toLowerCase().contains("hostname"));
    }

    @Test
    public void classicalCertificateUnderPqcKeyExchangeIsAdvised() {
        Grade g = Grade.of(healthy()
                .certKeyAnalysis("RSA", "SHA256withRSA", "RSA", 2048, false)
                .build());
        assertEquals("A", g.letter());
        assertEquals(1, g.advisories().size());
        assertTrue(g.advisories().get(0).contains("ML-DSA"));
    }

    // ==================== Protocol / cipher posture ====================

    @Test
    public void deprecatedProtocolsDowngradeTheLetter() {
        assertEquals("C", Grade.of(healthy().addProtocolVersion("TLSv1.0").build()).letter());
        assertEquals("B", Grade.of(healthy().addProtocolVersion("TLSv1.1").build()).letter());
        assertEquals("F", Grade.of(healthy().addProtocolVersion("SSLv3").build()).letter());
    }

    @Test
    public void tls10OutranksTls11InTheDowngrade() {
        Grade g = Grade.of(healthy()
                .addProtocolVersion("TLSv1.1")
                .addProtocolVersion("TLSv1.0")
                .build());
        assertEquals("C", g.letter(), "the worst accepted version decides");
    }

    @Test
    public void weakCipherCapsAtB() {
        Grade g = Grade.of(healthy().addCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA").build());
        assertEquals("B", g.letter());
    }

    @Test
    public void weakCipherCannotImproveAWorseLetter() {
        Grade g = Grade.of(healthy()
                .addProtocolVersion("TLSv1.0")
                .addCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA")
                .build());
        assertEquals("C", g.letter(), "a weak-cipher cap must never raise a worse grade");
    }

    // ==================== PQC readiness ====================

    @Test
    public void pqcReadinessMapsFromStatus() {
        assertEquals(Grade.Pqc.PQC_READY,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.PQC).build()).pqc());
        assertEquals(Grade.Pqc.PQC_CAPABLE,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.PQC_READY).build()).pqc());
        assertEquals(Grade.Pqc.CLASSICAL_ONLY,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.CLASSICAL).build()).pqc());
        assertEquals(Grade.Pqc.UNKNOWN,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.UNKNOWN).build()).pqc());
    }

    // ==================== Serialization ====================

    @Test
    public void rendersTheVerdictForAnApiResponse() {
        NVGenericMap m = Grade.of(healthy()
                .certHostname(false, "mismatch")
                .build()).toNVGenericMap();
        assertEquals("A", m.getValue("grade"));
        assertEquals("PQC_READY", m.getValue("pqc-readiness"));
        assertEquals("TRUSTED", m.getValue("trust-verdict"));
        assertNotNull(m.getValue("trust-reason"));
        assertNotNull(m.get("advisories"));
    }

    @Test
    public void nonTlsResultOmitsTheLetterButStillRenders() {
        NVGenericMap m = Grade.of(ProbeResult.builder("h", 22, "tcp").service("ssh").build())
                .toNVGenericMap();
        assertNull(m.get("grade"));
        assertEquals("UNKNOWN", m.getValue("trust-verdict"));
    }

    @Test
    public void advisoriesAreImmutableToCallers() {
        Grade g = Grade.of(healthy().build());
        assertFalse(g.advisories() == null);
        assertTrue(g.advisories().isEmpty());
    }
}
