package io.xlogistx.nosneak.grade;

import io.xlogistx.nosneak.result.ProbeResult;
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

    /**
     * The suites the enumerator really emits. An ECDHE suite that authenticates with an RSA
     * certificate is healthy — only static-RSA key exchange is weak — so a modern server must
     * not be capped at B by the mere presence of "RSA" in the suite name.
     */
    @Test
    public void ephemeralRsaAuthenticatedSuitesAreNotWeak() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
                .addCipherSuite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
                .build());
        assertEquals("A", g.letter(), "ECDHE_RSA is forward-secret and must not be graded weak");
    }

    @Test
    public void staticRsaKeyExchangeIsWeak() {
        Grade g = Grade.of(healthy().addCipherSuite("TLS_RSA_WITH_AES_256_GCM_SHA384").build());
        assertEquals("B", g.letter(), "static-RSA key exchange has no forward secrecy");
    }

    /** 3DES is weak (B); RC4, NULL and anonymous suites are insecure and cost a further step (C). */
    @Test
    public void observedTripleDesIsWeakAndRc4IsInsecure() {
        Grade weak = Grade.of(healthy().addCipherSuite("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA").build());
        assertEquals("B", weak.letter(), "3DES is a weak suite");

        Grade rc4 = Grade.of(healthy().addCipherSuite("TLS_RSA_WITH_RC4_128_SHA").build());
        assertEquals("C", rc4.letter(), "RC4 needs no downgrade to exploit");
        assertTrue(rc4.advisories().stream().anyMatch(a -> a.contains("insecure cipher suite")));

        Grade anon = Grade.of(healthy().addCipherSuite("TLS_DH_anon_WITH_AES_128_GCM_SHA256").build());
        assertEquals("C", anon.letter(), "anonymous key exchange is insecure");
        Grade nul = Grade.of(healthy().addCipherSuite("TLS_RSA_WITH_NULL_SHA256").build());
        assertEquals("C", nul.letter(), "NULL encryption is insecure");
    }

    /** The structured suite record does not change the letter; the flat name list drives the rule. */
    @Test
    public void structuredCipherDetailsDoNotAlterTheLetter() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "STRONG", "ECDHE", true)
                .build());
        assertEquals("A", g.letter());
    }

    // ==================== CBC: forward-secret vs static-RSA (P24) ====================

    /**
     * SSL Labs keeps A for ECDHE + AES-CBC: the defect is MAC-then-encrypt, not the key
     * exchange, so it is worth telling the operator but not worth a letter. Before this rule the
     * widened enumeration sweep dropped every ECDHE-CBC server from A to B.
     */
    @Test
    public void forwardSecretCbcIsAnAdvisoryNotACap() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .build());
        assertEquals("A", g.letter(), "forward-secret CBC must not cap the letter");
        assertEquals(1, g.advisories().size(), "expected one CBC advisory, got " + g.advisories());
        String adv = g.advisories().get(0);
        assertTrue(adv.startsWith("CBC suites accepted: "), adv);
        assertTrue(adv.contains("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"), adv);
        assertTrue(adv.contains("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"), adv);
        assertTrue(adv.contains("prefer AEAD"), adv);
    }

    /** Static-RSA CBC is capped at B exactly once — the missing forward secrecy is the defect. */
    @Test
    public void staticRsaCbcCapsAtBWithoutACbcAdvisory() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "WEAK", "RSA", false)
                .build());
        assertEquals("B", g.letter());
        assertFalse(g.advisories().stream().anyMatch(a -> a.startsWith("CBC suites accepted")),
                "a static-RSA CBC suite is already capped; it must not also be advised as CBC");
    }

    @Test
    public void insecureSuiteCapsAtC() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLSv1.0", "INSECURE", "RSA", false)
                .build());
        assertEquals("C", g.letter(), "an insecure suite outranks the weak and CBC tiers");
        assertTrue(g.advisories().stream().anyMatch(a -> a.contains("insecure cipher suite")));
    }

    @Test
    public void aeadOnlyServerKeepsItsLetter() {
        Grade g = Grade.of(healthy()
                .addCipherSuite("TLS_AES_128_GCM_SHA256", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "STRONG", "ECDHE", true)
                .build());
        assertEquals("A", g.letter());
        assertTrue(g.advisories().isEmpty(), "AEAD-only: nothing to advise, got " + g.advisories());
    }

    /** An older or hand-built result carries only names; forward secrecy is inferred from them. */
    @Test
    public void flatListFallbackStillClassifies() {
        Grade fsCbc = Grade.of(healthy().addCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384").build());
        assertEquals("A", fsCbc.letter(), "ECDHE in the name means forward secrecy");
        assertTrue(fsCbc.advisories().stream().anyMatch(a -> a.startsWith("CBC suites accepted")));

        Grade dheCbc = Grade.of(healthy().addCipherSuite("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256").build());
        assertEquals("A", dheCbc.letter(), "DHE in the name means forward secrecy");

        Grade staticEcdh = Grade.of(healthy().addCipherSuite("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256").build());
        assertEquals("B", staticEcdh.letter(), "static ECDH (no E) has no forward secrecy");

        Grade tls13 = Grade.of(healthy().addCipherSuite("TLS_AES_256_GCM_SHA384").build());
        assertEquals("A", tls13.letter(), "TLS 1.3 suites are always ephemeral");
    }

    /**
     * Mirrors the live xlogistx.io:443 result of 2026-09-11: TLS 1.3 only, three TLS 1.3 suites
     * plus seven ECDHE_ECDSA suites of which four are CBC, PQC hybrid, TRUSTED, eight groups.
     * SSL Labs grades this A; so do we, with one CBC advisory.
     */
    @Test
    public void liveXlogistxShapeGradesA() {
        ProbeResult r = ProbeResult.builder("xlogistx.io", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.PQC)
                .tlsVersion("TLSv1.3")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .certChainTimeValid(true)
                .certHostname(true, null)
                .revocation("GOOD", "crl")
                .addProtocolVersion("TLSv1.3")
                .addCipherSuite("TLS_AES_256_GCM_SHA384", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_AES_128_GCM_SHA256", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLSv1.2", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addSupportedGroup("X25519MLKEM768").addSupportedGroup("x25519").addSupportedGroup("x448")
                .addSupportedGroup("secp256r1").addSupportedGroup("secp384r1").addSupportedGroup("secp521r1")
                .addSupportedGroup("ffdhe2048").addSupportedGroup("ffdhe3072")
                .complete(true)
                .build();
        Grade g = Grade.of(r);
        assertEquals("A", g.letter());
        assertEquals(Grade.Pqc.PQC_READY, g.pqc());
        assertEquals(Grade.TrustVerdict.TRUSTED, g.verdict());
        assertEquals(1, g.advisories().size(), g.advisories().toString());
        assertTrue(g.advisories().get(0).startsWith("CBC suites accepted"));
    }

    /**
     * Mirrors the live google.com:443 result of 2026-09-11: TLS 1.0 through 1.3, static-RSA
     * suites and 3DES observed. TLS 1.0 alone is C; the weak suites cannot make it worse.
     */
    @Test
    public void liveGoogleShapeGradesC() {
        ProbeResult r = ProbeResult.builder("google.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.PQC)
                .tlsVersion("TLSv1.3")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .certChainTimeValid(true)
                .certHostname(true, null)
                .revocation("GOOD", "crl")
                .addProtocolVersion("TLSv1.3").addProtocolVersion("TLSv1.2")
                .addProtocolVersion("TLSv1.1").addProtocolVersion("TLSv1.0")
                .addCipherSuite("TLS_AES_256_GCM_SHA384", "TLSv1.3", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", "STRONG", "ECDHE", true)
                .addCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "ECDHE", true)
                .addCipherSuite("TLS_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", "WEAK", "RSA", false)
                .addCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "WEAK", "RSA", false)
                .addCipherSuite("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.2", "WEAK", "RSA", false)
                .addSupportedGroup("X25519MLKEM768").addSupportedGroup("x25519").addSupportedGroup("secp256r1")
                .complete(true)
                .build();
        Grade g = Grade.of(r);
        assertEquals("C", g.letter());
        assertEquals(Grade.TrustVerdict.TRUSTED, g.verdict());
        assertTrue(g.advisories().stream().anyMatch(a -> a.startsWith("CBC suites accepted")
                        && a.contains("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
                        && !a.contains("TLS_RSA_WITH_AES_128_CBC_SHA")),
                "only the forward-secret CBC suite is advised; static-RSA ones are capped instead: " + g.advisories());
    }

    // ==================== Named groups ====================

    @Test
    public void acceptingAHybridGroupRaisesNoAdvisory() {
        Grade g = Grade.of(healthy().addSupportedGroup("X25519MLKEM768").addSupportedGroup("x25519").build());
        assertEquals("A", g.letter());
        assertTrue(g.advisories().isEmpty(), "a PQC-capable server needs no group advisory");
    }

    @Test
    public void acceptingOnlyClassicalGroupsIsReportOnly() {
        Grade g = Grade.of(healthy()
                .pqcStatus(ProbeResult.PqcStatus.CLASSICAL)
                .addSupportedGroup("x25519").addSupportedGroup("secp256r1")
                .build());
        assertEquals("A", g.letter(), "named groups never move the letter");
        assertTrue(g.advisories().stream().anyMatch(a -> a.contains("no post-quantum key-exchange group")),
                "expected the group advisory, got " + g.advisories());
    }

    @Test
    public void noGroupEnumerationMeansNoGroupAdvisory() {
        Grade g = Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.CLASSICAL).build());
        assertFalse(g.advisories().stream().anyMatch(a -> a.contains("key-exchange group")),
                "without enumeration evidence there is nothing to advise on");
    }

    /**
     * A shallow probe records the negotiated version but never runs the enumeration sweep, so
     * there is no evidence that weak versions are disabled. It must not be handed an A.
     */
    @Test
    public void shallowProbeWithoutEnumerationGetsNoLetter() {
        ProbeResult r = ProbeResult.builder("example.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.PQC)
                .tlsVersion("TLSv1.3")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .complete(true)
                .build();
        assertNull(Grade.of(r).letter(), "an unenumerated scan has not earned a letter");
        assertEquals(Grade.TrustVerdict.TRUSTED, Grade.of(r).verdict());
    }

    /** A negotiated deprecated version is positive evidence of a bad posture, so it still grades. */
    @Test
    public void negotiatedDeprecatedVersionStillDowngradesWithoutEnumeration() {
        ProbeResult r = ProbeResult.builder("legacy.example.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .tlsVersion("TLSv1.0")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .complete(true)
                .build();
        assertEquals("C", Grade.of(r).letter());
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

    /**
     * v1's READY / PARTIAL / NOT_READY, restored: a hybrid group is ready; TLS 1.3 with a classical
     * group is one configuration change away (capable); TLS 1.2 or older has no PQC path at all.
     */
    @Test
    public void pqcReadinessMapsFromStatus() {
        assertEquals(Grade.Pqc.PQC_READY,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.PQC).build()).pqc());
        assertEquals(Grade.Pqc.PQC_CAPABLE,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.CLASSICAL).build()).pqc());
        assertEquals(Grade.Pqc.CLASSICAL_ONLY,
                Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.NOT_READY).build()).pqc());
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

    // ==================== Remediation text (v1's recommendations, restored) ====================

    private static boolean advised(Grade g, String fragment) {
        return g.advisories().stream().anyMatch(a -> a.contains(fragment));
    }

    @Test
    public void deprecatedVersionsCarryTheirRemediation() {
        Grade sslv3 = Grade.of(healthy().addProtocolVersion("SSLv3").build());
        assertTrue(advised(sslv3, "Disable SSLv3") && advised(sslv3, "POODLE"), sslv3.advisories().toString());

        Grade tls10 = Grade.of(healthy().addProtocolVersion("TLSv1.0").build());
        assertTrue(advised(tls10, "Disable TLS 1.0") && advised(tls10, "PCI DSS"), tls10.advisories().toString());
        assertFalse(advised(tls10, "Disable TLS 1.1"));

        Grade tls11 = Grade.of(healthy().addProtocolVersion("TLSv1.1").build());
        assertTrue(advised(tls11, "Disable TLS 1.1"), tls11.advisories().toString());
    }

    @Test
    public void missingTls13AdvisesTheUpgrade() {
        ProbeResult r = ProbeResult.builder("legacy.example.com", 443, "tcp")
                .service("https")
                .tlsState(ProbeResult.TlsState.DIRECT_TLS)
                .pqcStatus(ProbeResult.PqcStatus.NOT_READY)
                .tlsVersion("TLSv1.2")
                .certValidity("VALID")
                .certChainTrust("TRUSTED", "ok")
                .addProtocolVersion("TLSv1.2")
                .complete(true)
                .build();
        Grade g = Grade.of(r);
        assertTrue(advised(g, "Upgrade to TLS 1.3 for PQC support"), g.advisories().toString());
        assertEquals(Grade.Pqc.CLASSICAL_ONLY, g.pqc());
        assertFalse(advised(Grade.of(healthy().build()), "Upgrade to TLS 1.3"), "TLS 1.3 is already accepted");
    }

    @Test
    public void tls13WithClassicalKeyExchangeAdvisesEnablingAHybrid() {
        Grade g = Grade.of(healthy().pqcStatus(ProbeResult.PqcStatus.CLASSICAL).build());
        assertEquals(Grade.Pqc.PQC_CAPABLE, g.pqc());
        assertTrue(advised(g, "Enable PQC hybrid key exchange (X25519MLKEM768 or SecP256r1MLKEM768)"),
                g.advisories().toString());
        assertFalse(advised(Grade.of(healthy().build()), "Enable PQC hybrid"), "already hybrid: nothing to enable");
    }

    @Test
    public void classicalCertificateAdviceUsesTheV1Wording() {
        Grade g = Grade.of(healthy().certKeyAnalysis("RSA", "SHA256withRSA", "RSA", 2048, false).build());
        assertTrue(advised(g, "Consider migrating to PQC certificates (ML-DSA)"), g.advisories().toString());
        assertFalse(advised(Grade.of(healthy().certKeyAnalysis("RSA", "SHA256withRSA", "RSA", 2048, false)
                .pqcStatus(ProbeResult.PqcStatus.CLASSICAL).build()), "ML-DSA"),
                "only a PQC key exchange makes the certificate the remaining gap");
    }

    @Test
    public void trustFailuresCarryRenewalAdvice() {
        Grade expired = Grade.of(healthy().certValidity("EXPIRED").certNotAfter("2025-01-01T00:00:00Z").build());
        assertTrue(advised(expired, "EXPIRED") && advised(expired, "renew immediately")
                && advised(expired, "2025-01-01T00:00:00Z"), expired.advisories().toString());

        Grade notYet = Grade.of(healthy().certValidity("NOT_YET_VALID").build());
        assertTrue(advised(notYet, "NOT YET VALID") && advised(notYet, "server clock"), notYet.advisories().toString());

        Grade untrusted = Grade.of(healthy().certChainTrust("UNTRUSTED_ROOT", "anchor not found").build());
        assertTrue(advised(untrusted, "trusted Root CA") && advised(untrusted, "UNTRUSTED_ROOT")
                && advised(untrusted, "anchor not found"), untrusted.advisories().toString());

        Grade chain = Grade.of(healthy().certChainTimeValid(false).build());
        assertTrue(advised(chain, "intermediate/root certificate"), chain.advisories().toString());

        Grade revoked = Grade.of(healthy().revocation("REVOKED", "ocsp", null, "KEY_COMPROMISE").build());
        assertTrue(advised(revoked, "REVOKED (KEY_COMPROMISE)") && advised(revoked, "renew immediately"),
                revoked.advisories().toString());

        assertFalse(advised(Grade.of(healthy().certChainTrust("UNKNOWN", "no store").build()), "Root CA"),
                "a soft UNKNOWN chain result is not a finding");
    }

    @Test
    public void aNonTlsServiceGetsNoProtocolAdvice() {
        Grade g = Grade.of(ProbeResult.builder("h", 22, "tcp").service("ssh").complete(true).build());
        assertTrue(g.advisories().isEmpty(), g.advisories().toString());
    }
}
