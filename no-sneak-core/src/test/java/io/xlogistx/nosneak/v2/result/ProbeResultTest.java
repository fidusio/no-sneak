package io.xlogistx.nosneak.v2.result;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.NVGenericMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract tests for the facts-only result and its serialization.
 * <p>
 * The important cases here are the <b>negative</b> facts. The framework's JSON serializer omits
 * default values, so a {@code false} boolean silently disappears and becomes indistinguishable
 * from "not checked" — which is why the tri-state certificate facts are emitted as explicit
 * strings. These tests lock that in: a regression back to {@code NVBoolean} would hide an
 * expired intermediate or a hostname mismatch from every JSON consumer.
 */
public class ProbeResultTest {

    @Test
    public void defaultsAreFactsOnlyAndSafe() {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp").build();
        assertEquals(ProbeResult.TlsState.NONE, r.getTlsState());
        assertEquals(ProbeResult.PqcStatus.UNKNOWN, r.getPqcStatus());
        assertTrue(!r.isComplete());
        assertNotNull(r.getServiceFacts(), "service facts must never be null");
        assertNull(r.getServiceVersion());
        assertNotNull(r.getSupportedCipherSuites());
        assertNotNull(r.getSupportedProtocolVersions());
    }

    @Test
    public void revocationDateAndReasonAreSerialized() throws Exception {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .revocation("REVOKED", "ocsp", "2023-11-14T22:13:20Z", "KEY_COMPROMISE").build();
        assertEquals("2023-11-14T22:13:20Z", r.getRevocationDate());
        assertEquals("KEY_COMPROMISE", r.getRevocationReason());
        String json = GSONUtil.toJSONGenericMap(r.toNVGenericMap(), true, true, false);
        assertTrue(json.contains("\"revocation-method\": \"ocsp\"") || json.contains("\"revocation-method\":\"ocsp\""), json);
        assertTrue(json.contains("revocation-date"), json);
        assertTrue(json.contains("KEY_COMPROMISE"), json);
        // The two-argument form still works and leaves the extras absent.
        ProbeResult plain = ProbeResult.builder("h", 443, "tcp").revocation("GOOD", "stapled").build();
        assertNull(plain.getRevocationDate());
        assertNull(plain.getRevocationReason());
    }

    @Test
    public void cipherDetailsKeepTheFlatListInStepAndSerializeForwardSecrecyAsAString() throws Exception {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .addCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", "ACCEPTABLE", "RSA", false)
                .addCipherSuite("TLS_AES_256_GCM_SHA384", "TLSv1.3", "STRONG", "ECDHE/DHE", true)
                .addCipherSuite("TLS_AES_256_GCM_SHA384", "TLSv1.3", "STRONG", "ECDHE/DHE", true) // dedupe
                .serverCipherPreference("TLS_AES_256_GCM_SHA384", "server")
                .build();
        assertEquals(2, r.getSupportedCipherSuites().size());
        assertEquals(2, r.getSupportedCipherSuiteDetails().size());
        assertEquals("TLS_AES_256_GCM_SHA384", r.getServerCipherPreference());
        assertEquals("server", r.getServerCipherPreferenceMode());
        NVGenericMap m = r.toNVGenericMap();
        String json = GSONUtil.toJSONGenericMap(m, true, true, false);
        // A false forward-secrecy must be visible: it is the whole point of recording static RSA.
        assertTrue(json.contains("\"forward-secrecy\": \"NO\"") || json.contains("\"forward-secrecy\":\"NO\""), json);
        assertTrue(json.contains("server-cipher-preference"), json);
    }

    @Test
    public void supportedGroupsAndPreferenceAreSerialized() throws Exception {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .addSupportedGroup("X25519MLKEM768").addSupportedGroup("x25519").addSupportedGroup("x25519")
                .serverGroupPreference("X25519MLKEM768")
                .build();
        assertEquals(2, r.getSupportedGroups().size());
        assertEquals("X25519MLKEM768", r.getServerGroupPreference());
        String json = GSONUtil.toJSONGenericMap(r.toNVGenericMap(), true, true, false);
        assertTrue(json.contains("supported-groups"), json);
        assertTrue(json.contains("server-group-preference"), json);
        assertNotNull(ProbeResult.builder("h", 1, "tcp").build().getSupportedGroups(), "never null");
    }

    @Test
    public void notesAreMergedNotOverwritten() {
        ProbeResult r = ProbeResult.builder("h", 1, "tcp")
                .note("first").note("second").note(null).note("").build();
        assertEquals("first; second", r.getNote());
    }

    @Test
    public void factsDedupeAndIgnoreBlanks() {
        ProbeResult r = ProbeResult.builder("h", 1, "tcp")
                .fact("version", "1.0")
                .fact("version", "2.0")   // later capture wins
                .fact("blank", "")        // ignored
                .fact(null, "x")          // ignored
                .build();
        assertEquals("2.0", r.getServiceVersion());
        assertEquals(1, r.getServiceFacts().size());
    }

    @Test
    public void listFactsDedupeAndKeepOrder() {
        ProbeResult r = ProbeResult.builder("h", 1, "tcp")
                .addProtocolVersion("TLSv1.3")
                .addProtocolVersion("TLSv1.2")
                .addProtocolVersion("TLSv1.3")
                .addCipherSuite("A").addCipherSuite("A")
                .build();
        assertEquals(2, r.getSupportedProtocolVersions().size());
        assertEquals("TLSv1.3", r.getSupportedProtocolVersions().get(0));
        assertEquals(1, r.getSupportedCipherSuites().size());
    }

    // ==================== Negative facts must survive serialization ====================

    @Test
    public void expiredIntermediateIsVisibleInJson() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp")
                .certChainTimeValid(false).build().toNVGenericMap();
        assertEquals("INVALID", m.getValue("cert-chain-time-validity"));
        assertTrue(json(m).contains("INVALID"),
                "an expired intermediate must be visible in the rendered JSON");
    }

    @Test
    public void hostnameMismatchIsVisibleInJson() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp")
                .certHostname(false, "does not match").build().toNVGenericMap();
        assertEquals("MISMATCH", m.getValue("cert-hostname-match"));
        assertEquals("does not match", m.getValue("cert-hostname-message"));
        assertTrue(json(m).contains("MISMATCH"));
    }

    @Test
    public void classicalCertificateSignatureIsVisibleInJson() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp")
                .certKeyAnalysis("RSA", "SHA256withRSA", "RSA", 2048, false)
                .build().toNVGenericMap();
        assertEquals("CLASSICAL", m.getValue("cert-signature-pqc"));
        assertTrue(json(m).contains("CLASSICAL"));
    }

    /** Absence still has to mean "not checked" — the whole point of the tri-state. */
    @Test
    public void uncheckedCertFactsAreAbsent() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp").build().toNVGenericMap();
        assertNull(m.get("cert-chain-time-validity"));
        assertNull(m.get("cert-hostname-match"));
        assertNull(m.get("cert-signature-pqc"));
        assertNull(m.get("cert-chain-trust"));
    }

    @Test
    public void positiveCertFactsSerialize() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp")
                .certChainTimeValid(true)
                .certHostname(true, null)
                .certKeyAnalysis("PQC_SIGNATURE", "ML-DSA-65", "ML-DSA", 1952, true)
                .certChainTrust("TRUSTED", "ok")
                .build().toNVGenericMap();
        assertEquals("VALID", m.getValue("cert-chain-time-validity"));
        assertEquals("MATCH", m.getValue("cert-hostname-match"));
        assertEquals("PQC", m.getValue("cert-signature-pqc"));
        assertEquals("TRUSTED", m.getValue("cert-chain-trust"));
        assertEquals("ok", m.getValue("cert-chain-trust-message"));
        assertEquals("ML-DSA", m.getValue("cert-public-key-type"));
    }

    // ==================== Certificate chain breakdown ====================

    @Test
    public void certChainRendersEveryLinkWithItsRole() {
        NVGenericMap m = ProbeResult.builder("h", 443, "tcp")
                .addCert(new ProbeResult.CertInfo(0, "CN=leaf", "CN=ca", "nb", "na",
                        true, "VALID", false, false, "leaf"))
                .addCert(new ProbeResult.CertInfo(1, "CN=ca", "CN=root", "nb", "na",
                        false, "EXPIRED", false, true, "intermediate"))
                .addCert(new ProbeResult.CertInfo(2, "CN=root", "CN=root", "nb", "na",
                        true, "VALID", true, true, "root"))
                .build().toNVGenericMap();
        assertNotNull(m.get("cert-chain"));
        String rendered = json(m);
        assertTrue(rendered.contains("\"role\": \"leaf\"") || rendered.contains("\"role\":\"leaf\""));
        assertTrue(rendered.contains("root"));
        // The failing link must name WHY it failed, not just that the aggregate is bad.
        assertTrue(rendered.contains("EXPIRED"),
                "the expired link must carry its validity-state so the failing cert is identifiable");
    }

    @Test
    public void clearCertChainReplacesAPreviousRun() {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .addCert(new ProbeResult.CertInfo(0, "old", "old", null, null, true, "VALID", false, false, "leaf"))
                .clearCertChain()
                .addCert(new ProbeResult.CertInfo(0, "new", "new", null, null, true, "VALID", false, false, "leaf"))
                .build();
        assertEquals(1, r.getCertChain().size());
        assertEquals("new", r.getCertChain().get(0).subject);
    }

    @Test
    public void connectionTraceIsRecorded() {
        ProbeResult r = ProbeResult.builder("h", 25, "tcp")
                .addConnection(1, 25, "reconnect")
                .addConnection(2, 25, "done")
                .build();
        assertEquals(2, r.getConnections().size());
        assertEquals("done", r.getConnections().get(1).outcome);
        // index 0 / false values would be dropped by toJSONDefault - the include-defaults
        // renderer must keep them.
        assertTrue(json(r.toNVGenericMap()).contains("\"index\""));
    }

    // ==================== The explicit error surface ====================

    @Test
    public void successAndErrorMessageSurviveTheDefaultSerializer() throws Exception {
        ProbeResult failed = ProbeResult.builder("h", 443, "tcp")
                .complete(false).errorMessage("fail: expect: boom").build();
        assertFalse(failed.isSuccess());
        assertEquals("fail: expect: boom", failed.getErrorMessage());
        NVGenericMap m = failed.toNVGenericMap();
        assertEquals("false", m.getValue("success"), "a string, so a false never vanishes");
        assertEquals("fail: expect: boom", m.getValue("error-message"));
        // A string pair, not an NVBoolean: the framework's default renderer drops a false boolean.
        assertTrue(m.get("success") instanceof org.zoxweb.shared.util.NVPair, String.valueOf(m.get("success")));
        String rendered = json(m);
        assertTrue(rendered.contains("\"success\": \"false\"") || rendered.contains("\"success\":\"false\""), rendered);
        assertTrue(rendered.contains("error-message"), rendered);

        ProbeResult ok = ProbeResult.builder("h", 443, "tcp").complete(true).build();
        assertTrue(ok.isSuccess());
        assertNull(ok.getErrorMessage());
        assertEquals("true", ok.toNVGenericMap().getValue("success"));
        assertNull(ok.toNVGenericMap().get("error-message"));

        ProbeResult completeButErrored = ProbeResult.builder("h", 443, "tcp")
                .complete(true).errorMessage("x").build();
        assertFalse(completeButErrored.isSuccess(), "success is complete AND no error");
    }

    // ==================== Cipher components and ranking ====================

    @Test
    public void cipherComponentsAreRecordedAndSerialized() {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .addCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "STRONG",
                        "ECDHE", "RSA", "AES-256-GCM", "SHA384", true)
                .addCipherSuite("TLS_AES_128_GCM_SHA256", "TLSv1.3", "STRONG", "ECDHE/DHE", true) // old form
                .build();
        ProbeResult.CipherSuiteInfo full = r.getSupportedCipherSuiteDetails().get(0);
        assertEquals("RSA", full.authentication);
        assertEquals("AES-256-GCM", full.encryption);
        assertEquals("SHA384", full.mac);
        ProbeResult.CipherSuiteInfo plain = r.getSupportedCipherSuiteDetails().get(1);
        assertNull(plain.authentication, "the five-argument form leaves the components absent");
        String rendered = json(r.toNVGenericMap());
        assertTrue(rendered.contains("\"authentication\": \"RSA\"") || rendered.contains("\"authentication\":\"RSA\""), rendered);
        assertTrue(rendered.contains("AES-256-GCM"), rendered);
        assertTrue(rendered.contains("\"mac\": \"SHA384\"") || rendered.contains("\"mac\":\"SHA384\""), rendered);
    }

    @Test
    public void serverCipherRankingKeepsOrderDedupesAndSerializes() {
        ProbeResult r = ProbeResult.builder("h", 443, "tcp")
                .addServerCipherRank("B").addServerCipherRank("A").addServerCipherRank("B").addServerCipherRank("")
                .build();
        assertEquals(java.util.List.of("B", "A"), r.getServerCipherRanking());
        assertTrue(json(r.toNVGenericMap()).contains("server-cipher-ranking"));
        ProbeResult none = ProbeResult.builder("h", 443, "tcp").build();
        assertNotNull(none.getServerCipherRanking());
        assertTrue(none.getServerCipherRanking().isEmpty());
        assertNull(none.toNVGenericMap().get("server-cipher-ranking"), "absent when nothing was ranked");
    }

    @Test
    public void theRetiredPqcReadyValueIsGone() {
        for (ProbeResult.PqcStatus s : ProbeResult.PqcStatus.values()) {
            assertTrue(s == ProbeResult.PqcStatus.PQC || s == ProbeResult.PqcStatus.CLASSICAL
                    || s == ProbeResult.PqcStatus.NOT_READY || s == ProbeResult.PqcStatus.UNKNOWN, s.name());
        }
        assertEquals(4, ProbeResult.PqcStatus.values().length);
    }

    /** Render the way the CLI does (include-defaults), not via the default-omitting helper. */
    private static String json(NVGenericMap m) {
        try {
            return GSONUtil.toJSONGenericMap(m, true, true, false);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
