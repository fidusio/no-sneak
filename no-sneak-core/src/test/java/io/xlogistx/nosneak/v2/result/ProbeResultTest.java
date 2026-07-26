package io.xlogistx.nosneak.v2.result;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.NVGenericMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    /** Render the way the CLI does (include-defaults), not via the default-omitting helper. */
    private static String json(NVGenericMap m) {
        try {
            return GSONUtil.toJSONGenericMap(m, true, true, false);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
