package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.analysis.RevocationChecker;
import io.xlogistx.nosneak.v2.grade.Grade;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.http.HTTPURLCallback;
import org.zoxweb.shared.net.IPAddress;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.connected;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The post-handshake analysis actions driven through {@link ProbeContext} on a scripted
 * handshake ({@link ScriptedTls}): {@code pqc-check}'s four-way readiness and key-exchange
 * facts, {@code cert-chain-validate} on an in-memory chain, and every branch of
 * {@code revocation-check} — a usable staple, a malformed staple that must fall through to the
 * active check, the active check's OCSP and CRL answers, a leaf with nothing to check, and the
 * responder timeout fired by hand on the {@link ManualScheduler}. Plus the explicit
 * {@code success} / {@code error-message} surface of the delivered result.
 */
public class TlsAnalysisContextTest {

    private static final IPAddress TARGET = new IPAddress("127.0.0.1", 443);
    private static final int TIMEOUT = 3;
    private static final String OCSP_URL = "http://127.0.0.1:1/ocsp";
    private static final String CRL_URL = "http://127.0.0.1:1/ca.crl";
    private static final Date REVOKED_AT = new Date(1_700_000_000_000L);

    /** connect → tls-handshake → pqc-check → cert-chain-validate → revocation-check → done. */
    private static final String DEEP = "{\"name\":\"deep\",\"service\":\"tls\",\"ports\":[443],\"start\":\"connect\",\"states\":{"
            + "\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"tls\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
            + "\"tls\":{\"action\":\"tls-handshake\",\"mode\":\"pqc\",\"on\":{\"handshaked\":\"pqc\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
            + "\"pqc\":{\"action\":\"pqc-check\",\"on\":{\"done\":\"certchain\"}},"
            + "\"certchain\":{\"action\":\"cert-chain-validate\",\"on\":{\"done\":\"revocation\"}},"
            + "\"revocation\":{\"action\":\"revocation-check\",\"revocationTimeoutMs\":2000,\"on\":{\"done\":\"done\"}},"
            + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}";

    private static ScriptedTls.Ca ca;
    private static X509Certificate leaf;      // names an OCSP responder and a CRL
    private static X509Certificate bareLeaf;  // names neither

    @BeforeAll
    public static void fixtures() throws Exception {
        ca = ScriptedTls.ca("Scripted Test CA");
        leaf = ScriptedTls.leaf(ca, "leaf.example", OCSP_URL, CRL_URL);
        bareLeaf = ScriptedTls.leaf(ca, "bare.example", null, null);
    }

    private ScriptedTransport tx;
    private ManualScheduler clock;

    @BeforeEach
    public void fresh() {
        tx = new ScriptedTransport();
        clock = new ManualScheduler();
    }

    /** A scripted active check: records what it was asked and answers at once (or holds the callback). */
    static final class FakeActive implements ProbeContext.ActiveRevocation {
        final RevocationResult answer;
        int calls;
        X509Certificate leaf;
        X509Certificate issuer;
        long budget;
        Consumer<RevocationResult> pending;

        FakeActive(RevocationResult answer) {
            this.answer = answer;
        }

        @Override
        public void check(X509Certificate leaf, X509Certificate issuer, long timeoutMs,
                          Consumer<RevocationResult> onResult) {
            calls++;
            this.leaf = leaf;
            this.issuer = issuer;
            this.budget = timeoutMs;
            if (answer != null) {
                onResult.accept(answer);
            } else {
                pending = onResult;
            }
        }
    }

    /** An HTTP client that records what it was asked to send instead of connecting anywhere. */
    static final class CapturingHttp extends HTTPNIOSocket {
        final List<HTTPURLCallback> sent = new ArrayList<>();

        CapturingHttp() {
            super(null);
        }

        @Override
        public void asyncSend(HTTPURLCallback huc) {
            sent.add(huc);
        }
    }

    private static ScriptedTls.FakeTlsClient pqcClient(X509Certificate l) throws Exception {
        ScriptedTls.FakeTlsClient client = new ScriptedTls.FakeTlsClient();
        client.chain = ScriptedTls.bcChain(l, ca.cert);
        return client;
    }

    /** Runs the definition up to and including the scripted handshake; the actions after it run inline. */
    private ProbeContext handshake(ScriptedTls.FakeTlsClient client, ProbeContext.ActiveRevocation seam,
                                   HTTPNIOSocket http) {
        tx.scriptedTls = ScriptedTls.session(client);
        ProbeDefinition def = ProbeDefinitionLoader.parse(DEEP, "deep");
        ProbeContext ctx = http == null
                ? tx.newContext(clock, TARGET, def, TIMEOUT)
                : tx.newContext(clock, http, TARGET, def, TIMEOUT);
        if (seam != null) {
            ctx.activeRevocation(seam);
        }
        ctx.start();
        connected(tx.last());
        assertEquals("tls", ctx.currentStateId());
        assertEquals(1, tx.tlsStarts.size(), "the handshake state starts exactly one handshake");
        ScriptedTransport.handshaked(tx.tlsStarts.get(0), tx.scriptedTls);
        return ctx;
    }

    private ProbeResult delivered() {
        assertEquals(1, tx.delivered.size(), "exactly one result");
        return tx.delivered.get(0);
    }

    // ==================== revocation-check ====================

    @Test
    public void aUsableStapleAnswersWithoutTheActiveCheck() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(leaf);
        client.staple = ScriptedTls.ocsp(ca, leaf, CertificateStatus.GOOD);
        FakeActive active = new FakeActive(RevocationResult.good(RevocationChecker.METHOD_OCSP));

        handshake(client, active, null);

        ProbeResult r = delivered();
        assertEquals("GOOD", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_STAPLED, r.getRevocationMethod());
        assertEquals(0, active.calls, "a good staple is final: no network path");
        assertTrue(r.isSuccess());
        assertNull(r.getErrorMessage());
    }

    /** The v1 rule the rewrite had lost: a staple that does not parse is not an answer. */
    @Test
    public void aMalformedStapleFallsThroughToTheActiveCheck() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(leaf);
        client.staple = new byte[]{1, 2, 3, 4};
        FakeActive active = new FakeActive(RevocationResult.good(RevocationChecker.METHOD_OCSP));

        handshake(client, active, null);

        assertEquals(1, active.calls, "the malformed staple must not end the check as ERROR/stapled");
        assertEquals(leaf.getSerialNumber(), active.leaf.getSerialNumber(), "the presented leaf goes to the responder");
        assertEquals(ca.cert.getSubjectX500Principal(), active.issuer.getSubjectX500Principal(),
                "the presented issuer is what verifies the answer");
        assertEquals(2000L, active.budget, "the state's revocationTimeoutMs bounds the attempt");
        ProbeResult r = delivered();
        assertEquals("GOOD", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_OCSP, r.getRevocationMethod());
        assertNotEquals("ERROR", r.getRevocationStatus());
    }

    @Test
    public void aCrlAnswerFromTheActiveCheckKeepsDateAndReasonAndGradesRevoked() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(leaf);
        byte[] crl = ScriptedTls.crl(ca, leaf, REVOKED_AT);
        FakeActive active = new FakeActive(RevocationChecker.fromCRL(crl, leaf, ca.cert));

        handshake(client, active, null);

        ProbeResult r = delivered();
        assertEquals("REVOKED", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getRevocationMethod());
        assertEquals("KEY_COMPROMISE", r.getRevocationReason());
        assertTrue(r.getRevocationDate().startsWith("2023-11-14"), r.getRevocationDate());
        Grade g = Grade.of(r);
        // The throwaway CA is not in the JDK trust store, and an untrusted chain outranks a
        // revocation in v1's precedence — so T, not F; the revocation still reaches the advice.
        assertEquals("T", g.letter());
        assertEquals(Grade.TrustVerdict.UNTRUSTED_CHAIN, g.verdict());
        assertTrue(g.advisories().stream().anyMatch(a -> a.contains("REVOKED (KEY_COMPROMISE)") && a.contains("renew")),
                "the renewal advice: " + g.advisories());
    }

    @Test
    public void anActiveCheckThatHoldsTheCallbackHoldsTheProbeUntilItAnswers() throws Exception {
        FakeActive active = new FakeActive(null);
        ProbeContext ctx = handshake(pqcClient(leaf), active, null);

        assertEquals("revocation", ctx.currentStateId());
        assertTrue(tx.delivered.isEmpty(), "waiting for the responder");
        active.pending.accept(RevocationResult.unknown(RevocationChecker.METHOD_OCSP, "responder said unknown"));

        ProbeResult r = delivered();
        assertEquals("UNKNOWN", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_OCSP, r.getRevocationMethod());
        assertTrue(r.isSuccess(), "an unknown revocation status is a fact, not a failure");
    }

    @Test
    public void aLeafWithNoResponderAndNoCrlIsNotSupportedOnTheProductionPath() throws Exception {
        handshake(pqcClient(bareLeaf), null, null); // no seam, no HTTP client: the real checker decides

        ProbeResult r = delivered();
        assertEquals("NOT_SUPPORTED", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_NONE, r.getRevocationMethod());
        assertTrue(r.isSuccess());
    }

    @Test
    public void aSilentResponderTimesOutOnTheSchedulerAndTheProbeGoesOn() throws Exception {
        CapturingHttp http = new CapturingHttp();
        ProbeContext ctx = handshake(pqcClient(leaf), null, http); // the real NetworkRevocationChecker

        assertEquals("revocation", ctx.currentStateId());
        assertEquals(1, http.sent.size(), "one OCSP request went out on the probe's HTTP client");
        ManualScheduler.Task budget = clock.latestLive();
        assertNotNull(budget);
        assertEquals(2000L, budget.delayMs, "the state's revocationTimeoutMs is the responder budget");
        assertTrue(tx.delivered.isEmpty());

        budget.run(); // nobody ever answered

        ProbeResult r = delivered();
        assertEquals("UNKNOWN", r.getRevocationStatus());
        assertEquals(RevocationChecker.METHOD_OCSP + "-unreachable", r.getRevocationMethod());
        assertTrue(r.isSuccess(), "soft-fail: the probe still completes");
        assertEquals(0, clock.liveCount());
    }

    @Test
    public void theHttpClientIsBuiltOnlyWhenRevocationRunsAndOnlyOnce() throws Exception {
        ProbeDefinition def = ProbeDefinitionLoader.parse(DEEP, "deep");
        ProbeContext ctx = tx.newContext(clock, TARGET, def, TIMEOUT);
        assertNull(ctx.httpNio(), "the test seam has no socket to build one on");
        CapturingHttp http = new CapturingHttp();
        ProbeContext withHttp = tx.newContext(clock, http, TARGET, def, TIMEOUT);
        assertSame(http, withHttp.httpNio());
        assertSame(http, withHttp.httpNio(), "the supplied client is reused, never rebuilt");
    }

    // ==================== pqc-check + cert-chain-validate ====================

    @Test
    public void aHybridHandshakeIsPqcWithTheGroupAndAlgorithmRecorded() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(leaf);
        client.staple = ScriptedTls.ocsp(ca, leaf, CertificateStatus.GOOD);

        handshake(client, null, null);

        ProbeResult r = delivered();
        assertEquals(ProbeResult.TlsState.DIRECT_TLS, r.getTlsState());
        assertEquals(ProbeResult.PqcStatus.PQC, r.getPqcStatus());
        assertEquals("TLSv1.3", r.getTlsVersion());
        assertEquals("TLS_AES_256_GCM_SHA384", r.getCipherSuite());
        assertEquals("X25519MLKEM768", r.getKeyExchangeGroup());
        assertEquals("ML-KEM hybrid", r.toNVGenericMap().getValue("key-exchange-algorithm"));
        assertEquals(Grade.Pqc.PQC_READY, Grade.of(r).pqc());

        // cert facts from pqc-check
        Object subject = r.toNVGenericMap().getValue("cert-subject");
        assertTrue(subject instanceof String && ((String) subject).contains("leaf.example"), String.valueOf(subject));
        assertEquals("VALID", r.getCertValidity());
        assertEquals(Boolean.FALSE, r.getCertPqcReady(), "an RSA leaf is a classical signature");
        assertTrue(Grade.of(r).advisories().stream().anyMatch(a -> a.contains("ML-DSA")),
                "PQC key exchange under a classical certificate is advised: " + Grade.of(r).advisories());

        // chain breakdown from cert-chain-validate: leaf + the self-signed test CA as root
        assertEquals(2, r.getCertChain().size());
        assertEquals("leaf", r.getCertChain().get(0).role);
        assertEquals("root", r.getCertChain().get(1).role);
        assertTrue(r.getCertChain().get(1).selfSigned);
        assertEquals(Boolean.TRUE, r.getCertChainTimeValid());
        assertNotNull(r.getCertChainTrust());
        assertNotEquals("TRUSTED", r.getCertChainTrust(), "a throwaway CA anchors to nothing the JDK trusts");
        assertEquals(Grade.TrustVerdict.UNTRUSTED_CHAIN, Grade.of(r).verdict());
    }

    @Test
    public void tls13WithAClassicalGroupIsClassicalAndUpgradeable() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(bareLeaf);
        client.group = NamedGroup.x25519;

        handshake(client, null, null);

        ProbeResult r = delivered();
        assertEquals(ProbeResult.PqcStatus.CLASSICAL, r.getPqcStatus());
        assertEquals("x25519", r.getKeyExchangeGroup());
        assertEquals("ECDHE", r.toNVGenericMap().getValue("key-exchange-algorithm"));
        Grade g = Grade.of(r);
        assertEquals(Grade.Pqc.PQC_CAPABLE, g.pqc());
        assertTrue(g.advisories().stream().anyMatch(a -> a.startsWith("Enable PQC hybrid key exchange")),
                g.advisories().toString());
        assertFalse(g.advisories().stream().anyMatch(a -> a.startsWith("Upgrade to TLS 1.3")),
                "TLS 1.3 is already there");
    }

    @Test
    public void tls12IsNotReadyWhateverTheSuite() throws Exception {
        ScriptedTls.FakeTlsClient client = pqcClient(bareLeaf);
        client.version = ProtocolVersion.TLSv12;
        client.cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        client.group = 0; // no key_share on TLS 1.2

        handshake(client, null, null);

        ProbeResult r = delivered();
        assertEquals(ProbeResult.PqcStatus.NOT_READY, r.getPqcStatus());
        assertEquals("TLSv1.2", r.getTlsVersion());
        assertEquals("ECDHE", r.getKeyExchangeGroup(), "no group on TLS 1.2: the suite's family stands in");
        assertEquals("ECDHE", r.toNVGenericMap().getValue("key-exchange-algorithm"));
        Grade g = Grade.of(r);
        assertEquals(Grade.Pqc.CLASSICAL_ONLY, g.pqc());
        assertTrue(g.advisories().stream().anyMatch(a -> a.equals("Upgrade to TLS 1.3 for PQC support")),
                g.advisories().toString());
    }

    @Test
    public void classifyPqcPinsTheFourWayRule() {
        assertEquals(ProbeResult.PqcStatus.PQC, ProbeContext.classifyPqc(ProtocolVersion.TLSv13, "PQC_HYBRID"));
        assertEquals(ProbeResult.PqcStatus.CLASSICAL, ProbeContext.classifyPqc(ProtocolVersion.TLSv13, "ECDHE"));
        assertEquals(ProbeResult.PqcStatus.CLASSICAL, ProbeContext.classifyPqc(ProtocolVersion.TLSv13, "DHE"));
        assertEquals(ProbeResult.PqcStatus.NOT_READY, ProbeContext.classifyPqc(ProtocolVersion.TLSv12, "ECDHE"));
        assertEquals(ProbeResult.PqcStatus.NOT_READY, ProbeContext.classifyPqc(ProtocolVersion.TLSv10, "RSA"));
        assertEquals(ProbeResult.PqcStatus.UNKNOWN, ProbeContext.classifyPqc(null, "ECDHE"));
        assertEquals(ProbeResult.PqcStatus.UNKNOWN, ProbeContext.classifyPqc(ProtocolVersion.TLSv13, "UNKNOWN"));
        assertEquals(ProbeResult.PqcStatus.UNKNOWN, ProbeContext.classifyPqc(ProtocolVersion.TLSv13, null));
        assertEquals("ML-KEM hybrid", ProbeContext.keyExchangeAlgorithmName("PQC_HYBRID"));
        assertEquals("RSA", ProbeContext.keyExchangeAlgorithmName("RSA"));
        assertNull(ProbeContext.keyExchangeAlgorithmName("UNKNOWN"));
    }

    // ==================== the error surface ====================

    @Test
    public void aHandshakeThatNeverCompletesFailsWithSuccessFalseAndTheReason() {
        tx.scriptedTls = ScriptedTls.session(new ScriptedTls.FakeTlsClient());
        ProbeContext ctx = tx.newContext(clock, TARGET, ProbeDefinitionLoader.parse(DEEP, "deep"), TIMEOUT);
        ctx.start();
        connected(tx.last());
        assertEquals("tls", ctx.currentStateId());

        clock.fireLatest(); // the handshake window elapses

        ProbeResult r = delivered();
        assertFalse(r.isComplete());
        assertFalse(r.isSuccess());
        assertEquals("fail", r.getErrorMessage());
        assertEquals(ProbeResult.PqcStatus.UNKNOWN, r.getPqcStatus());
        assertEquals(ProbeResult.TlsState.NONE, r.getTlsState());
        assertEquals("false", r.toNVGenericMap().getValue("success"));
        assertEquals("fail", r.toNVGenericMap().getValue("error-message"));
    }
}
