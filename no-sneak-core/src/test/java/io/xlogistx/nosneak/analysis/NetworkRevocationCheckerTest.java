package io.xlogistx.nosneak.analysis;

import io.xlogistx.nosneak.runtime.ManualScheduler;
import io.xlogistx.nosneak.runtime.ScriptedTls;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.http.HTTPURLCallback;
import org.zoxweb.shared.http.HTTPResponseData;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The active OCSP-then-CRL check with the HTTP client replaced by a recorder and the scheduler
 * by hand: every request the checker would send is captured and answered by the test, so the
 * OCSP answer, the fall-through to the CRL, the responder timeout, the exactly-once guarantee and
 * the no-issuer short-circuit are pinned without a responder on the network.
 */
public class NetworkRevocationCheckerTest {

    private static final String OCSP_URL = "http://127.0.0.1:1/ocsp";
    private static final String CRL_URL = "http://127.0.0.1:1/ca.crl";
    private static final Date REVOKED_AT = new Date(1_700_000_000_000L);

    private static ScriptedTls.Ca ca;
    private static X509Certificate both;      // OCSP + CRL
    private static X509Certificate crlOnly;
    private static X509Certificate neither;

    @BeforeAll
    public static void fixtures() throws Exception {
        ca = ScriptedTls.ca("Responder Test CA");
        both = ScriptedTls.leaf(ca, "both.example", OCSP_URL, CRL_URL);
        crlOnly = ScriptedTls.leaf(ca, "crl.example", null, CRL_URL);
        neither = ScriptedTls.leaf(ca, "neither.example", null, null);
    }

    /** Records every request instead of connecting; the test answers through the request's callback. */
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

    private CapturingHttp http;
    private ManualScheduler clock;
    private final List<RevocationResult> results = new ArrayList<>();

    @BeforeEach
    public void fresh() {
        http = new CapturingHttp();
        clock = new ManualScheduler();
        results.clear();
    }

    private void check(X509Certificate leaf, X509Certificate issuer) {
        new NetworkRevocationChecker(http, clock).check(leaf, issuer, 5_000, results::add);
    }

    private static void answer(HTTPURLCallback request, int status, byte[] body) {
        request.getCallback().accept(new HTTPResponseData(status, new HashMap<>(), body, 1L));
    }

    private RevocationResult only() {
        assertEquals(1, results.size(), "the callback runs exactly once: " + results);
        return results.get(0);
    }

    @Test
    public void aGoodOcspAnswerIsGoodViaOcspAndCancelsTheBudget() throws Exception {
        check(both, ca.cert);
        assertEquals(1, http.sent.size(), "one OCSP request");
        assertTrue(results.isEmpty(), "nothing until the responder answers");
        assertEquals(1, clock.liveCount(), "the budget timer is armed");

        answer(http.sent.get(0), 200, ScriptedTls.ocsp(ca, both, CertificateStatus.GOOD));

        RevocationResult r = only();
        assertEquals(RevocationStatus.GOOD, r.getStatus());
        assertEquals(RevocationChecker.METHOD_OCSP, r.getMethod());
        assertEquals(0, clock.liveCount(), "an answer cancels the budget timer");
        assertEquals(1, http.sent.size(), "no CRL fetch after a definitive OCSP answer");
    }

    @Test
    public void anIndefiniteOcspAnswerFallsThroughToTheCrl() throws Exception {
        check(both, ca.cert);
        answer(http.sent.get(0), 200, ScriptedTls.ocsp(ca, both, new UnknownStatus()));
        assertTrue(results.isEmpty(), "the responder did not decide: the CRL is tried next");
        assertEquals(2, http.sent.size(), "the CRL request follows");

        answer(http.sent.get(1), 200, ScriptedTls.crl(ca, both, REVOKED_AT));

        RevocationResult r = only();
        assertEquals(RevocationStatus.REVOKED, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
        assertEquals("KEY_COMPROMISE", r.getRevocationReason());
        assertNotNull(r.getRevocationDate());
    }

    @Test
    public void anHttpFailureOnOcspFallsThroughToTheCrl() throws Exception {
        check(both, ca.cert);
        answer(http.sent.get(0), 503, null);
        assertEquals(2, http.sent.size());

        answer(http.sent.get(1), 200, ScriptedTls.crl(ca, null, null));

        RevocationResult r = only();
        assertEquals(RevocationStatus.GOOD, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
    }

    @Test
    public void aSilentResponderTimesOutOnTheSchedulerAndALateAnswerIsIgnored() throws Exception {
        check(both, ca.cert);
        assertEquals(1, http.sent.size());

        clock.fireLatest(); // the budget elapses with no answer

        RevocationResult r = only();
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertEquals(RevocationChecker.METHOD_OCSP + "-unreachable", r.getMethod());
        assertTrue(r.getErrorMessage().contains("No answer"), r.getErrorMessage());

        answer(http.sent.get(0), 200, ScriptedTls.ocsp(ca, both, CertificateStatus.GOOD)); // too late
        assertEquals(1, results.size(), "the late answer must not resolve the attempt a second time");
    }

    @Test
    public void aCrlOnlyLeafIsFetchedAndVerifiedAgainstTheIssuer() throws Exception {
        check(crlOnly, ca.cert);
        assertEquals(1, http.sent.size(), "no responder: straight to the CRL");

        answer(http.sent.get(0), 200, ScriptedTls.crl(ca, null, null));

        RevocationResult r = only();
        assertEquals(RevocationStatus.GOOD, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
    }

    /** The regression: a CRL that cannot be verified used to be reported GOOD. Now it is not even fetched. */
    @Test
    public void withoutTheIssuerACrlIsNeitherFetchedNorTrusted() {
        check(crlOnly, null);

        RevocationResult r = only();
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
        assertEquals(RevocationChecker.ISSUER_NOT_PRESENTED, r.getErrorMessage());
        assertTrue(http.sent.isEmpty(), "no request for an answer that could never be trusted");
        assertEquals(0, clock.liveCount(), "nothing left armed");
    }

    @Test
    public void withoutTheIssuerAnOcspLeafIsUnknownWithoutARequest() {
        check(both, null);

        RevocationResult r = only();
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertTrue(r.getErrorMessage().toLowerCase().contains("issuer"), r.getErrorMessage());
        assertTrue(http.sent.isEmpty());
    }

    @Test
    public void aLeafNamingNothingIsNotSupportedByDesign() {
        check(neither, ca.cert);
        RevocationResult r = only();
        assertEquals(RevocationStatus.NOT_SUPPORTED, r.getStatus());
        assertEquals(RevocationChecker.METHOD_NONE, r.getMethod());
        assertTrue(http.sent.isEmpty());
        assertEquals(0, clock.liveCount());
    }

    @Test
    public void noHttpClientIsUnknownNotAnError() {
        new NetworkRevocationChecker(null, clock).check(both, ca.cert, 5_000, results::add);
        RevocationResult r = only();
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertEquals(RevocationChecker.METHOD_NONE, r.getMethod());
    }
}
