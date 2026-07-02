package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.http.HTTPURLCallback;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.task.ConsumerCallback;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * NIO-based certificate revocation checker using HTTPURLCallback + HTTPNIOSocket
 * for truly async, event-driven HTTP requests (CRL downloads and OCSP).
 */
public class NIORevocationChecker {

    public static final LogWrapper log = new LogWrapper(NIORevocationChecker.class).setEnabled(false);

    /** Fallback soft-fail timeout for the active OCSP call when none/<=0 is supplied. */
    public static final long DEFAULT_TIMEOUT_MS = 5000L;

    private final HTTPNIOSocket httpNioSocket;
    private final OPSecUtil opsecUtil;
    private final long timeoutMs;

    public NIORevocationChecker(HTTPNIOSocket httpNioSocket) {
        this(httpNioSocket, DEFAULT_TIMEOUT_MS);
    }

    /**
     * @param httpNioSocket shared NIO HTTP socket
     * @param timeoutMs     hard bound for the whole revocation check (OCSP plus
     *                      CRL fallback). {@code <= 0} uses {@link #DEFAULT_TIMEOUT_MS}.
     *                      Without this, an unreachable OCSP/CRL endpoint would
     *                      never invoke the callback and the parent scan would
     *                      hang on its pending revocation task forever.
     */
    public NIORevocationChecker(HTTPNIOSocket httpNioSocket, long timeoutMs) {
        this.httpNioSocket = httpNioSocket;
        this.opsecUtil = OPSecUtil.singleton();
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
    }

    /**
     * Check certificate revocation using direct callbacks.
     * Tries OCSP first, falls back to CRL.
     *
     * @param cert     the certificate to check
     * @param issuer   the issuer certificate (may be null)
     * @param userCallback receives the revocation result
     */
    public void checkRevocation(X509Certificate cert, X509Certificate issuer,
                                Consumer<RevocationResult> userCallback) {
        checkRevocation(cert, issuer, null, userCallback);
    }

    /**
     * Revocation check with an optional handshake-stapled OCSP response.
     * <p>
     * Resolution order, fastest first:
     * <ol>
     *   <li><b>Stapled OCSP</b> (RFC 6066) - parsed in-memory, zero network,
     *       instant. This is the modern correct path (e.g. Let's Encrypt
     *       recommends stapling).</li>
     *   <li><b>Active OCSP</b> - only if not stapled AND the cert carries an
     *       OCSP URL AND we have the issuer. Short, soft-fail.</li>
     *   <li><b>NOT_CHECKED</b> - anything else (no stapling, no OCSP URL, or no
     *       issuer) resolves <i>immediately</i> as UNKNOWN/NOT_CHECKED. We do
     *       NOT fetch CRLs: for CAs like Let's Encrypt the CRL is a huge / often
     *       unreachable file and blocking on it is exactly the hang we are
     *       eliminating. This mirrors how browsers soft-fail.</li>
     * </ol>
     * The result is never {@code REVOKED} unless a responder explicitly says so;
     * inability to determine status is {@code UNKNOWN}, never a scan blocker.
     *
     * @param stapledOCSP DER-encoded OCSP response from the TLS handshake, or null
     */
    public void checkRevocation(X509Certificate cert, X509Certificate issuer,
                                byte[] stapledOCSP, Consumer<RevocationResult> userCallback) {
        if (cert == null) {
            userCallback.accept(RevocationResult.error("NONE", "Certificate is null"));
            return;
        }

        // 1) Stapled OCSP: instant, in-memory, no network, no timeout needed.
        if (stapledOCSP != null && stapledOCSP.length > 0) {
            RevocationResult stapledResult = parseOCSPBytes("OCSP_STAPLED", stapledOCSP);
            // A malformed/empty staple shouldn't kill the check - fall through
            // to the active path only if it was unusable.
            if (stapledResult.getStatus() != RevocationStatus.ERROR) {
                userCallback.accept(stapledResult);
                return;
            }
            if (log.isEnabled()) {
                log.getLogger().info("Stapled OCSP unusable (" + stapledResult.getErrorMessage()
                        + "), falling back to active check");
            }
        }

        // 2) Decide if an active OCSP call is even possible. If not, resolve
        //    immediately as NOT_CHECKED - never walk into a CRL black hole.
        List<String> ocspUrls = opsecUtil.extractOCSPResponderURLs(cert);
        if (ocspUrls.isEmpty()) {
            // CA design: cert has no OCSP responder and nothing was stapled
            // (e.g. Let's Encrypt's short-lived-cert / CRL model). This is a
            // normal, expected state - NOT a failure. We do not fetch CRLs.
            userCallback.accept(RevocationResult.notSupported("NOT_SUPPORTED",
                    "Certificate carries no OCSP responder URL; CA uses short-lived/CRL model (CRL not fetched by design)"));
            return;
        }
        if (issuer == null) {
            // We *could* have OCSP-checked but the chain didn't include the
            // issuer - genuinely indeterminate, not a CA-design choice.
            userCallback.accept(RevocationResult.unknown("NOT_CHECKED",
                    "No issuer certificate available for OCSP"));
            return;
        }

        // 3) Active OCSP, bounded and soft-fail.
        // Guard the user callback so it fires EXACTLY once, no matter which
        // path wins (OCSP response, HTTP exception, or the timeout). This is
        // what prevents the parent scan from hanging on a dead responder.
        final AtomicBoolean fired = new AtomicBoolean(false);
        final AtomicReference<ScheduledFuture<?>> timeoutHolderRef = new AtomicReference<>();
        // Track the in-flight HTTP requests so the orphaned OCSP/CRL socket is
        // reclaimed when this resolves (especially on timeout - that endpoint
        // never answered, so it would otherwise leak an fd indefinitely).
        final List<HTTPURLCallback> inFlight = Collections.synchronizedList(new ArrayList<>());
        final Consumer<RevocationResult> callback = result -> {
            if (!fired.compareAndSet(false, true)) {
                return;
            }
            ScheduledFuture<?> a = timeoutHolderRef.get();
            if (a != null) {
                try {
                    a.cancel(false);
                } catch (Exception ignored) {
                }
            }
            synchronized (inFlight) {
                for (HTTPURLCallback h : inFlight) {
                    SharedIOUtil.close(h);
                }
                inFlight.clear();
            }
            userCallback.accept(result);
        };

        // Register-or-close: under the SAME lock the guarded callback uses to
        // close+clear, decide whether a new request may launch. `fired` is set
        // (CAS) before that callback enters the lock, so once revocation has
        // resolved this returns false and the late request is closed
        // immediately instead of leaking (closes the timeout-vs-OCSP->CRL
        // fallback race that would otherwise re-orphan a socket).
        final Predicate<HTTPURLCallback> register = huc -> {
            synchronized (inFlight) {
                if (fired.get()) {
                    SharedIOUtil.close(huc);
                    return false;
                }
                inFlight.add(huc);
                return true;
            }
        };

        // Soft-fail upper bound on the active OCSP request.
        timeoutHolderRef.set(TaskUtil.defaultTaskScheduler().schedule(() ->
                callback.accept(RevocationResult.unknown("TIMEOUT",
                        "OCSP responder did not answer within " + timeoutMs + "ms")),
                timeoutMs, TimeUnit.MILLISECONDS));

        // Active OCSP. Any failure (HTTP error/exception/bad response) is a
        // SOFT fail -> UNKNOWN, never REVOKED, and never a CRL fallback.
        checkOCSP(cert, issuer, ocspUrls.get(0), register, callback);
    }

    /**
     * Check certificate via OCSP.
     */
    private void checkOCSP(X509Certificate cert, X509Certificate issuerCert,
                           String ocspUrl, Predicate<HTTPURLCallback> register,
                           Consumer<RevocationResult> callback) {
        try {
            // Build OCSP request
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC").build();
            CertificateID certId = new CertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert),
                    cert.getSerialNumber()
            );

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            OCSPReq ocspReq = reqBuilder.build();
            byte[] ocspReqData = ocspReq.getEncoded();

            // Build POST request
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.buildHMCI(ocspUrl, HTTPMethod.POST, false);
            hmci.setContentType("application/ocsp-request");
            hmci.setContent(ocspReqData);

            HTTPURLCallback huc = new HTTPURLCallback(hmci, new ConsumerCallback<HTTPResponse>() {
                @Override
                public void accept(HTTPResponse response) {
                    if (log.isEnabled()) log.getLogger().info("" + response);
                    callback.accept(parseOCSPResponse(response));
                }

                @Override
                public void exception(Throwable e) {
                    if (log.isEnabled())
                        log.getLogger().info("OCSP request failed: " + e.getMessage());
                    callback.accept(RevocationResult.error("OCSP", "Request failed: " + e.getMessage()));
                }
            }, false);

            if (!register.test(huc)) {
                return;
            }
            httpNioSocket.asyncSend(huc);
        } catch (Exception e) {
            if (log.isEnabled())
                log.getLogger().info("OCSP request build failed: " + e.getMessage());
            callback.accept(RevocationResult.error("OCSP", "Failed to build OCSP request: " + e.getMessage()));
        }
    }

    private RevocationResult parseOCSPResponse(HTTPResponse response) {
        if (!response.isSuccess()) {
            return RevocationResult.error("OCSP", "HTTP error: " + response.getStatus());
        }
        return parseOCSPBytes("OCSP", ((HTTPResponseData) response).getData());
    }

    /**
     * Parse a DER OCSP response (from a stapled handshake response or an HTTP
     * fetch) into a {@link RevocationResult}. {@code method} labels the source
     * ("OCSP" or "OCSP_STAPLED").
     */
    private RevocationResult parseOCSPBytes(String method, byte[] body) {
        if (body == null || body.length == 0) {
            return RevocationResult.error(method, "Empty OCSP response");
        }
        try {
            OCSPResp ocspResp = new OCSPResp(body);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                return RevocationResult.error(method, "OCSP response status: " + ocspResp.getStatus());
            }

            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (basicResp == null) {
                return RevocationResult.error(method, "No basic OCSP response");
            }

            for (SingleResp singleResp : basicResp.getResponses()) {
                CertificateStatus certStatus = singleResp.getCertStatus();
                if (certStatus == CertificateStatus.GOOD) {
                    return RevocationResult.good(method);
                } else if (certStatus instanceof RevokedStatus) {
                    RevokedStatus revokedStatus = (RevokedStatus) certStatus;
                    Long revDate = revokedStatus.getRevocationTime() != null ?
                            revokedStatus.getRevocationTime().getTime() : null;
                    String reason = "UNSPECIFIED";
                    if (revokedStatus.hasRevocationReason()) {
                        reason = getRevocationReasonString(revokedStatus.getRevocationReason());
                    }
                    return RevocationResult.revoked(method, revDate, reason);
                } else if (certStatus instanceof UnknownStatus) {
                    return RevocationResult.unknown(method, "Certificate status unknown to OCSP responder");
                }
            }

            return RevocationResult.unknown(method, "No matching response found");
        } catch (Exception e) {
            if (log.isEnabled())
                log.getLogger().info("OCSP response parse failed: " + e.getMessage());
            return RevocationResult.error(method, "Failed to parse OCSP response: " + e.getMessage());
        }
    }

    private String getRevocationReasonString(int reason) {
        switch (reason) {
            case 0:
                return "UNSPECIFIED";
            case 1:
                return "KEY_COMPROMISE";
            case 2:
                return "CA_COMPROMISE";
            case 3:
                return "AFFILIATION_CHANGED";
            case 4:
                return "SUPERSEDED";
            case 5:
                return "CESSATION_OF_OPERATION";
            case 6:
                return "CERTIFICATE_HOLD";
            case 8:
                return "REMOVE_FROM_CRL";
            case 9:
                return "PRIVILEGE_WITHDRAWN";
            case 10:
                return "AA_COMPROMISE";
            default:
                return "UNKNOWN(" + reason + ")";
        }
    }

    /**
     * No-op - we don't own the NIOSocket.
     */
    public void shutdown() {
    }
}
