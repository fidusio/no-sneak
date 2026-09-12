package io.xlogistx.nosneak.v2.analysis;

import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.http.HTTPURLCallback;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponse;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.task.ConsumerCallback;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Active revocation over the network, <b>without blocking a thread</b>: an OCSP POST to the
 * leaf's AIA responder, and when the certificate names no responder (or the responder fails) a
 * CRL GET from its distribution point. Both ride the injected {@link HTTPNIOSocket} (the same
 * {@code NIOSocket} the probe runs on) and the injected scheduler bounds the whole attempt;
 * the callback is invoked exactly once, from whichever of {response, error, timeout} arrives
 * first, and every in-flight HTTP session is closed at that moment so a silent responder
 * cannot leak a socket.
 * <p>
 * Soft-fail everywhere: an unreachable responder is {@code UNKNOWN}/{@code ocsp-unreachable}
 * (or {@code crl-unreachable}), never {@code REVOKED} and never a trust failure on its own —
 * that is {@code Grade}'s call, and it only acts on a confirmed {@code REVOKED}.
 */
public final class NetworkRevocationChecker {

    public static final LogWrapper log = new LogWrapper(NetworkRevocationChecker.class).setEnabled(false);

    /** Default bound on the whole OCSP-then-CRL attempt. */
    public static final long DEFAULT_TIMEOUT_MS = 5_000;

    private final HTTPNIOSocket http;
    private final ScheduledExecutorService scheduler;

    public NetworkRevocationChecker(HTTPNIOSocket http, ScheduledExecutorService scheduler) {
        this.http = http;
        this.scheduler = scheduler;
    }

    /**
     * Resolve the leaf's revocation status. Never blocks; {@code onResult} runs on an NIO,
     * scheduler or pool thread exactly once.
     *
     * @param leaf      the server's leaf certificate
     * @param issuer    its issuer, needed to build the OCSP CertificateID and to verify a CRL;
     *                  when absent neither is possible and the answer is {@code UNKNOWN} at once
     * @param timeoutMs upper bound on the whole attempt; {@code <= 0} uses {@link #DEFAULT_TIMEOUT_MS}
     */
    public void check(X509Certificate leaf, X509Certificate issuer, long timeoutMs,
                      Consumer<RevocationResult> onResult) {
        final long budget = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
        OPSecUtil ops = OPSecUtil.singleton();
        final List<String> ocspUrls = leaf != null ? ops.extractOCSPResponderURLs(leaf) : Collections.emptyList();
        final List<String> crlUrls = leaf != null ? ops.extractCRLDistributionPoints(leaf) : Collections.emptyList();

        if (leaf == null) {
            onResult.accept(RevocationResult.error(RevocationChecker.METHOD_NONE, "No leaf certificate"));
            return;
        }
        if (ocspUrls.isEmpty() && crlUrls.isEmpty()) {
            onResult.accept(RevocationChecker.notSupported(
                    "Certificate names no OCSP responder and no CRL distribution point"));
            return;
        }
        if (http == null) {
            onResult.accept(RevocationResult.unknown(RevocationChecker.METHOD_NONE,
                    "No HTTP transport available for an active revocation check"));
            return;
        }

        final Attempt attempt = new Attempt(onResult);
        attempt.timeout = scheduler.schedule(() -> attempt.finish(RevocationResult.unknown(
                        (ocspUrls.isEmpty() ? RevocationChecker.METHOD_CRL : RevocationChecker.METHOD_OCSP) + "-unreachable",
                        "No answer within " + budget + " ms")),
                budget, TimeUnit.MILLISECONDS);

        if (!ocspUrls.isEmpty() && issuer != null) {
            fetchOCSP(leaf, issuer, ocspUrls.get(0), attempt, r -> {
                if (r.getStatus() == OPSecUtil.RevocationStatus.GOOD
                        || r.getStatus() == OPSecUtil.RevocationStatus.REVOKED
                        || crlUrls.isEmpty()) {
                    attempt.finish(r);
                } else {
                    // The responder did not give a definitive answer: try the CRL before giving up.
                    fetchCRL(leaf, issuer, crlUrls.get(0), attempt, attempt::finish);
                }
            });
        } else if (!crlUrls.isEmpty() && issuer != null) {
            fetchCRL(leaf, issuer, crlUrls.get(0), attempt, attempt::finish);
        } else if (!crlUrls.isEmpty()) {
            // A CRL fetched without the issuer could not be signature-verified, so it could never
            // say GOOD (see RevocationChecker.fromCRL); do not spend a request to learn that.
            attempt.finish(RevocationResult.unknown(RevocationChecker.METHOD_CRL,
                    RevocationChecker.ISSUER_NOT_PRESENTED));
        } else {
            attempt.finish(RevocationResult.unknown(RevocationChecker.METHOD_OCSP,
                    "OCSP responder present but the issuer certificate was not sent, so no request can be built"));
        }
    }

    private void fetchOCSP(X509Certificate leaf, X509Certificate issuer, String url, Attempt attempt,
                           Consumer<RevocationResult> next) {
        try {
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
            CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuer), leaf.getSerialNumber());
            OCSPReq request = new OCSPReqBuilder().addRequest(id).build();

            HTTPMessageConfigInterface hmci = HTTPMessageConfig.buildHMCI(url, HTTPMethod.POST, false);
            hmci.setContentType("application/ocsp-request");
            hmci.setContent(request.getEncoded());
            send(hmci, attempt, RevocationChecker.METHOD_OCSP, body -> next.accept(RevocationChecker.fromOCSPResponse(body)), next);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("OCSP request build failed: " + e.getMessage());
            next.accept(RevocationResult.error(RevocationChecker.METHOD_OCSP,
                    "Failed to build OCSP request: " + e.getMessage()));
        }
    }

    private void fetchCRL(X509Certificate leaf, X509Certificate issuer, String url, Attempt attempt,
                          Consumer<RevocationResult> next) {
        try {
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.buildHMCI(url, HTTPMethod.GET, false);
            send(hmci, attempt, RevocationChecker.METHOD_CRL,
                    body -> next.accept(RevocationChecker.fromCRL(body, leaf, issuer)), next);
        } catch (Exception e) {
            next.accept(RevocationResult.error(RevocationChecker.METHOD_CRL,
                    "Failed to build CRL request: " + e.getMessage()));
        }
    }

    private void send(HTTPMessageConfigInterface hmci, Attempt attempt, String method,
                      Consumer<byte[]> onBody, Consumer<RevocationResult> onFailure) throws Exception {
        HTTPURLCallback huc = new HTTPURLCallback(hmci, new ConsumerCallback<HTTPResponse>() {
            @Override
            public void accept(HTTPResponse response) {
                if (response == null || !response.isSuccess()) {
                    onFailure.accept(RevocationResult.unknown(method + "-unreachable",
                            "HTTP " + (response != null ? response.getStatus() : "no response")));
                    return;
                }
                byte[] body = response instanceof HTTPResponseData ? ((HTTPResponseData) response).getData() : null;
                onBody.accept(body);
            }

            @Override
            public void exception(Throwable e) {
                onFailure.accept(RevocationResult.unknown(method + "-unreachable",
                        "Request failed: " + e.getMessage()));
            }
        }, false);
        if (!attempt.register(huc)) {
            return; // already resolved (timeout won): do not launch a request nobody will read
        }
        http.asyncSend(huc);
    }

    /** One resolution: exactly-once completion, and every in-flight HTTP session closed with it. */
    private static final class Attempt {
        private final Consumer<RevocationResult> onResult;
        private final AtomicBoolean fired = new AtomicBoolean();
        private final List<HTTPURLCallback> inFlight = new ArrayList<>();
        volatile ScheduledFuture<?> timeout;

        Attempt(Consumer<RevocationResult> onResult) {
            this.onResult = onResult;
        }

        boolean register(HTTPURLCallback huc) {
            synchronized (inFlight) {
                if (fired.get()) {
                    SharedIOUtil.close(huc);
                    return false;
                }
                inFlight.add(huc);
                return true;
            }
        }

        void finish(RevocationResult r) {
            if (!fired.compareAndSet(false, true)) {
                return;
            }
            ScheduledFuture<?> t = timeout;
            if (t != null) {
                try {
                    t.cancel(false);
                } catch (RuntimeException ignored) {
                }
            }
            synchronized (inFlight) {
                for (HTTPURLCallback h : inFlight) {
                    SharedIOUtil.close(h);
                }
                inFlight.clear();
            }
            onResult.accept(r);
        }
    }
}
