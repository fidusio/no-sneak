package io.xlogistx.nosneak.v2.analysis;

import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.zoxweb.server.logging.LogWrapper;

/**
 * Certificate revocation via <b>handshake-stapled OCSP</b> (RFC 6066): the DER OCSP response
 * the server stapled during the TLS handshake is parsed in-memory — zero network, instant,
 * browser-equivalent soft-fail. When no response was stapled the status is
 * {@code UNKNOWN}/{@code NOT_CHECKED} (an active OCSP/CRL fetch needs the HTTP NIO stack and is
 * added when that is wired). Results use opsec's {@link RevocationResult}.
 */
public final class RevocationChecker {

    public static final LogWrapper log = new LogWrapper(RevocationChecker.class).setEnabled(false);

    private RevocationChecker() {
    }

    /** Parse a stapled OCSP response (or return UNKNOWN/NOT_CHECKED when none was stapled). */
    public static RevocationResult fromStaple(byte[] stapledOCSP) {
        if (stapledOCSP == null || stapledOCSP.length == 0) {
            return RevocationResult.unknown("NOT_CHECKED", "No stapled OCSP response");
        }
        return parseOCSPBytes("OCSP_STAPLED", stapledOCSP);
    }

    /** Parse a DER OCSP response into a {@link RevocationResult}. */
    private static RevocationResult parseOCSPBytes(String method, byte[] body) {
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
                    RevokedStatus revoked = (RevokedStatus) certStatus;
                    Long revDate = revoked.getRevocationTime() != null
                            ? revoked.getRevocationTime().getTime() : null;
                    String reason = revoked.hasRevocationReason()
                            ? getRevocationReasonString(revoked.getRevocationReason()) : "UNSPECIFIED";
                    return RevocationResult.revoked(method, revDate, reason);
                } else if (certStatus instanceof UnknownStatus) {
                    return RevocationResult.unknown(method, "Certificate status unknown to OCSP responder");
                }
            }
            return RevocationResult.unknown(method, "No matching response found");
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("OCSP parse failed: " + e.getMessage());
            return RevocationResult.error(method, "Failed to parse OCSP response: " + e.getMessage());
        }
    }

    private static String getRevocationReasonString(int reason) {
        switch (reason) {
            case 0: return "UNSPECIFIED";
            case 1: return "KEY_COMPROMISE";
            case 2: return "CA_COMPROMISE";
            case 3: return "AFFILIATION_CHANGED";
            case 4: return "SUPERSEDED";
            case 5: return "CESSATION_OF_OPERATION";
            case 6: return "CERTIFICATE_HOLD";
            case 8: return "REMOVE_FROM_CRL";
            case 9: return "PRIVILEGE_WITHDRAWN";
            case 10: return "AA_COMPROMISE";
            default: return "UNKNOWN(" + reason + ")";
        }
    }
}
