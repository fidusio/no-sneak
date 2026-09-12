package io.xlogistx.nosneak.v2.analysis;

import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.zoxweb.server.logging.LogWrapper;

import java.io.ByteArrayInputStream;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Certificate revocation from evidence already in hand: a handshake-stapled OCSP response
 * (RFC 6066), an OCSP response fetched by {@link NetworkRevocationChecker}, or a CRL it
 * downloaded. Everything here is in-memory parsing — zero network, instant.
 * <p>
 * {@code revocation-method} is one of {@link #METHOD_STAPLED}, {@link #METHOD_OCSP},
 * {@link #METHOD_CRL} or {@link #METHOD_NONE}; a network fetch that could not complete reports
 * {@code UNKNOWN} with the method suffixed {@code -unreachable} so the reader can tell "the
 * responder said unknown" from "the responder never answered". Results use opsec's
 * {@link RevocationResult}, whose date and reason are kept — they used to be computed here and
 * dropped by the caller (PENDING-ISSUES P14).
 */
public final class RevocationChecker {

    public static final LogWrapper log = new LogWrapper(RevocationChecker.class).setEnabled(false);

    public static final String METHOD_STAPLED = "stapled";
    public static final String METHOD_OCSP = "ocsp";
    public static final String METHOD_CRL = "crl";
    public static final String METHOD_NONE = "none";

    private RevocationChecker() {
    }

    /** Parse a stapled OCSP response, or {@code UNKNOWN}/{@link #METHOD_NONE} when none was stapled. */
    public static RevocationResult fromStaple(byte[] stapledOCSP) {
        if (stapledOCSP == null || stapledOCSP.length == 0) {
            return RevocationResult.unknown(METHOD_NONE, "No stapled OCSP response");
        }
        return parseOCSPBytes(METHOD_STAPLED, stapledOCSP);
    }

    /** Parse an OCSP response fetched from the certificate's AIA responder. */
    public static RevocationResult fromOCSPResponse(byte[] body) {
        return parseOCSPBytes(METHOD_OCSP, body);
    }

    /**
     * Look the leaf up in a DER-encoded CRL. When the issuer is supplied the CRL signature is
     * verified first; a CRL that does not verify is reported as {@code UNKNOWN}, never as GOOD.
     */
    public static RevocationResult fromCRL(byte[] crlDer, X509Certificate leaf, X509Certificate issuer) {
        if (crlDer == null || crlDer.length == 0) {
            return RevocationResult.error(METHOD_CRL, "Empty CRL");
        }
        if (leaf == null) {
            return RevocationResult.error(METHOD_CRL, "No leaf certificate to look up");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDer));
            if (issuer != null) {
                try {
                    crl.verify(issuer.getPublicKey());
                } catch (Exception e) {
                    return RevocationResult.unknown(METHOD_CRL, "CRL signature does not verify against the issuer: "
                            + e.getMessage());
                }
            }
            Date next = crl.getNextUpdate();
            if (next != null && next.before(new Date())) {
                return RevocationResult.unknown(METHOD_CRL, "CRL is stale (nextUpdate " + next.toInstant() + ")");
            }
            X509CRLEntry entry = crl.getRevokedCertificate(leaf.getSerialNumber());
            if (entry == null) {
                return RevocationResult.good(METHOD_CRL);
            }
            Long when = entry.getRevocationDate() != null ? entry.getRevocationDate().getTime() : null;
            CRLReason reason = entry.getRevocationReason();
            return RevocationResult.revoked(METHOD_CRL, when, reason != null ? reason.name() : "UNSPECIFIED");
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("CRL parse failed: " + e.getMessage());
            return RevocationResult.error(METHOD_CRL, "Failed to parse CRL: " + e.getMessage());
        }
    }

    /** The CA offers no OCSP responder and no CRL: revocation is not checkable by design. */
    public static RevocationResult notSupported(String why) {
        return RevocationResult.notSupported(METHOD_NONE, why);
    }

    /** Parse a DER OCSP response into a {@link RevocationResult} under the given method label. */
    static RevocationResult parseOCSPBytes(String method, byte[] body) {
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
                            ? reasonName(revoked.getRevocationReason()) : "UNSPECIFIED";
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

    /** RFC 5280 CRLReason code → the JDK enum's name, so OCSP and CRL report the same vocabulary. */
    static String reasonName(int reason) {
        switch (reason) {
            case 0: return CRLReason.UNSPECIFIED.name();
            case 1: return CRLReason.KEY_COMPROMISE.name();
            case 2: return CRLReason.CA_COMPROMISE.name();
            case 3: return CRLReason.AFFILIATION_CHANGED.name();
            case 4: return CRLReason.SUPERSEDED.name();
            case 5: return CRLReason.CESSATION_OF_OPERATION.name();
            case 6: return CRLReason.CERTIFICATE_HOLD.name();
            case 8: return CRLReason.REMOVE_FROM_CRL.name();
            case 9: return CRLReason.PRIVILEGE_WITHDRAWN.name();
            case 10: return CRLReason.AA_COMPROMISE.name();
            default: return "UNKNOWN(" + reason + ")";
        }
    }
}
