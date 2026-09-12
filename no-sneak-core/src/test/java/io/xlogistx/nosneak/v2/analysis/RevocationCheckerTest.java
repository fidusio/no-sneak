package io.xlogistx.nosneak.v2.analysis;

import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure tests for the in-memory revocation parsers: a throwaway CA, a leaf, a signed OCSP
 * response and a signed CRL are built in-test with Bouncy Castle, so the status, method,
 * date and reason every path reports are pinned without a responder on the network.
 */
public class RevocationCheckerTest {

    private static KeyPair caKey;
    private static X509Certificate ca;
    private static X509CertificateHolder caHolder;
    private static X509Certificate leaf;
    private static final Date REVOKED_AT = new Date(1_700_000_000_000L);

    @BeforeAll
    public static void fixtures() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        caKey = gen.generateKeyPair();
        KeyPair leafKey = gen.generateKeyPair();
        X500Name caName = new X500Name("CN=Test CA");
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000L * 365);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey.getPrivate());

        caHolder = new JcaX509v3CertificateBuilder(caName, BigInteger.ONE, notBefore, notAfter,
                caName, caKey.getPublic()).build(signer);
        X509CertificateHolder leafHolder = new JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(42),
                notBefore, notAfter, new X500Name("CN=leaf.example"), leafKey.getPublic()).build(signer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ca = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(caHolder.getEncoded()));
        leaf = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafHolder.getEncoded()));
    }

    private static byte[] ocsp(CertificateStatus status) throws Exception {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1), caHolder, leaf.getSerialNumber());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey.getPrivate());
        BasicOCSPResp basic = new BasicOCSPRespBuilder(new RespID(caHolder.getSubject()))
                .addResponse(id, status)
                .build(signer, new X509CertificateHolder[]{caHolder}, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    private static byte[] crl(boolean revokeLeaf, boolean stale) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey.getPrivate());
        X509v2CRLBuilder b = new X509v2CRLBuilder(caHolder.getSubject(), new Date(System.currentTimeMillis() - 60_000));
        b.setNextUpdate(new Date(System.currentTimeMillis() + (stale ? -1 : 1) * 3_600_000L));
        if (revokeLeaf) {
            b.addCRLEntry(leaf.getSerialNumber(), REVOKED_AT, CRLReason.keyCompromise);
        }
        X509CRLHolder holder = b.build(signer);
        return holder.getEncoded();
    }

    // ==================== stapled ====================

    @Test
    public void nothingStapledIsUnknownWithMethodNone() {
        RevocationResult r = RevocationChecker.fromStaple(null);
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertEquals(RevocationChecker.METHOD_NONE, r.getMethod());
        assertEquals(RevocationStatus.UNKNOWN, RevocationChecker.fromStaple(new byte[0]).getStatus());
    }

    @Test
    public void aStapledGoodResponseIsGoodViaStapled() throws Exception {
        RevocationResult r = RevocationChecker.fromStaple(ocsp(CertificateStatus.GOOD));
        assertEquals(RevocationStatus.GOOD, r.getStatus());
        assertEquals(RevocationChecker.METHOD_STAPLED, r.getMethod());
        assertNull(r.getRevocationDate());
    }

    // ==================== OCSP ====================

    @Test
    public void aRevokedOcspResponseKeepsDateAndReason() throws Exception {
        RevocationResult r = RevocationChecker.fromOCSPResponse(
                ocsp(new RevokedStatus(REVOKED_AT, CRLReason.keyCompromise)));
        assertEquals(RevocationStatus.REVOKED, r.getStatus());
        assertEquals(RevocationChecker.METHOD_OCSP, r.getMethod());
        assertNotNull(r.getRevocationDate(), "the responder's revocation time must be kept");
        assertEquals(REVOKED_AT.getTime() / 1000, r.getRevocationDate() / 1000);
        assertEquals("KEY_COMPROMISE", r.getRevocationReason());
    }

    @Test
    public void garbageOcspBytesAreAnErrorNotARevocation() {
        RevocationResult r = RevocationChecker.fromOCSPResponse(new byte[]{1, 2, 3, 4});
        assertEquals(RevocationStatus.ERROR, r.getStatus());
        assertEquals(RevocationChecker.METHOD_OCSP, r.getMethod());
    }

    // ==================== CRL ====================

    @Test
    public void aCrlThatListsTheLeafIsRevokedWithDateAndReason() throws Exception {
        RevocationResult r = RevocationChecker.fromCRL(crl(true, false), leaf, ca);
        assertEquals(RevocationStatus.REVOKED, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
        assertEquals(REVOKED_AT.getTime() / 1000, r.getRevocationDate() / 1000);
        assertEquals("KEY_COMPROMISE", r.getRevocationReason());
    }

    @Test
    public void aCrlWithoutTheLeafIsGoodViaCrl() throws Exception {
        RevocationResult r = RevocationChecker.fromCRL(crl(false, false), leaf, ca);
        assertEquals(RevocationStatus.GOOD, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
    }

    @Test
    public void aStaleCrlIsUnknownNeverGood() throws Exception {
        RevocationResult r = RevocationChecker.fromCRL(crl(false, true), leaf, ca);
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertTrue(r.getErrorMessage().toLowerCase().contains("stale"));
    }

    @Test
    public void aCrlSignedByAStrangerIsUnknownNeverGood() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair stranger = gen.generateKeyPair();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(stranger.getPrivate());
        X509v2CRLBuilder b = new X509v2CRLBuilder(caHolder.getSubject(), new Date());
        b.setNextUpdate(new Date(System.currentTimeMillis() + 3_600_000L));
        byte[] forged = b.build(signer).getEncoded();

        RevocationResult r = RevocationChecker.fromCRL(forged, leaf, ca);
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertTrue(r.getErrorMessage().contains("signature"));
    }

    /**
     * A chain of one: the server sent no issuer, so the CRL's signature cannot be checked. It
     * used to read GOOD whenever the serial was absent — an unverified CRL proves nothing.
     */
    @Test
    public void aCrlWithoutTheIssuerIsUnknownNeverGood() throws Exception {
        RevocationResult r = RevocationChecker.fromCRL(crl(false, false), leaf, null);
        assertEquals(RevocationStatus.UNKNOWN, r.getStatus());
        assertEquals(RevocationChecker.METHOD_CRL, r.getMethod());
        assertEquals(RevocationChecker.ISSUER_NOT_PRESENTED, r.getErrorMessage());
        // Even a CRL that does list the leaf is not trusted unverified: still UNKNOWN, not REVOKED.
        assertEquals(RevocationStatus.UNKNOWN, RevocationChecker.fromCRL(crl(true, false), leaf, null).getStatus());
    }

    @Test
    public void reasonCodesMapToTheJdkNames() {
        assertEquals("KEY_COMPROMISE", RevocationChecker.reasonName(1));
        assertEquals("CERTIFICATE_HOLD", RevocationChecker.reasonName(6));
        assertEquals("REMOVE_FROM_CRL", RevocationChecker.reasonName(8));
        assertEquals("UNKNOWN(7)", RevocationChecker.reasonName(7));
    }
}
