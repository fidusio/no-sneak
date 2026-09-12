package io.xlogistx.nosneak.v2.runtime;

import io.xlogistx.nosneak.v2.analysis.VersionProbeCallback;
import io.xlogistx.nosneak.v2.tls.PQCSessionConfig;
import io.xlogistx.nosneak.v2.tls.PQCTlsClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The "server" side of a scripted TLS handshake: an in-memory CA and leaf (with or without OCSP
 * and CRL pointers), the responses that CA would sign, and a {@link PQCTlsClient} stand-in whose
 * negotiated facts a test sets directly. {@link ScriptedTransport#scriptedTls} hands the session
 * to a {@code ProbeContext}, so every action after {@code tls-handshake} — {@code pqc-check},
 * {@code cert-chain-validate}, {@code revocation-check}, the enumerations — runs on real code
 * over facts the test chose, with no socket anywhere.
 */
public final class ScriptedTls {

    private static final AtomicLong SERIAL = new AtomicLong(42);

    private ScriptedTls() {
    }

    /** A throwaway CA: key, JCA certificate and BC holder. */
    public static final class Ca {
        public final KeyPair key;
        public final X509Certificate cert;
        public final X509CertificateHolder holder;

        Ca(KeyPair key, X509Certificate cert, X509CertificateHolder holder) {
            this.key = key;
            this.cert = cert;
            this.holder = holder;
        }
    }

    public static Ca ca(String cn) throws Exception {
        KeyPair key = rsa();
        X500Name name = new X500Name("CN=" + cn);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                notBefore(), notAfter(), name, key.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509CertificateHolder holder = b.build(signer(key));
        return new Ca(key, toX509(holder), holder);
    }

    /**
     * A leaf signed by {@code ca} with a DNS and a 127.0.0.1 SAN; {@code ocspUrl} / {@code crlUrl}
     * (nullable) become its AIA responder and CRL distribution point.
     */
    public static X509Certificate leaf(Ca ca, String cn, String ocspUrl, String crlUrl) throws Exception {
        KeyPair key = rsa();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(ca.holder.getSubject(),
                BigInteger.valueOf(SERIAL.incrementAndGet()), notBefore(), notAfter(),
                new X500Name("CN=" + cn), key.getPublic());
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, cn),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        if (ocspUrl != null) {
            b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        if (crlUrl != null) {
            b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{
                    new DistributionPoint(new DistributionPointName(new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))), null, null)}));
        }
        return toX509(b.build(signer(ca.key)));
    }

    /** A DER OCSP response from {@code ca} about {@code leaf} with the given status. */
    public static byte[] ocsp(Ca ca, X509Certificate leaf, CertificateStatus status) throws Exception {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1), ca.holder, leaf.getSerialNumber());
        BasicOCSPResp basic = new BasicOCSPRespBuilder(new RespID(ca.holder.getSubject()))
                .addResponse(id, status)
                .build(signer(ca.key), new X509CertificateHolder[]{ca.holder}, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    /** A fresh DER CRL from {@code ca}, listing {@code revoked} (nullable) as key-compromised at {@code revokedAt}. */
    public static byte[] crl(Ca ca, X509Certificate revoked, Date revokedAt) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(ca.holder.getSubject(), new Date(System.currentTimeMillis() - 60_000));
        b.setNextUpdate(new Date(System.currentTimeMillis() + 3_600_000L));
        if (revoked != null) {
            b.addCRLEntry(revoked.getSerialNumber(), revokedAt, CRLReason.keyCompromise);
        }
        X509CRLHolder holder = b.build(signer(ca.key));
        return holder.getEncoded();
    }

    /** The chain as Bouncy Castle's TLS {@code Certificate}, leaf first — what a handshake presents. */
    public static org.bouncycastle.tls.Certificate bcChain(X509Certificate... chain) throws Exception {
        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        TlsCertificate[] list = new TlsCertificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            list[i] = crypto.createCertificate(chain[i].getEncoded());
        }
        return new org.bouncycastle.tls.Certificate(list);
    }

    /** A session whose client is {@code client}: what {@link ScriptedTransport#scriptedTls} takes. */
    public static PQCSessionConfig session(FakeTlsClient client) {
        PQCSessionConfig cfg = new PQCSessionConfig(InetSocketAddress.createUnresolved("127.0.0.1", 443));
        cfg.tlsClient = client;
        return cfg;
    }

    /**
     * A {@link PQCTlsClient} whose negotiated facts are fields a test sets: the version, the
     * suite, the TLS 1.3 key-share group (0 = none, as on TLS 1.2), the presented chain and the
     * stapled OCSP response. Every getter the engine reads is overridden.
     */
    public static final class FakeTlsClient extends PQCTlsClient {
        public ProtocolVersion version = ProtocolVersion.TLSv13;
        public int cipher = CipherSuite.TLS_AES_256_GCM_SHA384;
        public int group = NamedGroup.X25519MLKEM768;
        public org.bouncycastle.tls.Certificate chain;
        public byte[] staple;

        public FakeTlsClient() {
            super(InetSocketAddress.createUnresolved("127.0.0.1", 443));
        }

        @Override public ProtocolVersion getNegotiatedVersion() { return version; }
        @Override public String getNegotiatedVersionString() { return VersionProbeCallback.getVersionName(version); }
        @Override public int getNegotiatedCipherSuite() { return cipher; }
        @Override public String getNegotiatedCipherSuiteName() { return getCipherSuiteName(cipher); }
        @Override public int getNegotiatedKeyExchange() { return group; }
        @Override public String getNegotiatedKeyExchangeName() { return group == 0 ? "UNKNOWN" : getNamedGroupName(group); }
        @Override public org.bouncycastle.tls.Certificate getServerCertificate() { return chain; }
        @Override public byte[] getStapledOCSPResponse() { return staple; }
        @Override public boolean isHandshakeComplete() { return true; }

        /** The production rule over the scripted fields: the group on TLS 1.3, the suite's family before. */
        @Override
        public String getKeyExchangeAlgorithm() {
            if (ProtocolVersion.TLSv13.equals(version)) {
                return group != 0 ? getNamedGroupName(group) : "TLS1.3-KeyShare";
            }
            String name = getCipherSuiteName(cipher);
            if (name.contains("ECDHE")) return "ECDHE";
            if (name.contains("DHE")) return "DHE";
            if (name.contains("RSA")) return "RSA";
            return "UNKNOWN";
        }
    }

    // ---- plumbing ----

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static ContentSigner signer(KeyPair key) throws Exception {
        return new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate());
    }

    private static Date notBefore() {
        return new Date(System.currentTimeMillis() - 86_400_000L);
    }

    private static Date notAfter() {
        return new Date(System.currentTimeMillis() + 86_400_000L * 365);
    }

    private static X509Certificate toX509(X509CertificateHolder holder) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }
}
