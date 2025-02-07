package com.coder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Calendar;

public class CertUtils {
    public static X509Certificate generateCertificate() throws Exception {
        var cert = generateECCCertificate();
        System.out.println("Generated ECC certificate: " + cert.toString());
        System.out.println("Generated ECC transformCertificate: " + transformCertificate(cert));
        return cert;
    }

    public static X509Certificate generateECCCertificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        var keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        var paramSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(paramSpec);

        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        var privateKey = keyPair.getPrivate();


        X500Name distinguishedName = new X500Name("CN=com.example, O=Global Software Support LLC, OU=IT, L=Budapest, C=Hungary");
        var calendar = Calendar.getInstance();
        var notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        var notAfter = calendar.getTime();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                distinguishedName, // issuer
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                distinguishedName, // subject (but for root certificate issuer=subject)
                publicKey
        );

        try {
            var extensionBuilder = new JcaX509ExtensionUtils();
            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, extensionBuilder.createSubjectKeyIdentifier(publicKey));
            certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionBuilder.createAuthorityKeyIdentifier(publicKey));

            var signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

            return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signerBuilder.build(privateKey)));
        } catch (Exception e) {
            throw new RuntimeException("Error creating certificate...");
        }
    }

    public static String transformCertificate(X509Certificate certificate) throws CertificateEncodingException {
        return "-----BEGIN CERTIFICATE-----" +
                Base64.getEncoder().encodeToString(certificate.getEncoded()) +
                "-----END CERTIFICATE-----";
    }
}
