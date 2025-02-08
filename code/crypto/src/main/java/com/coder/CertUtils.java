package com.coder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.javatuples.Pair;

import javax.security.auth.x500.X500Principal;


public class CertUtils {
    public static Pair<X509Certificate, KeyPair> generateCertificate() throws Exception {
        Pair<X509Certificate, KeyPair> result = generateECCCertificate();
        var cert = result.getValue0();
        System.out.println("Generated ECC certificate: " + cert.toString());
        System.out.println("Generated ECC transformCertificate: " + transformCertificate(cert));
        return result;
    }

    public static Pair<X509Certificate, KeyPair> generateECCCertificate() throws Exception {
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

            var cert = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signerBuilder.build(privateKey)));
            return Pair.with(cert, keyPair);
        } catch (Exception e) {
            throw new RuntimeException("Error creating certificate...");
        }
    }

    public static String transformCertificate(X509Certificate certificate) throws CertificateEncodingException {
        return "-----BEGIN CERTIFICATE-----" +
                Base64.getEncoder().encodeToString(certificate.getEncoded()) +
                "-----END CERTIFICATE-----";
    }

    public static void intermidiateCertificate() throws Exception {
        Pair<X509Certificate, KeyPair> result = generateECCCertificate();
        var rootCACert = result.getValue0();
        var rootCAKeyPair = result.getValue1();

        String csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIBKzCB0wIBADBxMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxETAP\n" +
                "BgNVBAcMCE5ldyBZb3JrMRcwFQYDVQQKDA5JVCBTdGFydHVwIExMQzELMAkGA1UE\n" +
                "CwwCSVQxFjAUBgNVBAMMDWNvbS5pdHN0YXJ0dXAwWTATBgcqhkjOPQIBBggqhkjO\n" +
                "PQMBBwNCAAS9hrnRtDXKDAG0VC2j4eueDUMF2cFbBror0Wavbz6j7Ix/uzI/+D6v\n" +
                "KV3LK3NdtN7wJVxjqc3e2vGl2rtY9DZNoAAwCgYIKoZIzj0EAwIDRwAwRAIgYl0Y\n" +
                "bG1P2RhzbOsXDg0jTIR8vXaeqYhRlzMrXbeIeLUCIGjBqCyoOfXpB4M3ZoVfyW+V\n" +
                "KGLy4u02MkLEDowf7p7q\n" +
                "-----END CERTIFICATE REQUEST-----";


        X509Certificate intermediateCertificate = generateIntermediateCertificate(rootCACert, rootCAKeyPair, csr);
        System.out.println("intermediate certificate: " + intermediateCertificate.toString());
        intermediateCertificate.verify(rootCACert.getPublicKey());
    }

    private static X509Certificate generateIntermediateCertificate(X509Certificate rootCACert, KeyPair rootCAKeyPair, String csr) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            PKCS10CertificationRequest request = convertToPKCS10(csr);
            var subject = request.getSubject();

            var subjectPublicKeyInfo = request.getSubjectPublicKeyInfo();
            var keyConverter = new JcaPEMKeyConverter();
            var publicKey = keyConverter.getPublicKey(subjectPublicKeyInfo);

            X509Certificate signedCert = generateCertificate(rootCACert, rootCAKeyPair.getPrivate(), subject, publicKey);
            return signedCert;
        } catch (
                Exception e) {
            return null;
        }
    }

    private static X509Certificate generateCertificate(X509Certificate rootCertificate, PrivateKey rootPrivateKey, X500Name subject, PublicKey publicKey) {
        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                rootCertificate.getSubjectX500Principal(), // issuer
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                new X500Principal(subject.toString()), // subject
                publicKey
        );

        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            certificateBuilder.addExtension(Extension.subjectKeyIdentifier,
                    false, extensionUtils.createSubjectKeyIdentifier(publicKey));
            certificateBuilder.addExtension(Extension.authorityKeyIdentifier,
                    false, extensionUtils.createAuthorityKeyIdentifier(rootCertificate));

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

            return new JcaX509CertificateConverter()
                    .getCertificate(certificateBuilder
                            .build(signerBuilder.build(rootPrivateKey)));
        } catch (GeneralSecurityException | OperatorCreationException e) {
            throw new RuntimeException("Error creating certificate...");
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }
    }

    private static PKCS10CertificationRequest convertToPKCS10(String csr) {
        PKCS10CertificationRequest request = null;
        ByteArrayInputStream stream;

        try {
            var byteArrayStream = new ByteArrayInputStream(csr.getBytes());
            var pemParser = new PEMParser(new InputStreamReader(byteArrayStream));
            var pemObject = pemParser.readObject();

            if (pemObject instanceof PKCS10CertificationRequest) {
                request = (PKCS10CertificationRequest) pemObject;
            }
        } catch (Exception e) {
            throw new RuntimeException("Error converting CSR to PKCS10CertificationRequest");
        }
        return request;
    }
}
