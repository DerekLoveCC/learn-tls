package com.coder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        //generateRSA();
        //generateECC();
        readPEM();
    }

    private static void readPEM() {
        readPEMPublicKey();
        //readPEMPrivateKey();
    }

    private static void readPEMPrivateKey() {
        try (FileReader fileReader = new FileReader("D:\\Github\\learn-tls\\testdata\\private-key.pem");
             PemReader pemReader = new PemReader(fileReader)) {
            var pemObject = pemReader.readPemObject();
            var sepc = new PKCS8EncodedKeySpec(pemObject.getContent());
            var keyFactory = KeyFactory.getInstance("RSA");
            System.out.println("<==================read pem private key=========================>");
            System.out.println(keyFactory.generatePrivate(sepc));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void readPEMPublicKey() {
        try (FileReader fileReader = new FileReader("D:\\Github\\learn-tls\\testdata\\public-key.pem");
             PemReader pemReader = new PemReader(fileReader)) {
            var pemObject = pemReader.readPemObject();
            var sepc = new X509EncodedKeySpec(pemObject.getContent());
            var keyFactory = KeyFactory.getInstance("RSA");
            var publicKey = keyFactory.generatePublic(sepc);
            System.out.println(publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void generateECC() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        var param = new ECGenParameterSpec("prime256v1");
        try {
            keyPairGenerator.initialize(param);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        System.out.println(publicKey);
        System.out.println("<==========>");

        var privateKey = keyPair.getPrivate();
        System.out.println(privateKey);
    }

    private static void generateRSA() throws NoSuchAlgorithmException {
        var keypairGenerator = KeyPairGenerator.getInstance("RSA");
        keypairGenerator.initialize(2048);

        var keypair = keypairGenerator.generateKeyPair();
        var publicKey = keypair.getPublic();
        System.out.println(publicKey);

        System.out.println("<============================================>");

        var privateKey = keypair.getPrivate();
        System.out.println(privateKey);
    }
}