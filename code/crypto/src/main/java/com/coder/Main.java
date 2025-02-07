package com.coder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        //KeyUtils.readPEM();

        CertUtils.generateCertificate();
    }
}