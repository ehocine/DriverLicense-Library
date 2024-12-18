package com.driverlicense.service;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class SimpleDocumentSigner
        implements DocumentSigner {
    private X509Certificate certificate;
    private final PrivateKey privateKey;

    public SimpleDocumentSigner(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public SimpleDocumentSigner(PrivateKey privateKey) {
        this(privateKey, null);
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public byte[] signData(byte[] dataToBeSigned) {
        try {
            Signature signature = Signature.getInstance(this.certificate.getSigAlgName());
            signature.initSign(this.privateKey);
            signature.update(dataToBeSigned);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}