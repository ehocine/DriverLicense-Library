package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.ASN1InputStream;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


public class DLDG13File
        extends DLDataGroup {
    private final PublicKey publicKey;

    public DLDG13File(PublicKey publicKey) {
        this.publicKey = publicKey;
    }


    public DLDG13File(InputStream in) {
        try {
            TLVInputStream tlvIn = new TLVInputStream(in);
            if (tlvIn.readTag() != 111)
                throw new IOException("Wrong tag.");
            tlvIn.readLength();
            ASN1InputStream asn1in = new ASN1InputStream(in);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(asn1in.readObject().getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(pubKeySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException(e.toString());
        }
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            BERTLVObject ef =
                    new BERTLVObject(111,
                            this.publicKey.getEncoded(), false);
            this.sourceObject = ef;
            this.isSourceConsistent = true;
            return ef.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public int getTag() {
        return 111;
    }


    public PublicKey getPublicKey() {
        return this.publicKey;
    }
}