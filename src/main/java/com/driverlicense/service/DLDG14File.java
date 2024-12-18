package com.driverlicense.service;

import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class DLDG14File extends DLDataGroup {
    private static final ASN1ObjectIdentifier ID_ACAUTH = new ASN1ObjectIdentifier("1.0.18013.3.3.1");
    private final Map<Integer, PublicKey> publicKeys;

    public byte[] getEncoded() {
        return new byte[0];
    }

    public int getTag() {
        return 110;
    }

    public DLDG14File(InputStream inputStream) throws IOException {
        TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
        if (tLVInputStream.readTag() == 110) {
            this.isSourceConsistent = false;
            tLVInputStream.readLength();
            Enumeration objects = ((DERSet) new ASN1InputStream(tLVInputStream.readValue()).readObject()).getObjects();
            this.publicKeys = new TreeMap<>();
            while (objects.hasMoreElements()) {
                DERSequence dERSequence = (DERSequence) objects.nextElement();
                ASN1ObjectIdentifier dERObjectIdentifier = (ASN1ObjectIdentifier) dERSequence.getObjectAt(0);
                if (dERObjectIdentifier.equals(ID_ACAUTH)) {
                    DERSequence dERSequence2 = (DERSequence) dERSequence.getObjectAt(1);
                    if (dERSequence2.size() == 2) {
                        this.publicKeys.put(((ASN1Integer) dERSequence2.getObjectAt(0)).getValue().intValue(), getKey(dERSequence2.getObjectAt(1).toASN1Primitive()));
                    } else {
                        this.publicKeys.put(-1, getKey(dERSequence2.getObjectAt(0).toASN1Primitive()));
                    }
                } else {
                    throw new IllegalStateException("Wrong OID " + dERObjectIdentifier.getId());
                }
            }
            return;
        }
        throw new IllegalArgumentException("Expected EF_DG14_TAG");
    }

    private PublicKey getKey(ASN1Object aSN1Object) throws IOException {
        try {
            return (ECPublicKey) KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(aSN1Object.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Could not decode key.");
        }
    }

    public DLDG14File(PublicKey publicKey) {
        TreeMap treeMap = new TreeMap();
        this.publicKeys = treeMap;
        treeMap.put(-1, publicKey);
    }

    public DLDG14File(Map<Integer, PublicKey> map) {
        TreeMap treeMap = new TreeMap();
        this.publicKeys = treeMap;
        treeMap.putAll(map);
    }

    public int getSize() {
        return this.publicKeys.size();
    }

    public PublicKey getKey(Integer num) {
        if (getSize() == 0) {
            return null;
        }
        return this.publicKeys.get(num);
    }

    public Set<Integer> getIds() {
        return this.publicKeys.keySet();
    }

    public String toString() {
        return "DG14File: " + this.publicKeys.toString();
    }

    public static void main(String[] strArr) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator instance = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
            instance.initialize(new ECGenParameterSpec("c2pnb163v1"));
            KeyPair generateKeyPair = instance.generateKeyPair();
            KeyPair generateKeyPair2 = instance.generateKeyPair();
            DLDG14File dG14File = new DLDG14File((PublicKey) (ECPublicKey) generateKeyPair.getPublic());
            HashMap hashMap = new HashMap();
            hashMap.put(10, generateKeyPair.getPublic());
            hashMap.put(20, generateKeyPair2.getPublic());
            PrintStream printStream = System.out;
            printStream.println("File 1 : " + dG14File);
            DLDG14File dG14File2 = new DLDG14File((InputStream) new ByteArrayInputStream(dG14File.getEncoded()));
            PrintStream printStream2 = System.out;
            printStream2.println("File 1p: " + dG14File2);
            boolean equals = Arrays.equals(dG14File.getEncoded(), dG14File2.getEncoded());
            PrintStream printStream3 = System.out;
            printStream3.println("res1: " + equals);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
