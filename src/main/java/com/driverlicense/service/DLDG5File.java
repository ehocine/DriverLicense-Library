package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;


public class DLDG5File
        extends DLDataGroup {
    private static final short TYPE_TAG = 137;
    private static final short DATA_TAG = 24387;
    private byte[] signatureData = null;

    private int imageType = 0;

    private String mimeImageType = null;


    public static final int TYPE_JPEG = 3;


    public static final int TYPE_JPEG2000 = 4;


    public static final int TYPE_WSQ = 63;


    public DLDG5File(byte[] data, String mimeType) {
        this.signatureData = data;
        if ("image/jpeg".equals(mimeType)) {
            this.imageType = 3;
        } else if ("image/jpeg2000".equals(mimeType)) {
            this.imageType = 4;
        } else {
            throw new IllegalArgumentException("Wrong image type.");
        }
        this.mimeImageType = mimeType;
    }


    public DLDG5File(InputStream in) throws IOException {
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != 103) {
            throw new IllegalArgumentException("Expected EF_DG5_TAG");
        }
        this.isSourceConsistent = false;
        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject typeObject = mainObject.getSubObject(137);
        BERTLVObject dataObject = mainObject.getSubObject(24387);
        this.imageType = ((byte[]) typeObject.getValue())[0];
        if (this.imageType == 3) {
            this.mimeImageType = "image/jpeg";
        } else if (this.imageType == 4) {
            this.mimeImageType = "image/jpeg2000";
        } else {
            throw new IOException("Wrong image type.");
        }
        this.signatureData = (byte[]) dataObject.getValue();
    }

    public int getTag() {
        return 103;
    }

    public String toString() {
        return "DG5File: type " + this.imageType + " bytes " + this.signatureData.length;
    }


    public String getMimeType() {
        return this.mimeImageType;
    }


    public byte[] getImage() {
        return this.signatureData;
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            BERTLVObject result = new BERTLVObject(103,
                    new BERTLVObject(137, new byte[]{(byte) this.imageType}));
            result.addSubObject(new BERTLVObject(24387, this.signatureData));
            result.reconstructLength();
            this.sourceObject = result;
            this.isSourceConsistent = true;
            return result.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void main(String[] args) {
        try {
            byte[] testArray = {103, 8, -119, 1,
                    3, 95, 67, 2, -34, -83};
            DLDG5File f = new DLDG5File(new ByteArrayInputStream(testArray));
            System.out.println(f.toString());
            System.out.println("org0: " + Hex.bytesToHexString(testArray));
            byte[] enc = f.getEncoded();
            byte[] enc2 = f.getEncoded();
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            System.out.println("Compare1: " + Arrays.equals(testArray, enc));
            System.out.println("Compare2: " + Arrays.equals(enc, enc2));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}