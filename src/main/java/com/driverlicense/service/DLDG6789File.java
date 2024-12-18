package com.driverlicense.service;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;


public abstract class DLDG6789File
        extends DLDataGroup {
    static final int BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 32609;
    static final int BIOMETRIC_INFORMATION_TEMPLATE_TAG = 32608;
    static final int BIOMETRIC_INFO_COUNT_TAG = 2;
    static final int BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = -95;
    static final int BIOMETRIC_DATA_BLOCK_TAG = 24366;
    static final int BIOMETRIC_DATA_BLOCK_TAG_ALT = 32558;
    static final int FORMAT_OWNER_TAG = 135;
    static final int FORMAT_TYPE_TAG = 136;
    static final int SMT_TAG = 125;
    static final int SMT_DO_PV = 129;
    static final int SMT_DO_CG = 133;
    static final int SMT_DO_CC = 142;
    static final int SMT_DO_DS = 158;
    protected List<byte[]> templates;

    protected DLDG6789File() {
    }

    public DLDG6789File(InputStream in, int requiredTag) throws IOException {
        super(in);
        if (this.dataGroupTag != requiredTag) {
            throw new IllegalArgumentException("Expected " +
                    Hex.intToHexString(requiredTag));
        }
        try {
            TLVInputStream tlvIn = new TLVInputStream(in);
            int bioInfoGroupTemplateTag = tlvIn.readTag();
            if (bioInfoGroupTemplateTag != 32609) {
                throw new IllegalArgumentException("Expected tag BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG (" + Integer.toHexString(32609) + ") in CBEFF structure, found " + Integer.toHexString(bioInfoGroupTemplateTag));
            }
            tlvIn.readLength();
            int bioInfoCountTag = tlvIn.readTag();
            if (bioInfoCountTag != 2) {
                throw new IllegalArgumentException("Expected tag BIOMETRIC_INFO_COUNT_TAG (" + Integer.toHexString(2) + ") in CBEFF structure, found " + Integer.toHexString(bioInfoCountTag));
            }
            int tlvBioInfoCountLength = tlvIn.readLength();
            if (tlvBioInfoCountLength != 1) {
                throw new IllegalArgumentException("BIOMETRIC_INFO_COUNT should have length 1, found length " + tlvBioInfoCountLength);
            }
            int bioInfoCount = tlvIn.readValue()[0] & 0xFF;
            for (int i = 0; i < bioInfoCount; i++) {
                readBIT(tlvIn, i);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Could not decode: " + e.toString());
        }
        this.isSourceConsistent = false;
    }

    private void readBIT(TLVInputStream tlvIn, int templateIndex) throws IOException {
        int bioInfoTemplateTag = tlvIn.readTag();
        if (bioInfoTemplateTag != 32608) {
            throw new IllegalArgumentException("Expected tag BIOMETRIC_INFORMATION_TEMPLATE_TAG (" + Integer.toHexString(32608) + "), found " + Integer.toHexString(bioInfoTemplateTag));
        }
        tlvIn.readLength();

        int headerTemplateTag = tlvIn.readTag();
        int headerTemplateLength = tlvIn.readLength();

        if (headerTemplateTag == 125) {

            readStaticallyProtectedBIT(headerTemplateTag, headerTemplateLength, templateIndex, tlvIn);
        } else if ((headerTemplateTag & 0xA0) == 160) {
            readBHT(headerTemplateTag, headerTemplateLength, templateIndex, tlvIn);
            readBiometricDataBlock(tlvIn);
        } else {
            throw new IllegalArgumentException("Unsupported template tag: " + Integer.toHexString(headerTemplateTag));
        }
    }


    private void readBHT(int headerTemplateTag, int headerTemplateLength, int templateIndex, TLVInputStream tlvIn) throws IOException {
        int expectedBioHeaderTemplateTag = -95 + templateIndex & 0xFF;
        if (headerTemplateTag != expectedBioHeaderTemplateTag) {
            String warning = "Expected tag BIOMETRIC_HEADER_TEMPLATE_TAG (" + Integer.toHexString(expectedBioHeaderTemplateTag) + "), found " + Integer.toHexString(headerTemplateTag);
            System.out.println(warning);
        }
        tlvIn.skip(headerTemplateLength);
    }


    private void readStaticallyProtectedBIT(int tag, int length, int templateIndex, TLVInputStream tlvIn) throws IOException {
        TLVInputStream tlvBHTIn = new TLVInputStream(new ByteArrayInputStream(decodeSMTValue(tlvIn)));
        int headerTemplateTag = tlvBHTIn.readTag();
        int headerTemplateLength = tlvBHTIn.readLength();
        readBHT(headerTemplateTag, headerTemplateLength, templateIndex, tlvBHTIn);
        TLVInputStream tlvBiometricDataBlockIn = new TLVInputStream(new ByteArrayInputStream(decodeSMTValue(tlvIn)));
        readBiometricDataBlock(tlvBiometricDataBlockIn);
    }

    private byte[] decodeSMTValue(TLVInputStream tlvIn) throws IOException {
        int doTag = tlvIn.readTag();
        int doLength = tlvIn.readLength();
        switch (doTag) {

            case 129, 133:
                return tlvIn.readValue();

            case 142:
                tlvIn.skip(doLength);

            case 158:
                tlvIn.skip(doLength);
                break;
        }
        return null;
    }

    private void readBiometricDataBlock(TLVInputStream tlvIn) throws IOException {
        int bioDataBlockTag = tlvIn.readTag();
        if (bioDataBlockTag != 24366 &&
                bioDataBlockTag != 32558) {
            throw new IllegalArgumentException("Expected tag BIOMETRIC_DATA_BLOCK_TAG (" + Integer.toHexString(24366) + ") or BIOMETRIC_DATA_BLOCK_TAG_ALT (" + Integer.toHexString(32558) + "), found " + Integer.toHexString(bioDataBlockTag));
        }
        int length = tlvIn.readLength();
        readBiometricData((InputStream) tlvIn, length);
    }


    protected void readBiometricData(InputStream in, int length) throws IOException {
        DataInputStream dataIn = new DataInputStream(in);
        byte[] data = new byte[length];
        dataIn.readFully(data);
        if (this.templates == null) this.templates = (List) new ArrayList<Byte>();
        this.templates.add(data);
    }

    public int getTag() {
        return this.dataGroupTag;
    }

    public abstract byte[] getEncoded();

    public abstract String toString();
}