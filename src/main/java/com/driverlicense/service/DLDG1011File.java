package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.IOException;
import java.io.InputStream;


public class DLDG1011File
        extends DLDataGroup {
    private byte[] contents = null;
    private int requiredTag = 0;


    public DLDG1011File(byte[] data, int requiredTag) {
        this.contents = data;
        this.requiredTag = requiredTag;
    }


    public DLDG1011File(InputStream in, int requiredTag) throws IOException {
        this.requiredTag = requiredTag;
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != requiredTag)
            throw new IllegalArgumentException("Expected " + Hex.intToHexString(requiredTag));
        this.isSourceConsistent = false;
        tlvIn.readLength();
        this.contents = tlvIn.readValue();
    }

    public int getTag() {
        return this.requiredTag;
    }


    public String toString() {
        return "DG1011File: tag " + Hex.intToHexString(this.requiredTag) + " bytes " + this.contents.length;
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            BERTLVObject result = new BERTLVObject(this.requiredTag, this.contents);
            result.reconstructLength();
            this.sourceObject = result;
            this.isSourceConsistent = true;
            return result.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}