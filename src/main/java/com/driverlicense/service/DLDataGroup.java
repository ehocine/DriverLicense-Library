package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;

import java.io.IOException;
import java.io.InputStream;


public abstract class DLDataGroup
        extends DrivingLicenseFile {
    protected int dataGroupTag;
    protected int dataGroupLength;

    DLDataGroup() {
    }

    protected DLDataGroup(InputStream in) {
        try {
            TLVInputStream tlvIn = new TLVInputStream(in);
            this.dataGroupTag = tlvIn.readTag();
            this.dataGroupLength = tlvIn.readLength();
        } catch (IOException ioe) {
            throw new IllegalArgumentException("Could not decode: " + ioe);
        }
    }

    DLDataGroup(BERTLVObject object) {
                this.sourceObject = object;
                this.isSourceConsistent = true;
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        return null;
    }

    public String toString() {
        if (this.isSourceConsistent) {
            return this.sourceObject.toString();
        }
        return super.toString();
    }

    public int getTag() {
        return this.dataGroupTag;
    }

    public int getLength() {
        return this.dataGroupLength;
    }
}


/* Location:              /Users/elhadjhocine/Downloads/isodl-20110215/lib/drivinglicense.jar!/org/isodl/service/DataGroup.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */