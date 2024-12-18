package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public class FacePortrait {
    public final int TYPE_JPEG = 3;

    public final int TYPE_JPEG2000 = 4;

    public final int TYPE_WSQ = 63;

    private final short INSTANCE_TAG = 162;

    private final short TIME_TAG = 136;

    private final short TYPE_TAG = 137;

    private final short DATA_TAG = 24384;

    private byte[] portraitContents = null;

    private String mimeImageType = null;

    private int imageType = 0;

    private String timeStamp = null;


    public FacePortrait(byte[] portraitContents, String mimeType, String time) {
        if ("image/jpeg".equals(mimeType)) {
            this.imageType = 3;
        } else if ("image/jpeg2000".equals(mimeType)) {
            this.imageType = 4;
        } else {
            throw new IllegalArgumentException("Wrong image type.");
        }
        this.mimeImageType = mimeType;
        this.timeStamp = Objects.requireNonNullElse(time, "000000");
        this.portraitContents = portraitContents;
    }


    public FacePortrait(InputStream in) throws IOException {
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != 162) {
            throw new IllegalArgumentException("Expected INSTANCE_TAG");
        }
        tlvIn.readLength();

        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);

        BERTLVObject timeObj = mainObject.getSubObject(136);
        BERTLVObject typeObj = mainObject.getSubObject(137);
        BERTLVObject dataObj = mainObject.getSubObject(24384);

        byte[] value = (byte[]) timeObj.getValue();
        this.timeStamp = Hex.bytesToHexString(value);
        this.imageType = ((byte[]) typeObj.getValue())[0];
        if (this.imageType == 3) {
            this.mimeImageType = "image/jpeg";
        } else if (this.imageType == 4) {
            this.mimeImageType = "image/jpeg2000";
        } else {
            throw new IOException("Wrong image type.");
        }
        this.portraitContents = (byte[]) dataObj.getValue();
    }


    public BERTLVObject getTLVObject() {
        BERTLVObject result = new BERTLVObject(162, new BERTLVObject(
                136, Hex.hexStringToBytes(this.timeStamp)));
        result.addSubObject(new BERTLVObject(137,
                new byte[]{(byte) this.imageType}));
        result.addSubObject(new BERTLVObject(24384, this.portraitContents));
        result.reconstructLength();
        return result;
    }


    public byte[] getEncoded() {
        return getTLVObject().getEncoded();
    }


    public byte[] getImage() {
        return this.portraitContents;
    }


    public String getMimeType() {
        return this.mimeImageType;
    }


    public String getDate() {
        return this.timeStamp;
    }
}