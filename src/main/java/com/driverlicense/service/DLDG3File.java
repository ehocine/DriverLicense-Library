package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;


public class DLDG3File
        extends DLDataGroup {
    private static final short TAGS_TAG = 92;
    private static final short ADMIN_NUMBER_TAG = 24424;
    private static final short DOCUMENT_DISC_TAG = 24425;
    private static final short DATA_DISC_TAG = 24429;
    private static final short ID_NUMBER_TAG = 24426;
    public String adminNumber = null;

    public int documentDisc = 0;

    public int dataDisc = 0;

    public byte[] idNumber = null;

    private List<Integer> tagList = new ArrayList<>();


    public DLDG3File(String adminNumber, int documentDisc, int dataDisc, byte[] idNumber) {
        this.adminNumber = adminNumber;
        this.documentDisc = documentDisc;
        this.dataDisc = dataDisc;
        this.idNumber = idNumber;
        if (adminNumber != null) {
            this.tagList.add(24424);
        }
        if (documentDisc > 0) {
            this.tagList.add(24425);
        }
        if (dataDisc > 0) {
            this.tagList.add(24429);
        }
        if (idNumber != null) {
            this.tagList.add(24426);
        }
    }


    public DLDG3File(InputStream in) throws IOException {
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != 108) {
            throw new IllegalArgumentException("Expected EF_DG3_TAG");
        }
        this.isSourceConsistent = false;

        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject tagsObject = mainObject.getSubObject(92);

        byte[] tags = (byte[]) tagsObject.getValue();
        String tagString = Hex.bytesToHexString(tags);

        for (int i = 0; i < tags.length / 2; i++) {
            String num = tagString.substring(i * 4, (i + 1) * 4);
            short tagNum = Hex.hexStringToShort(num);
            this.tagList.add((int) tagNum);
            BERTLVObject o = mainObject.getSubObject(tagNum);
            byte[] value = (byte[]) o.getValue();
            switch (tagNum) {
                case 24424:
                    this.adminNumber = new String(value);
                    break;
                case 24425:
                    this.documentDisc = value[0];
                    break;
                case 24429:
                    this.dataDisc = value[0];
                    break;
                case 24426:
                    this.idNumber = value;
                    break;
                default:
                    throw new IOException("Unexpected tag.");
            }
        }
    }


    public int getTag() {
        return 108;
    }

    public String toString() {
        return "DG3File:  Admin#: " + this.adminNumber + " Document: " +
                this.documentDisc + " Data: " + this.dataDisc + " Id#: " +
                Hex.bytesToHexString(this.idNumber);
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            Iterator<Integer> it = this.tagList.iterator();
            String tagValues = "";
            Vector<BERTLVObject> objs = new Vector<BERTLVObject>();
            while (it.hasNext()) {
                short tag = ((Integer) it.next()).shortValue();
                tagValues = String.valueOf(tagValues) + Hex.shortToHexString(tag);
                byte[] value = (byte[]) null;
                switch (tag) {
                    case 24424:
                        value = this.adminNumber.getBytes();
                        break;
                    case 24425:
                        value = new byte[]{(byte) this.documentDisc};
                        break;
                    case 24429:
                        value = new byte[]{(byte) this.dataDisc};
                        break;
                    case 24426:
                        value = new byte[this.idNumber.length];
                        System.arraycopy(this.idNumber, 0, value, 0, this.idNumber.length);
                        break;
                }


                BERTLVObject o = new BERTLVObject(tag, value);
                objs.add(o);
            }

            BERTLVObject result = new BERTLVObject(108,
                    new BERTLVObject(92, Hex.hexStringToBytes(tagValues)));

            for (BERTLVObject obj : objs) {
                result.addSubObject(obj);
            }
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