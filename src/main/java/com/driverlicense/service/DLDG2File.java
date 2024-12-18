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


public class DLDG2File
        extends DLDataGroup {
    private static final short TAGS_TAG = 92;
    private static final short GENDER_TAG = 24373;
    private static final short HEIGHT_TAG = 24420;
    private static final short WEIGHT_TAG = 24421;
    private static final short EYE_TAG = 24422;
    private static final short HAIR_TAG = 24423;
    private static final short POB_TAG = 24337;
    private static final short POR_TAG = 24386;
    public int gender = 0;

    public static final int MALE = 1;

    public static final int FEMALE = 2;

    public int height = 0;

    public int weight = 0;

    public String eye = null;

    public String hair = null;

    public String pob = null;

    public String por = null;

    private List<Integer> tagList = new ArrayList<>();


    public DLDG2File(int gender, int height, int weight, String eye, String hair, String pob, String por) {
        this.gender = gender;
        this.height = height;
        this.weight = weight;
        this.eye = eye;
        this.hair = hair;
        this.pob = pob;
        this.por = por;
        if (gender > 0) {
            this.tagList.add(24373);
        }
        if (height > 0) {
            this.tagList.add(24420);
        }
        if (weight > 0) {
            this.tagList.add(24421);
        }
        if (eye != null) {
            this.tagList.add(24422);
        }
        if (hair != null) {
            this.tagList.add(24423);
        }
        if (pob != null) {
            this.tagList.add(24337);
        }
        if (por != null) {
            this.tagList.add(24386);
        }
    }


    public DLDG2File(InputStream in) throws IOException {
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != 107) {
            throw new IllegalArgumentException("Expected EF_DG2_TAG");
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
                case 24373:
                    this.gender = value[0];
                    break;
                case 24420:
                    this.height = Integer.parseInt(Hex.bytesToHexString(value));
                    break;
                case 24421:
                    this.weight = Integer.parseInt(Hex.bytesToHexString(value));
                    break;
                case 24422:
                    this.eye = new String(value);
                    break;
                case 24423:
                    this.hair = new String(value);
                    break;
                case 24337:
                    this.pob = new String(value);
                    break;
                case 24386:
                    this.por = new String(value);
                    break;
                default:
                    throw new IOException("Unexpected tag.");
            }
        }
    }


    public int getTag() {
        return 107;
    }

    public String toString() {
        return "DG2File: Gender: " + this.gender + " Height: " + this.height +
                " Weight: " + this.weight + " Eye: " + this.eye + " Hair: " + this.hair +
                " Pob: " + this.pob + " Por: " + this.por;
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
                    case 24373:
                        value = new byte[]{(byte) this.gender};
                        break;
                    case 24420:
                        value = Hex.hexStringToBytes(String.valueOf(this.height));
                        if (value.length == 1) {
                            byte[] t = new byte[2];
                            t[1] = value[0];
                            value = t;
                        }
                        break;
                    case 24421:
                        value = Hex.hexStringToBytes(String.valueOf(this.weight));
                        if (value.length == 1) {
                            byte[] t = new byte[2];
                            t[1] = value[0];
                            value = t;
                        }
                        break;
                    case 24422:
                        value = this.eye.getBytes();
                        break;
                    case 24423:
                        value = this.hair.getBytes();
                        break;
                    case 24337:
                        value = this.pob.getBytes();
                        break;
                    case 24386:
                        value = this.por.getBytes();
                        break;
                }


                BERTLVObject o = new BERTLVObject(tag, value);
                objs.add(o);
            }

            BERTLVObject result = new BERTLVObject(107,
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