package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;


public class DLDG11File
        extends DLDataGroup {
    private static final short CATEGORIES_INFO_TAG = 32611;
    private List<CategoryInfo> categories = new ArrayList<>();


    public DLDG11File(List<CategoryInfo> categories) {
        this.categories.addAll(categories);
    }


    public DLDG11File(InputStream in) throws IOException {
        TLVInputStream tlvIn = new TLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != 109 && tag != 98) {
            throw new IllegalArgumentException("Expected EF_DG11_TAG or EF_DG11_TAG_ALT");
        }
        this.isSourceConsistent = false;

        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject categoryObject = mainObject
                .getSubObject(32611);

        BERTLVObject numObject = categoryObject
                .getSubObject(2);
        int totalCat = ((byte[]) numObject.getValue())[0];

        for (int i = 0; i < totalCat; i++) {
            BERTLVObject catObject = categoryObject.getChildByIndex(i + 1);
            this.categories.add(new CategoryInfo(new ByteArrayInputStream(
                    catObject.getEncoded())));
        }
    }

    public int getTag() {
        return 109;
    }

    public String toString() {
        return "DG11File: " + this.categories;
    }


    public List<CategoryInfo> getCategories() {
        return new ArrayList<>(this.categories);
    }


    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }

        try {
            BERTLVObject num = new BERTLVObject(2,
                    new byte[]{(byte) this.categories.size()});

            BERTLVObject cats = new BERTLVObject(32611, num);
            for (CategoryInfo c : this.categories) {
                cats.addSubObject(c.getTLVObject());
            }
            cats.reconstructLength();
            BERTLVObject result = new BERTLVObject(109, cats);
            this.sourceObject = result;
            result.reconstructLength();
            this.isSourceConsistent = true;
            return result.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}