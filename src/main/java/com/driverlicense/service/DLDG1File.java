package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class DLDG1File extends DLDataGroup {
    private static final short CATEGORIES_INFO_TAG = 32611;
    private static final short DEMOGRAPHIC_INFO_TAG = 24351;
    private final List<CategoryInfo> categories;
    private final DriverDemographicInfo driverInfo;

    public int getTag() {
        return 97;
    }

    public DLDG1File(DriverDemographicInfo driverDemographicInfo, List<CategoryInfo> list) {
        ArrayList arrayList = new ArrayList();
        this.categories = arrayList;
        this.driverInfo = driverDemographicInfo;
        arrayList.addAll(list);
    }

    public DLDG1File(InputStream inputStream) throws IOException {
        this.categories = new ArrayList<>();
        TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
        int readTag = tLVInputStream.readTag();
        if (readTag == 97) {
            int i = 0;
            this.isSourceConsistent = false;
            tLVInputStream.readLength();
            BERTLVObject bERTLVObject = new BERTLVObject(readTag, tLVInputStream.readValue());
            BERTLVObject subObject = bERTLVObject.getSubObject(24351);
            BERTLVObject subObject2 = bERTLVObject.getSubObject(32611);
            this.driverInfo = new DriverDemographicInfo(new ByteArrayInputStream((byte[]) subObject.getValue()));
            byte b = ((byte[]) subObject2.getSubObject(2).getValue())[0];
            while (i < b) {
                i++;
                this.categories.add(new CategoryInfo(new ByteArrayInputStream(subObject2.getChildByIndex(i).getEncoded())));
            }
            return;
        }
        throw new IllegalArgumentException("Expected EF_DG1_TAG");
    }

    public DriverDemographicInfo getDriverInfo() {
        return this.driverInfo;
    }

    public String toString() {
        return "DG1File: " + this.driverInfo.toString() + "\n      " + this.categories;
    }

    public List<CategoryInfo> getCategories() {
        ArrayList arrayList = new ArrayList();
        arrayList.addAll(this.categories);
        return arrayList;
    }

    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            BERTLVObject bERTLVObject = new BERTLVObject(97, new BERTLVObject(24351, this.driverInfo.getEncoded()));
            BERTLVObject bERTLVObject2 = new BERTLVObject(32611, new BERTLVObject(2, new byte[]{(byte) this.categories.size()}));
            for (CategoryInfo tLVObject : this.categories) {
                bERTLVObject2.addSubObject(tLVObject.getTLVObject());
            }
            bERTLVObject2.reconstructLength();
            bERTLVObject.addSubObject(bERTLVObject2);
            this.sourceObject = bERTLVObject;
            bERTLVObject.reconstructLength();
            this.isSourceConsistent = true;
            return bERTLVObject.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
