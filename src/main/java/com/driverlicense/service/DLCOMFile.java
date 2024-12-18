package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class DLCOMFile extends DrivingLicenseFile {
    private static final int IDL_VERSION = 1;
    private static final int SOI_TAG = 134;
    private static final int TAG_LIST_TAG = 92;
    private static final int VERSION_LDS_TAG = 24321;
    private final int majorVersion;
    private final int releaseVersion;
    private SecurityObjectIndicator[] sois;
    private final List<Integer> tagList;

    public int getTag() {
        return 96;
    }

    public DLCOMFile(int i, int i2, List<Integer> list, SecurityObjectIndicator[] securityObjectIndicatorArr) {
        if (list == null) {
            throw new IllegalArgumentException();
        } else if (i == 1) {
            this.majorVersion = i;
            this.releaseVersion = i2;
            ArrayList arrayList = new ArrayList();
            this.tagList = arrayList;
            arrayList.addAll(list);
            this.sois = securityObjectIndicatorArr == null ? new SecurityObjectIndicator[0] : securityObjectIndicatorArr;
        } else {
            throw new IllegalArgumentException("Wrong major version: " + i);
        }
    }

    public DLCOMFile(int i, int i2, List<Integer> list) {
        this(i, i2, list, null);
    }

    public DLCOMFile(InputStream inputStream) throws IOException {
        TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
        int readTag = tLVInputStream.readTag();
        if (readTag == 96) {
            tLVInputStream.readLength();
            BERTLVObject bERTLVObject = new BERTLVObject(readTag, tLVInputStream.readValue());
            BERTLVObject subObject = bERTLVObject.getSubObject(VERSION_LDS_TAG);
            BERTLVObject subObject2 = bERTLVObject.getSubObject(92);
            BERTLVObject subObject3 = bERTLVObject.getSubObject(134);
            byte[] bArr = (byte[]) subObject.getValue();
            if (bArr.length == 2) {
                this.majorVersion = bArr[0];
                this.releaseVersion = bArr[1];
                byte[] bArr2 = (byte[]) subObject2.getValue();
                this.tagList = new ArrayList<>();
                for (byte b : bArr2) {
                    this.tagList.add(b & 255);
                }
                if (subObject3 != null) {
                    DERSet dERSet = (DERSet) new ASN1InputStream((byte[]) subObject3.getValue()).readObject();
                    this.sois = new SecurityObjectIndicator[dERSet.size()];
                    for (int i = 0; i < dERSet.size(); i++) {
                        DERSequence dERSequence = (DERSequence) dERSet.getObjectAt(i);
                        SecurityObjectIndicator securityObjectIndicator = new SecurityObjectIndicator(dERSequence);
                        if (securityObjectIndicator.getDGNumber() == 13) {
                            this.sois[i] = new SecurityObjectIndicatorDG13(dERSequence);
                        } else if (securityObjectIndicator.getDGNumber() == 14) {
                            this.sois[i] = new SecurityObjectIndicatorDG14(dERSequence);
                        } else {
                            this.sois[i] = securityObjectIndicator;
                        }
                    }
                    return;
                }
                this.sois = new SecurityObjectIndicator[0];
                return;
            }
            throw new IllegalArgumentException("Wrong length of LDS version object");
        }
        throw new IOException("Wrong tag!");
    }

    public String getVersion() {
        return this.majorVersion + "." + this.releaseVersion;
    }

    public List<Integer> getTagList() {
        return this.tagList;
    }

    public void insertTag(Integer num) {
        if (!this.tagList.contains(num)) {
            this.tagList.add(num);
        }
    }

    public SecurityObjectIndicator[] getSOIArray() {
        return this.sois;
    }

    public void setSOIArray(SecurityObjectIndicator[] securityObjectIndicatorArr) {
        this.sois = securityObjectIndicatorArr;
    }

    public byte[] getEncoded() {
        BERTLVObject[] bERTLVObjectArr;
        try {
            BERTLVObject bERTLVObject = new BERTLVObject(VERSION_LDS_TAG, new byte[]{(byte) this.majorVersion, (byte) this.releaseVersion});
            byte[] bArr = new byte[this.tagList.size()];
            for (int i = 0; i < this.tagList.size(); i++) {
                bArr[i] = (byte) this.tagList.get(i).intValue();
            }
            BERTLVObject bERTLVObject2 = new BERTLVObject(92, bArr);
            SecurityObjectIndicator[] securityObjectIndicatorArr = this.sois;
            if (securityObjectIndicatorArr != null) {
                if (securityObjectIndicatorArr.length != 0) {
                    DERSequence[] dERSequenceArr = new DERSequence[securityObjectIndicatorArr.length];
                    int i2 = 0;
                    while (true) {
                        SecurityObjectIndicator[] securityObjectIndicatorArr2 = this.sois;
                        if (i2 >= securityObjectIndicatorArr2.length) {
                            break;
                        }
                        dERSequenceArr[i2] = securityObjectIndicatorArr2[i2].getDERSequence();
                        i2++;
                    }
                    bERTLVObjectArr = new BERTLVObject[]{bERTLVObject, bERTLVObject2, new BERTLVObject(134, new DERSet((ASN1Encodable[]) dERSequenceArr).getEncoded())};
                    BERTLVObject bERTLVObject3 = new BERTLVObject(96, bERTLVObjectArr);
                    bERTLVObject3.reconstructLength();
                    return bERTLVObject3.getEncoded();
                }
            }
            bERTLVObjectArr = new BERTLVObject[]{bERTLVObject, bERTLVObject2};
            BERTLVObject bERTLVObject32 = new BERTLVObject(96, bERTLVObjectArr);
            bERTLVObject32.reconstructLength();
            return bERTLVObject32.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("COMFile: ");
        stringBuffer.append("Version ").append(this.majorVersion).append(".").append(this.releaseVersion);
        stringBuffer.append(", ");
        stringBuffer.append("[");
        int size = this.tagList.size();
        int i = 0;
        for (Integer intValue : this.tagList) {
            int intValue2 = intValue;
            stringBuffer.append("DG").append(DrivingLicenseFile.lookupDataGroupNumberByTag(intValue2));
            if (i < size - 1) {
                stringBuffer.append(", ");
            }
            i++;
        }
        stringBuffer.append("]");
        for (SecurityObjectIndicator securityObjectIndicator : this.sois) {
            stringBuffer.append(securityObjectIndicator.toString());
        }
        return stringBuffer.toString();
    }

    public List<Integer> getDGNumbers() {
        ArrayList arrayList = new ArrayList();
        for (Integer intValue : this.tagList) {
            arrayList.add((int) DrivingLicenseFile.lookupDataGroupNumberByTag(intValue));
        }
        return arrayList;
    }
}
