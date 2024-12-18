package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import com.driverlicense.service.categories.DrivingCategory;
import com.driverlicense.service.categories.LimitationCode;
import com.driverlicense.service.categories.Sign;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.StringTokenizer;

public class CategoryInfo {
    private static final short CATEGORY_TAG = 135;
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyyMMdd");
    static boolean properISOFormat = false;
    private DrivingCategory category;
    private List<LimitationCode> code;
    private byte[] contents;
    public Date doe;
    public Date doi;
    private Sign sign;
    private String value;

    public CategoryInfo(byte[] bArr) {
        this.contents = bArr;
        decodeContents(bArr);
    }

    public CategoryInfo(DrivingCategory drivingCategory, Date date, Date date2, List<LimitationCode> list, Sign sign2, String str) {
        this.contents = null;
        this.category = drivingCategory;
        this.doi = date;
        this.doe = date2;
        this.code = list;
        this.sign = sign2;
        this.value = str;
        decodeContents(getContents());
    }

    public CategoryInfo(InputStream inputStream) {
        this.contents = null;
        try {
            TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
            int readTag = tLVInputStream.readTag();
            if (readTag == 135) {
                tLVInputStream.readLength();
                byte[] readValue = tLVInputStream.readValue();
                this.contents = readValue;
                decodeContents(readValue);
                return;
            }
            throw new IllegalArgumentException("Expected CATEGORY_TAG (135), found " + readTag);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public BERTLVObject getTLVObject() {
        BERTLVObject bERTLVObject = new BERTLVObject(135, this.contents);
        bERTLVObject.reconstructLength();
        return bERTLVObject;
    }

    public byte[] getEncoded() {
        return getTLVObject().getEncoded();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.category);
        sb.append(";");
        Date date = this.doi;
        String str = "";
        sb.append(date != null ? SDF.format(date) : str);
        sb.append(";");
        Date date2 = this.doe;
        sb.append(date2 != null ? SDF.format(date2) : str);
        sb.append(";");
        Object obj = this.code;
        if (obj == null) {
            obj = str;
        }
        sb.append(obj);
        sb.append(";");
        Object obj2 = this.sign;
        if (obj2 == null) {
            obj2 = str;
        }
        sb.append(obj2);
        sb.append(";");
        String str2 = this.value;
        if (str2 != null) {
            str = str2;
        }
        sb.append(str);
        return sb.toString();
    }

    public byte[] getContents() {
        try {
            if (this.contents == null) {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                byteArrayOutputStream.write((this.category + ";").getBytes());
                Date date = this.doi;
                byteArrayOutputStream.write(date != null ? Hex.hexStringToBytes(SDF.format(date)) : new byte[0]);
                byteArrayOutputStream.write(59);
                Date date2 = this.doe;
                byteArrayOutputStream.write(date2 != null ? Hex.hexStringToBytes(SDF.format(date2)) : new byte[0]);
                byteArrayOutputStream.write(59);
                List<LimitationCode> list = this.code;
                String str = "";
                byteArrayOutputStream.write((list != null ? list.toString() : str).getBytes());
                byteArrayOutputStream.write(59);
                Sign sign2 = this.sign;
                byteArrayOutputStream.write((sign2 != null ? sign2.toString() : str).getBytes());
                byteArrayOutputStream.write(59);
                String str2 = this.value;
                if (str2 != null) {
                    str = str2;
                }
                byteArrayOutputStream.write(str.getBytes());
                this.contents = byteArrayOutputStream.toByteArray();
            }
            return this.contents;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void decodeContents(byte[] bArr) throws IllegalArgumentException {
        Date date;
        Date date2;
        List<LimitationCode> list;
        List<LimitationCode> list2;
        List<LimitationCode> list3;
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        String str = new String(getField(byteArrayInputStream, false));
        checkString(str, true, true, false, 1, 3);
        DrivingCategory drivingCategory = DrivingCategory.categories.get(str);
        if (drivingCategory != null) {
            this.category = drivingCategory;
            String bytesToHexString = Hex.bytesToHexString(getField(byteArrayInputStream, false));
            try {
                Sign sign2 = null;
                if (!bytesToHexString.isEmpty()) {
                    checkString(bytesToHexString, false, true, false, 8, 8);
                    date = SDF.parse(bytesToHexString);
                    if (properISOFormat) {
                        if (this.category.isNotSpecific()) {
                            throw new IllegalArgumentException("Wrong combination of category and dates.");
                        }
                    }
                } else {
                    date = null;
                }
                this.doi = date;
                String bytesToHexString2 = Hex.bytesToHexString(getField(byteArrayInputStream, false));
                try {
                    if (!bytesToHexString2.isEmpty()) {
                        checkString(bytesToHexString2, false, true, false, 8, 8);
                        date2 = SDF.parse(bytesToHexString2);
                        if (properISOFormat) {
                            if (this.category.isNotSpecific()) {
                                throw new IllegalArgumentException("Wrong combination of category and dates.");
                            }
                        }
                    } else {
                        date2 = null;
                    }
                    this.doe = date2;
                    boolean z = date2 == null;
                    Date date3 = this.doi;
                    if (z != (date3 == null) || (date3 != null && !date3.before(date2))) {
                        throw new IllegalArgumentException("Wrong dates (null or issue after expiry).");
                    }
                    String str2 = new String(getField(byteArrayInputStream, false));
                    checkString(str2, true, true, true, 0, properISOFormat ? 5 : -1);
                    ArrayList arrayList = new ArrayList();
                    StringTokenizer stringTokenizer = new StringTokenizer(str2, "+");
                    while (stringTokenizer.hasMoreTokens()) {
                        String nextToken = stringTokenizer.nextToken();
                        if (!"".equals(nextToken)) {
                            LimitationCode limitationCode = LimitationCode.limitationCodes.get(nextToken);
                            if (limitationCode != null) {
                                arrayList.add(limitationCode);
                            } else {
                                throw new IllegalArgumentException("Code " + nextToken + " unknown.");
                            }
                        }
                    }
                    if (!arrayList.isEmpty()) {
                        this.code = arrayList;
                    }
                    String str3 = new String(getField(byteArrayInputStream, false));
                    checkString(str3, false, false, true, 0, 2);
                    if (!str3.isEmpty()) {
                        sign2 = Sign.signs.get(str3);
                        if (sign2 == null) {
                            throw new IllegalArgumentException("Sign " + str3 + " unknown.");
                        } else if (properISOFormat && ((list3 = this.code) == null || !list3.get(0).needSign())) {
                            throw new IllegalArgumentException("Invalid combination of code and sign.");
                        }
                    } else if (properISOFormat && (list2 = this.code) != null && list2.get(0).needSign()) {
                        throw new IllegalArgumentException("Invalid combination of code and sign.");
                    }
                    this.sign = sign2;
                    String str4 = new String(getField(byteArrayInputStream, true));
                    checkString(str4, true, true, true, 0, 30);
                    if (!str4.isEmpty()) {
                        this.value = str4;
                        if (properISOFormat) {
                            List<LimitationCode> list4 = this.code;
                            if (list4 == null || !list4.get(0).needValue()) {
                                throw new IllegalArgumentException("Invalid combination of code and value.");
                            }
                        }
                    } else if (properISOFormat && (list = this.code) != null && list.get(0).needValue()) {
                        throw new IllegalArgumentException("Invalid combination of code and value.");
                    }
                } catch (ParseException unused) {
                    throw new IllegalArgumentException("Badly formatted date: " + bytesToHexString2 + ".");
                }
            } catch (ParseException unused2) {
                throw new IllegalArgumentException("Badly formatted date: " + bytesToHexString + ".");
            }
        } else {
            throw new IllegalArgumentException("Unknown category: " + str + ".");
        }
    }

    public DrivingCategory getCategory() {
        return this.category;
    }

    public Date getDoI() {
        return this.doi;
    }

    public Date getDoE() {
        return this.doe;
    }

    public List<LimitationCode> getCode() {
        return this.code;
    }

    public Sign getSign() {
        return this.sign;
    }

    public String getValue() {
        return this.value;
    }

    private byte[] getField(ByteArrayInputStream byteArrayInputStream, boolean z) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int i = z ? -1 : 59;
        int read = byteArrayInputStream.read();
        while (read != i) {
            byteArrayOutputStream.write(read);
            read = byteArrayInputStream.read();
        }
        return byteArrayOutputStream.toByteArray();
    }

    private void checkString(String str, boolean z, boolean z2, boolean z3, int i, int i2) throws IllegalArgumentException {
        if (str.length() < i || (i2 >= 0 && str.length() > i2)) {
            throw new IllegalArgumentException();
        }
        int i3 = 0;
        while (i3 < str.length()) {
            char charAt = str.charAt(i3);
            if ((!Character.isLetter(charAt) || z) && (!Character.isDigit(charAt) || z2)) {
                i3++;
            } else {
                throw new IllegalArgumentException();
            }
        }
    }
}
