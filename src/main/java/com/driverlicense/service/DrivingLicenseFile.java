package com.driverlicense.service;


import com.driverlicense.tlv.BERTLVObject;

import java.io.IOException;

public abstract class DrivingLicenseFile {
    public static final int EF_COM_TAG = 96;
    public static final int EF_DG1_TAG = 97;
    public static final int EF_DG2_TAG = 107;
    public static final int EF_DG3_TAG = 108;
    public static final int EF_DG4_TAG = 101;
    public static final int EF_DG5_TAG = 103;
    public static final int EF_DG6_TAG = 117;
    public static final int EF_DG7_TAG = 99;
    public static final int EF_DG8_TAG = 118;
    public static final int EF_DG9_TAG = 112;
    public static final int EF_DG10_TAG = 63;
    public static final int EF_DG11_TAG = 109;
    public static final int EF_DG11_TAG_ALT = 98;
    public static final int EF_DG12_TAG = 113;
    public static final int EF_DG13_TAG = 111;
    public static final int EF_DG14_TAG = 110;
    public static final int EF_SOD_TAG = 119;
    BERTLVObject sourceObject;
    boolean isSourceConsistent;

    public abstract byte[] getEncoded() throws IOException;

    public static short lookupFIDByTag(int tag) {
        return switch (tag) {
            case 96 -> 30;
            case 97 -> 1;
            case 107 -> 2;
            case 108 -> 3;
            case 101 -> 4;
            case 103 -> 5;
            case 117 -> 6;
            case 99 -> 7;
            case 118 -> 8;
            case 112 -> 9;
            case 63 -> 10;
            case 98, 109 -> 11;
            case 113 -> 12;
            case 111 -> 13;
            case 110 -> 14;
            case 119 -> 29;
            default -> throw new NumberFormatException("Unknown tag " +
                    Integer.toHexString(tag));
        };
    }


    public static byte lookupSIDByTag(int tag) {
        return switch (tag) {
            case 96 -> 30;
            case 97 -> 1;
            case 107 -> 2;
            case 108 -> 3;
            case 101 -> 4;
            case 103 -> 5;
            case 117 -> 6;
            case 99 -> 7;
            case 118 -> 8;
            case 112 -> 9;
            case 63 -> 10;
            case 98, 109 -> 11;
            case 113 -> 12;
            case 111 -> 13;
            case 110 -> 14;
            case 119 -> 29;
            default -> throw new NumberFormatException("Unknown tag " +
                    Integer.toHexString(tag));
        };
    }


    public static int lookupDataGroupNumberByTag(int tag) {
        return switch (tag) {
            case 97 -> 1;
            case 107 -> 2;
            case 108 -> 3;
            case 101 -> 4;
            case 103 -> 5;
            case 117 -> 6;
            case 99 -> 7;
            case 118 -> 8;
            case 112 -> 9;
            case 63 -> 10;
            case 98, 109 -> 11;
            case 113 -> 12;
            case 111 -> 13;
            case 110 -> 14;
            default -> throw new NumberFormatException("Unknown tag " +
                    Integer.toHexString(tag));
        };
    }


    public static int lookupDataGroupNumberByFID(short fid) {
        return switch (fid) {
            case 1 -> 1;
            case 2 -> 2;
            case 3 -> 3;
            case 4 -> 4;
            case 5 -> 5;
            case 6 -> 6;
            case 7 -> 7;
            case 8 -> 8;
            case 9 -> 9;
            case 10 -> 10;
            case 11 -> 11;
            case 12 -> 12;
            case 13 -> 13;
            case 14 -> 14;
            default -> -1;
        };
    }


    public static int lookupTagByDataGroupNumber(int num) {
        return switch (num) {
            case 1 -> 97;
            case 2 -> 107;
            case 3 -> 108;
            case 4 -> 101;
            case 5 -> 103;
            case 6 -> 117;
            case 7 -> 99;
            case 8 -> 118;
            case 9 -> 112;
            case 10 -> 63;
            case 11 -> 109;
            case 12 -> 113;
            case 13 -> 111;
            case 14 -> 110;
            default -> throw new NumberFormatException("Unknown DG" + num);
        };
    }
}