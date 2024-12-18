package com.driverlicense.service;

import net.sf.scuba.util.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;


public class DriverDemographicInfo {
    public String familyName = null;

    public String givenNames = null;

    public String dob = null;

    public String doi = null;

    public String doe = null;

    public String country = null;

    public String authority = null;

    public String number = null;


    public DriverDemographicInfo(String familyName, String givenNames, String dob, String doi, String doe, String country, String authority, String number) {
        this.familyName = familyName;
        this.givenNames = givenNames;
        this.dob = dob;
        this.doi = doi;
        this.doe = doe;
        this.country = country;
        this.authority = authority;
        this.number = number;
    }


    public DriverDemographicInfo(InputStream in) throws IOException {
        int len = 0;
        byte[] t = (byte[]) null;
        len = in.read();
        t = new byte[len];
        in.read(t);
        this.familyName = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        this.givenNames = new String(t);
        t = new byte[4];
        in.read(t);
        this.dob = Hex.bytesToHexString(t);
        t = new byte[4];
        in.read(t);
        this.doi = Hex.bytesToHexString(t);
        t = new byte[4];
        in.read(t);
        this.doe = Hex.bytesToHexString(t);
        t = new byte[3];
        in.read(t);
        this.country = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        this.authority = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        this.number = new String(t);
    }


    public String toString() {
        return String.valueOf(this.familyName) + "<" + this.givenNames + "<" + this.dob + "<" + this.doi + "<" +
                this.doe + "<" + this.country + "<" + this.authority + "<" + this.number;
    }


    public byte[] getEncoded() {
        String[] data = {this.familyName, this.givenNames, this.dob, this.doi, this.doe, this.country,
                this.authority, this.number};
        int total = 0;
        byte b1;
        int i;
        String[] arrayOfString1;
        for (i = (arrayOfString1 = data).length, b1 = 0; b1 < i; ) {
            String s = arrayOfString1[b1];
            total += s.length() + 1;
            b1++;
        }

        total -= 16;
        byte[] result = new byte[total];
        int offset = 0;
        byte b2;
        int j;
        String[] arrayOfString2;
        for (j = (arrayOfString2 = data).length, b2 = 0; b2 < j; ) {
            String s = arrayOfString2[b2];
            if (!Objects.equals(s, this.dob) && !Objects.equals(s, this.doi) && !Objects.equals(s, this.doe) && !Objects.equals(s, this.country)) {
                result[offset++] = (byte) s.length();
                System.arraycopy(s.getBytes(), 0, result, offset, s.length());
                offset += s.length();
            } else if (Objects.equals(s, this.country)) {
                System.arraycopy(s.getBytes(), 0, result, offset, 3);
                offset += 3;
            } else {
                System.arraycopy(Hex.hexStringToBytes(s), 0, result,
                        offset, 4);
                offset += 4;
            }
            b2++;
        }

        return result;
    }
}