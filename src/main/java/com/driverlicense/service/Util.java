package com.driverlicense.service;


import net.sf.scuba.util.Hex;
import org.bouncycastle.asn1.*;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;


class Util {
    public static final int ENC_MODE = 1;
    public static final int MAC_MODE = 2;

    public static SecretKey deriveKey(byte[] keySeed, int mode) throws GeneralSecurityException {
        MessageDigest shaDigest = MessageDigest.getInstance("SHA1");
        shaDigest.update(keySeed);
        byte[] c = {0, 0, 0, (byte) mode};
        shaDigest.update(c);
        byte[] hash = shaDigest.digest();
        byte[] key = new byte[24];
        System.arraycopy(hash, 0, key, 0, 8);
        System.arraycopy(hash, 8, key, 8, 8);
        System.arraycopy(hash, 0, key, 16, 8);
        SecretKeyFactory desKeyFactory = SecretKeyFactory.getInstance("DESede");
        return desKeyFactory.generateSecret(new DESedeKeySpec(key));
    }

    public static long computeSendSequenceCounter(byte[] rndICC, byte[] rndIFD) {
        if (rndICC == null || rndICC.length != 8 || rndIFD == null ||
                rndIFD.length != 8) {
            throw new IllegalStateException("Wrong length input");
        }
        long ssc = 0L;
        int i;
        for (i = 4; i < 8; i++) {
            ssc <<= 8L;
            ssc += (rndICC[i] & 0xFF);
        }
        for (i = 4; i < 8; i++) {
            ssc <<= 8L;
            ssc += (rndIFD[i] & 0xFF);
        }
        return ssc;
    }


    public static byte[] pad(byte[] in) {
        return pad(in, 0, in.length);
    }

    public static byte[] pad(byte[] in, int offset, int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(in, offset, length);
        out.write(-128);
        while (out.size() % 8 != 0) {
            out.write(0);
        }
        return out.toByteArray();
    }

    public static byte[] unpad(byte[] in) {
        int i = in.length - 1;
        while (i >= 0 && in[i] == 0) {
            i--;
        }
        if ((in[i] & 0xFF) != 128) {
            throw new IllegalStateException(
                    "unpad expected constant 0x80, found 0x" +
                            Integer.toHexString(in[i] & 0xFF) +
                            "\nDEBUG: in = " + Hex.bytesToHexString(in) +
                            ", index = " + i);
        }
        byte[] out = new byte[i];
        System.arraycopy(in, 0, out, 0, i);
        return out;
    }


    public static byte[] recoverMessage(int digestLength, byte[] plaintext) {
        if (plaintext == null || plaintext.length < 1) {
            throw new IllegalArgumentException(
                    "Plaintext too short to recover message");
        }
        if ((plaintext[0] & 0xC0 ^ 0x40) != 0) {
            throw new NumberFormatException("Could not get M1");
        }
        if ((plaintext[plaintext.length - 1] & 0xF ^ 0xC) != 0) {
            throw new NumberFormatException("Could not get M1");
        }
        int delta = 0;
        if ((plaintext[plaintext.length - 1] & 0xFF ^ 0xBC) == 0) {
            delta = 1;
        } else {

            throw new NumberFormatException("Could not get M1");
        }


        int paddingLength = 0;
        for (; paddingLength < plaintext.length; paddingLength++) {

            if ((plaintext[paddingLength] & 0xF ^ 0xA) == 0) {
                break;
            }
        }
        int messageOffset = paddingLength + 1;

        int paddedMessageLength = plaintext.length - delta - digestLength;
        int messageLength = paddedMessageLength - messageOffset;


        if (messageLength <= 0) {
            throw new NumberFormatException("Could not get M1");
        }


        if ((plaintext[0] & 0x20) == 0) {
            throw new NumberFormatException("Could not get M1");
        }
        byte[] recoveredMessage = new byte[messageLength];
        System.arraycopy(plaintext, messageOffset, recoveredMessage, 0,
                messageLength);
        return recoveredMessage;
    }


    public static String printASN1Primitive(DERNull derNull) throws IOException {
        return "DERNull" + Hex.bytesToHexString(derNull.getEncoded());
    }

    public static String printASN1Primitive(DERTaggedObject derUnknownTag) {
        return "DERUnknownTag: " + derUnknownTag.getTagClass();
    }

    public static String printASN1Primitive(ASN1ObjectIdentifier derObjectIdentifier) {
        return "ASN1PrimitiveIdentifier: " + derObjectIdentifier.getId();
    }

    public static String printASN1Primitive(DEROctetString derOctetString) {
        return "DEROctetString: " +
                Hex.bytesToHexString(derOctetString.getOctets());
    }

    public static String printASN1Primitive(DERUTF8String derString) {
        return String.valueOf(derString.getClass().getSimpleName()) + ": " +
                derString.getString();
    }

    public static String printASN1Primitive(DERUTCTime derUTCTime) {
        return "DERUTCTime: " + derUTCTime.getAdjustedTime();
    }

    public static String printASN1Primitive(DERGeneralizedTime derGeneralizedTime) {
        return "DERGeneralizedTime: " + derGeneralizedTime.getTime();
    }
}