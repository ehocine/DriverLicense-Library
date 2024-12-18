package com.driverlicense.tlv;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;


public class BERTLVObject {
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyMMddhhmmss'Z'");

    public static final int UNIVERSAL_CLASS = 0;

    public static final int APPLICATION_CLASS = 1;

    public static final int CONTEXT_SPECIFIC_CLASS = 2;

    public static final int PRIVATE_CLASS = 3;

    public static final int BOOLEAN_TYPE_TAG = 1;

    public static final int INTEGER_TYPE_TAG = 2;

    public static final int BIT_STRING_TYPE_TAG = 3;

    public static final int OCTET_STRING_TYPE_TAG = 4;

    public static final int NULL_TYPE_TAG = 5;

    public static final int OBJECT_IDENTIFIER_TYPE_TAG = 6;

    public static final int OBJECT_DESCRIPTOR_TYPE_TAG = 7;

    public static final int EXTERNAL_TYPE_TAG = 8;

    public static final int REAL_TYPE_TAG = 9;

    public static final int ENUMERATED_TYPE_TAG = 10;

    public static final int EMBEDDED_PDV_TYPE_TAG = 11;

    public static final int UTF8_STRING_TYPE_TAG = 12;

    public static final int SEQUENCE_TYPE_TAG = 16;

    public static final int SET_TYPE_TAG = 17;

    public static final int NUMERIC_STRING_TYPE_TAG = 18;

    public static final int PRINTABLE_STRING_TYPE_TAG = 19;

    public static final int T61_STRING_TYPE_TAG = 20;

    public static final int IA5_STRING_TYPE_TAG = 22;

    public static final int UTC_TIME_TYPE_TAG = 23;

    public static final int GENERALIZED_TIME_TYPE_TAG = 24;

    public static final int GRAPHIC_STRING_TYPE_TAG = 25;

    public static final int VISIBLE_STRING_TYPE_TAG = 26;

    public static final int GENERAL_STRING_TYPE_TAG = 27;

    public static final int UNIVERSAL_STRING_TYPE_TAG = 28;

    public static final int BMP_STRING_TYPE_TAG = 30;

    private int tag;

    private int length;

    private Object value;

    public BERTLVObject(int tag, Object value) {
        this(tag, value, true);
    }

    public BERTLVObject(int tag, Object value, boolean interpretValue) {
        try {
            this.tag = tag;
            this.value = value;
            switch (value) {
                case byte[] bytes -> this.length = bytes.length;
                case BERTLVObject bertlvObject -> {
                    this.value = new BERTLVObject[1];
                    ((BERTLVObject[]) this.value)[0] = bertlvObject;
                }
                case BERTLVObject[] bertlvObjects -> this.value = value;
                case Byte b -> {
                    this.length = 1;
                    this.value = new byte[1];
                    ((byte[]) this.value)[0] = b;
                }
                case Integer i -> {
                    this.value = new BERTLVObject[1];
                    ((BERTLVObject[]) this.value)[0] = new BERTLVObject(2, value);
                }
                case null, default -> {
                    assert value != null;
                    throw new IllegalArgumentException("Cannot encode value of type: " + value.getClass());
                }
            }
            if (value instanceof byte[] && interpretValue)
                this.value = interpretValue(tag, (byte[]) value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static BERTLVObject getInstance(InputStream in) throws IOException {
        TLVInputStream tlvIn = (in instanceof TLVInputStream) ? (TLVInputStream) in : new TLVInputStream(in);
        int tag = tlvIn.readTag();
        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        return new BERTLVObject(tag, valueBytes);
    }

    private static Object interpretValue(int tag, byte[] valueBytes) {
        if (isPrimitive(tag))
            return interpretPrimitiveValue(tag, valueBytes);
        try {
            return interpretCompoundValue(tag, valueBytes);
        } catch (IOException ioe) {
            return new BERTLVObject[0];
        }
    }

    private static Object interpretPrimitiveValue(int tag, byte[] valueBytes) {
        if (getTagClass(tag) == 0)
            switch (tag) {
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                    return valueBytes;
                case 12:
                case 19:
                case 20:
                case 22:
                case 26:
                case 27:
                case 28:
                case 30:
                    return new String(valueBytes);
                case 23:
                    try {
                        return SDF.parse(new String(valueBytes));
                    } catch (ParseException parseException) {
                        break;
                    }
            }
        return valueBytes;
    }

    private static BERTLVObject[] interpretCompoundValue(int tag, byte[] valueBytes) throws IOException {
        Collection<BERTLVObject> subObjects = new ArrayList<BERTLVObject>();
        TLVInputStream in = new TLVInputStream(new ByteArrayInputStream(valueBytes));
        int length = valueBytes.length;
        try {
            while (length > 0) {
                BERTLVObject subObject = getInstance(in);
                length -= subObject.getLength();
                subObjects.add(subObject);
            }
        } catch (EOFException _) {
        }
        BERTLVObject[] result = new BERTLVObject[subObjects.size()];
        subObjects.toArray(result);
        return result;
    }

    private static int getTagClass(int tag) {
        int i = 3;
        for (; i >= 0; i--) {
            int mask = 255 << 8 * i;
            if ((tag & mask) != 0)
                break;
        }
        int msByte = (tag & 255 << 8 * i) >> 8 * i & 0xFF;
        return switch (msByte & 0xC0) {
            case 0 -> 0;
            case 64 -> 1;
            case 128 -> 2;
            default -> 3;
        };
    }

    public void addSubObject(BERTLVObject object) {
        Collection<BERTLVObject> subObjects = new ArrayList<BERTLVObject>();
        switch (this.value) {
            case null -> this.value = new BERTLVObject[1];
            case BERTLVObject[] bertlvObjects -> subObjects.addAll(Arrays.asList(bertlvObjects));
            case BERTLVObject bertlvObject -> {
                subObjects.add(bertlvObject);
                this.value = new BERTLVObject[2];
            }
            default -> throw new IllegalStateException("Error: Unexpected value in BERTLVObject");
        }
        subObjects.add(object);
        this.value = subObjects.toArray((BERTLVObject[]) this.value);
        reconstructLength();
    }

    public int getTag() {
        return this.tag;
    }

    public void reconstructLength() {
        this.length = (getValueAsBytes(this.tag, this.value)).length;
    }

    public int getLength() {
        return this.length;
    }

    public Object getValue() {
        return this.value;
    }

    public byte[] getEncoded() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(getTagAsBytes(this.tag));
            out.write(getLengthAsBytes(getLength()));
            out.write(getValueAsBytes(this.tag, this.value));
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
        return out.toByteArray();
    }

    public BERTLVObject getSubObject(int i) {
        if (this.tag == i) {
            return this;
        }
        Object obj = this.value;
        if (!(obj instanceof BERTLVObject[] bERTLVObjectArr)) {
            return null;
        }
        for (BERTLVObject subObject : bERTLVObjectArr) {
            BERTLVObject subObject2 = subObject.getSubObject(i);
            if (subObject2 != null) {
                return subObject2;
            }
        }
        return null;
    }

    public BERTLVObject getSubObject(int[] tagPath, int offset, int length) {
        if (length == 0)
            return this;
        BERTLVObject child = getSubObject(tagPath[offset]);
        if (child != null)
            return child.getSubObject(tagPath, offset + 1, length - 1);
        return null;
    }

    public BERTLVObject getChildByIndex(int index) {
        if (this.value instanceof BERTLVObject[] children) {
            return children[index];
        }
        return null;
    }

    public String toString() {
        return toString(0);
    }

    private String toString(int indent) {
        byte[] prefixBytes = new byte[indent];
        Arrays.fill(prefixBytes, (byte) 32);
        String prefix = new String(prefixBytes);
        StringBuilder result = new StringBuilder();
        result.append(prefix);
        result.append(tagToString());
        result.append(" ");
        result.append(Integer.toString(getLength()));
        result.append(" ");
        if (this.value instanceof byte[] valueData) {
            result.append("'0x");
            if (indent + 2 * valueData.length <= 60) {
                result.append(Hex.bytesToHexString(valueData));
            } else {
                result
                        .append(Hex.bytesToHexString(valueData, 0, (50 - indent) / 2));
                result.append("...");
            }
            result.append("'\n");
        } else if (this.value instanceof BERTLVObject[] subObjects) {
            result.append("{\n");
            for (BERTLVObject subObject : subObjects) result.append(subObject.toString(indent + 3));
            result.append(prefix);
            result.append("}\n");
        } else {
            result.append("\"");
            result.append((this.value != null) ? this.value.toString() : "null");
            result.append("\"\n");
        }
        return result.toString();
    }

    private String tagToString() {
        if (getTagClass(this.tag) == 0)
            if (isPrimitive(this.tag)) {
                switch (this.tag & 0x1F) {
                    case 1:
                        return "BOOLEAN";
                    case 2:
                        return "INTEGER";
                    case 3:
                        return "BIT_STRING";
                    case 4:
                        return "OCTET_STRING";
                    case 5:
                        return "NULL";
                    case 6:
                        return "OBJECT_IDENTIFIER";
                    case 9:
                        return "REAL";
                    case 12:
                        return "UTF_STRING";
                    case 19:
                        return "PRINTABLE_STRING";
                    case 20:
                        return "T61_STRING";
                    case 22:
                        return "IA5_STRING";
                    case 26:
                        return "VISIBLE_STRING";
                    case 27:
                        return "GENERAL_STRING";
                    case 28:
                        return "UNIVERSAL_STRING";
                    case 30:
                        return "BMP_STRING";
                    case 23:
                        return "UTC_TIME";
                    case 24:
                        return "GENERAL_TIME";
                }
            } else {
                switch (this.tag & 0x1F) {
                    case 10:
                        return "ENUMERATED";
                    case 16:
                        return "SEQUENCE";
                    case 17:
                        return "SET";
                }
            }
        return "'0x" + Hex.intToHexString(this.tag) + "'";
    }

    private static boolean isPrimitive(int tag) {
        int i = 3;
        for (; i >= 0; i--) {
            int mask = 255 << 8 * i;
            if ((tag & mask) != 0)
                break;
        }
        int msByte = (tag & 255 << 8 * i) >> 8 * i & 0xFF;
        boolean result = ((msByte & 0x20) == 0);
        return result;
    }

    public static int getTagLength(int tag) {
        return (getTagAsBytes(tag)).length;
    }

    public static int getLengthLength(int length) {
        return (getLengthAsBytes(length)).length;
    }

    public static byte[] getTagAsBytes(int tag) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int byteCount = (int) (Math.log(tag) / Math.log(256.0D)) + 1;
        for (int i = 0; i < byteCount; i++) {
            int pos = 8 * (byteCount - i - 1);
            out.write((tag & 255 << pos) >> pos);
        }
        byte[] tagBytes = out.toByteArray();
        switch (getTagClass(tag)) {
            case 1:
                tagBytes[0] = (byte) (tagBytes[0] | 0x40);
                break;
            case 2:
                tagBytes[0] = (byte) (tagBytes[0] | 0x80);
                break;
            case 3:
                tagBytes[0] = (byte) (tagBytes[0] | 0xC0);
                break;
        }
        if (!isPrimitive(tag))
            tagBytes[0] = (byte) (tagBytes[0] | 0x20);
        return tagBytes;
    }

    public static byte[] getLengthAsBytes(int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (length < 128) {
            out.write(length);
        } else {
            int byteCount = log(length, 256);
            out.write(0x80 | byteCount);
            for (int i = 0; i < byteCount; i++) {
                int pos = 8 * (byteCount - i - 1);
                out.write((length & 255 << pos) >> pos);
            }
        }
        return out.toByteArray();
    }

    private static int log(int n, int base) {
        int result = 0;
        while (n > 0) {
            n /= base;
            result++;
        }
        return result;
    }

    private static byte[] getValueAsBytes(int tag, Object value) {
        if (value == null)
            System.out.println("DEBUG: object has no value: tag == " +
                    Integer.toHexString(tag));
        if (isPrimitive(tag)) {
            if (value instanceof byte[])
                return (byte[]) value;
            if (value instanceof String)
                return ((String) value).getBytes();
            if (value instanceof Date)
                return SDF.format((Date) value).getBytes();
            if (value instanceof Integer) {
                int intValue = (Integer) value;
                int byteCount = Integer.bitCount(intValue) / 8 + 1;
                byte[] result = new byte[byteCount];
                for (int i = 0; i < byteCount; i++) {
                    int pos = 8 * (byteCount - i - 1);
                    result[i] = (byte) ((intValue & 255 << pos) >> pos);
                }
                return result;
            }
            if (value instanceof Byte) {
                byte[] result = new byte[1];
                result[0] = (Byte) value;
                return result;
            }
        }
        if (value instanceof BERTLVObject[] children) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            for (BERTLVObject child : children) {
                try {
                    result.write(child.getEncoded());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return result.toByteArray();
        }
        if (value instanceof byte[]) {
            System.err.println("DEBUG: WARNING: BERTLVobject with non-primitive tag " +
                    Hex.intToHexString(tag) + " has byte[] value");
            return (byte[]) value;
        }
        throw new IllegalStateException("Cannot decode value of " + (
                (value == null) ? "null" : value.getClass().getCanonicalName()) +
                " (tag = " + Hex.intToHexString(tag) + ")");
    }
}