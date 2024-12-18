package com.driverlicense.service;

import net.sf.scuba.data.Gender;
import org.jmrtd.lds.ImageInfo;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;

public class FaceInfo {
    public static final short EXPRESSION_EYES_LOOKING_AWAY = 5;
    public static final short EXPRESSION_FROWNING = 7;
    public static final short EXPRESSION_NEUTRAL = 1;
    public static final short EXPRESSION_RAISED_EYEBROWS = 4;
    public static final short EXPRESSION_SMILE_CLOSED = 2;
    public static final short EXPRESSION_SMILE_OPEN = 3;
    public static final short EXPRESSION_SQUINTING = 6;
    public static final short EXPRESSION_UNSPECIFIED = 0;
    public static final int EYE_COLOR_BLACK = 1;
    public static final int EYE_COLOR_BLUE = 2;
    public static final int EYE_COLOR_BROWN = 3;
    public static final int EYE_COLOR_GRAY = 4;
    public static final int EYE_COLOR_GREEN = 5;
    public static final int EYE_COLOR_MULTI_COLORED = 6;
    public static final int EYE_COLOR_PINK = 7;
    public static final int EYE_COLOR_UNKNOWN = 8;
    public static final int EYE_COLOR_UNSPECIFIED = 0;
    public static final int FACE_IMAGE_TYPE_BASIC = 1;
    public static final int FACE_IMAGE_TYPE_FULL_FRONTAL = 2;
    public static final int FACE_IMAGE_TYPE_OTHER = 4;
    public static final int FACE_IMAGE_TYPE_TOKEN_FRONTAL = 3;
    public static final int FACE_IMAGE_TYPE_UNSPECIFIED = 0;
    private static final int FEATURE_BEARD_FLAG = 8;
    private static final int FEATURE_BLINK_FLAG = 32;
    private static final int FEATURE_DARK_GLASSES = 512;
    private static final int FEATURE_DISTORTING_MEDICAL_CONDITION = 1024;
    private static final int FEATURE_FEATURES_ARE_SPECIFIED_FLAG = 0;
    private static final int FEATURE_GLASSES_FLAG = 2;
    private static final int FEATURE_LEFT_EYE_PATCH_FLAG = 128;
    private static final int FEATURE_MOUSTACHE_FLAG = 4;
    private static final int FEATURE_MOUTH_OPEN_FLAG = 64;
    private static final int FEATURE_RIGHT_EYE_PATCH = 256;
    private static final int FEATURE_TEETH_VISIBLE_FLAG = 16;
    public static final int HAIR_COLOR_BALD = 1;
    public static final int HAIR_COLOR_BLACK = 2;
    public static final int HAIR_COLOR_BLONDE = 3;
    public static final int HAIR_COLOR_BLUE = 9;
    public static final int HAIR_COLOR_BROWN = 4;
    public static final int HAIR_COLOR_GRAY = 5;
    public static final int HAIR_COLOR_GREEN = 8;
    public static final int HAIR_COLOR_RED = 7;
    public static final int HAIR_COLOR_UNKNOWN = 255;
    public static final int HAIR_COLOR_UNSPECIFIED = 0;
    public static final int HAIR_COLOR_WHITE = 6;
    public static final int IMAGE_COLOR_SPACE_GRAY8 = 3;
    public static final int IMAGE_COLOR_SPACE_OTHER = 4;
    public static final int IMAGE_COLOR_SPACE_RGB24 = 1;
    public static final int IMAGE_COLOR_SPACE_UNSPECIFIED = 0;
    public static final int IMAGE_COLOR_SPACE_YUV422 = 2;
    private static final int IMAGE_DATA_TYPE_JPEG = 0;
    private static final int IMAGE_DATA_TYPE_JPEG2000 = 1;
    private static final int PITCH = 1;
    private static final int ROLL = 2;
    public static final int SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM = 2;
    public static final int SOURCE_TYPE_STATIC_PHOTO_SCANNER = 3;
    public static final int SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE = 1;
    public static final int SOURCE_TYPE_UNKNOWN = 7;
    public static final int SOURCE_TYPE_UNSPECIFIED = 0;
    public static final int SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM = 5;
    public static final int SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM = 6;
    public static final int SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE = 4;
    private static final int YAW = 0;
    private final int deviceType;
    private final short expression;
    private final EyeColor eyeColor;
    private long faceImageBlockLength;
    private int faceImageType;
    private long featureMask;
    private final FeaturePoint[] featurePoints;
    private final Gender gender;
    private final int hairColor;
    private int height;
    private int imageColorSpace;
    private final int imageDataType;
    private final int[] poseAngle;
    private final int[] poseAngleUncertainty;
    private int quality;
    private final int sourceType;
    private int width;

    public enum Expression {
        UNSPECIFIED,
        NEUTRAL,
        SMILE_CLOSED,
        SMILE_OPEN,
        RAISED_EYEBROWS,
        EYES_LOOKING_AWAY,
        SQUINTING,
        FROWNING
    }

    public enum FaceImageType {
        UNSPECIFIED,
        BASIC,
        FULL_FRONTAL,
        TOKEN_FRONTAL,
        OTHER
    }

    public enum Features {
        FEATURES_ARE_SPECIFIED,
        GLASSES,
        MOUSTACHE,
        BEARD,
        TEETH_VISIBLE,
        BLINK,
        MOUTH_OPEN,
        LEFT_EYE_PATCH,
        RIGHT_EYE_PATCH,
        DARK_GLASSES,
        DISTORTING_MEDICAL_CONDITION
    }

    public enum HairColor {
        UNSPECIFIED,
        BALD,
        BLACK,
        BLONDE,
        BROWN,
        GRAY,
        WHITE,
        RED,
        GREEN,
        BLUE,
        UNKNOWN
    }

    public enum ImageColorSpace {
        UNSPECIFIED,
        RGB24,
        YUV422,
        GRAY8,
        OTHER
    }

    public enum ImageData {
        TYPE_JPEG,
        TYPE_JPEG2000
    }

    public enum SourceType {
        UNSPECIFIED,
        STATIC_PHOTO_UNKNOWN_SOURCE,
        STATIC_PHOTO_DIGITAL_CAM,
        STATIC_PHOTO_SCANNER,
        VIDEO_FRAME_UNKNOWN_SOURCE,
        VIDEO_FRAME_ANALOG_CAM,
        VIDEO_FRAME_DIGITAL_CAM,
        UNKNOWN
    }

    public enum EyeColor {
        UNSPECIFIED {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 0;
            }
        },
        BLACK {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 1;
            }
        },
        BLUE {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 2;
            }
        },
        BROWN {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 3;
            }
        },
        GRAY {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 4;
            }
        },
        GREEN {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 5;
            }
        },
        MULTI_COLORED {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 6;
            }
        },
        PINK {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 7;
            }
        },
        UNKNOWN {
            /* access modifiers changed from: package-private */
            public int toInt() {
                return 8;
            }
        };

        /* access modifiers changed from: package-private */
        public abstract int toInt();

        static EyeColor toEyeColor(int i) {
            for (EyeColor eyeColor : values()) {
                if (eyeColor.toInt() == i) {
                    return eyeColor;
                }
            }
            return null;
        }
    }

    public FaceInfo(Gender gender2, EyeColor eyeColor2, int i, short s, int i2) {
        this.faceImageBlockLength = 0;
        this.gender = gender2;
        this.eyeColor = eyeColor2;
        this.hairColor = i;
        this.expression = s;
        this.sourceType = i2;
        this.deviceType = 0;
        this.poseAngle = new int[3];
        this.poseAngleUncertainty = new int[3];
        this.featurePoints = new FeaturePoint[0];
        this.imageDataType = 0;
    }

    FaceInfo(InputStream inputStream) throws IOException {
        DataInputStream dataInputStream = inputStream instanceof DataInputStream ? (DataInputStream) inputStream : new DataInputStream(inputStream);
        this.faceImageBlockLength = ((long) dataInputStream.readInt()) & 4294967295L;
        int readUnsignedShort = dataInputStream.readUnsignedShort();
        this.gender = Gender.getInstance(dataInputStream.readUnsignedByte());
        this.eyeColor = EyeColor.toEyeColor(dataInputStream.readUnsignedByte());
        this.hairColor = dataInputStream.readUnsignedByte();
        long readUnsignedByte = dataInputStream.readUnsignedByte();
        this.featureMask = readUnsignedByte;
        this.featureMask = (readUnsignedByte << 16) | ((long) dataInputStream.readUnsignedShort());
        this.expression = dataInputStream.readShort();
        this.poseAngle = new int[3];
        int readUnsignedByte2 = dataInputStream.readUnsignedByte();
        this.poseAngle[0] = (readUnsignedByte2 <= 91 ? readUnsignedByte2 - 1 : readUnsignedByte2 - 181) * 2;
        int readUnsignedByte3 = dataInputStream.readUnsignedByte();
        this.poseAngle[1] = (readUnsignedByte3 <= 91 ? readUnsignedByte3 - 1 : readUnsignedByte3 - 181) * 2;
        int readUnsignedByte4 = dataInputStream.readUnsignedByte();
        this.poseAngle[2] = (readUnsignedByte4 <= 91 ? readUnsignedByte4 - 1 : readUnsignedByte4 - 181) * 2;
        int[] iArr = new int[3];
        this.poseAngleUncertainty = iArr;
        iArr[0] = dataInputStream.readUnsignedByte();
        this.poseAngleUncertainty[1] = dataInputStream.readUnsignedByte();
        this.poseAngleUncertainty[2] = dataInputStream.readUnsignedByte();
        this.featurePoints = new FeaturePoint[readUnsignedShort];
        for (int i = 0; i < readUnsignedShort; i++) {
            int readUnsignedByte5 = dataInputStream.readUnsignedByte();
            byte readByte = dataInputStream.readByte();
            int readUnsignedShort2 = dataInputStream.readUnsignedShort();
            int readUnsignedShort3 = dataInputStream.readUnsignedShort();
            dataInputStream.skip(2);
            this.featurePoints[i] = new FeaturePoint(this, readUnsignedByte5, readByte, readUnsignedShort2, readUnsignedShort3);
        }
        this.faceImageType = dataInputStream.readUnsignedByte();
        this.imageDataType = dataInputStream.readUnsignedByte();
        this.width = dataInputStream.readUnsignedShort();
        this.height = dataInputStream.readUnsignedShort();
        this.imageColorSpace = dataInputStream.readUnsignedByte();
        this.sourceType = dataInputStream.readUnsignedByte();
        this.deviceType = dataInputStream.readUnsignedShort();
        this.quality = dataInputStream.readUnsignedShort();
        if (this.width <= 0) {
            this.width = 800;
        }
        if (this.height <= 0) {
            this.height = 600;
        }
    }

    public byte[] getEncoded() {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
            dataOutputStream.writeShort(this.featurePoints.length);
            dataOutputStream.writeByte(this.gender.toInt());
            dataOutputStream.writeByte(this.eyeColor.toInt());
            dataOutputStream.writeByte(this.hairColor);
            dataOutputStream.writeByte((byte) ((int) ((this.featureMask & 16711680) >> 16)));
            dataOutputStream.writeByte((byte) ((int) ((this.featureMask & 65280) >> 8)));
            dataOutputStream.writeByte((byte) ((int) (this.featureMask & 255)));
            dataOutputStream.writeShort(this.expression);
            for (int i = 0; i < 3; i++) {
                int[] iArr = this.poseAngle;
                dataOutputStream.writeByte((iArr[i] < 0 || iArr[i] > 180) ? (iArr[i] / 2) + 181 : (iArr[i] / 2) + 1);
            }
            for (int i2 = 0; i2 < 3; i2++) {
                dataOutputStream.writeByte(this.poseAngleUncertainty[i2]);
            }
            int i3 = 0;
            while (true) {
                FeaturePoint[] featurePointArr = this.featurePoints;
                if (i3 >= featurePointArr.length) {
                    break;
                }
                FeaturePoint featurePoint = featurePointArr[i3];
                dataOutputStream.writeByte(featurePoint.getType());
                dataOutputStream.writeByte((featurePoint.getMajorCode() << 4) | featurePoint.getMinorCode());
                dataOutputStream.writeShort(featurePoint.getX());
                dataOutputStream.writeShort(featurePoint.getY());
                dataOutputStream.writeShort(0);
                i3++;
            }
            dataOutputStream.writeByte(this.faceImageType);
            dataOutputStream.writeByte(this.imageDataType);
            dataOutputStream.writeShort(this.width);
            dataOutputStream.writeShort(this.height);
            dataOutputStream.writeByte(this.imageColorSpace);
            dataOutputStream.writeByte(this.sourceType);
            dataOutputStream.writeShort(this.deviceType);
            dataOutputStream.writeShort(this.quality);
            int i4 = this.imageDataType;
            if (i4 != 0) {
                if (i4 != 1) {
                    throw new IOException("Unknown image data type!");
                }
            }
            dataOutputStream.flush();
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            dataOutputStream.close();
            this.faceImageBlockLength = byteArray.length;
            ByteArrayOutputStream byteArrayOutputStream2 = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream2 = new DataOutputStream(byteArrayOutputStream2);
            dataOutputStream2.writeInt((int) this.faceImageBlockLength);
            dataOutputStream2.write(byteArray);
            dataOutputStream2.flush();
            byte[] byteArray2 = byteArrayOutputStream2.toByteArray();
            dataOutputStream2.close();
            return byteArray2;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getRawImage() {
        try {
            return new ByteArrayOutputStream().toByteArray();
        } catch (Exception unused) {
            return null;
        }
    }

    public String getMimeType() {
        int i = this.imageDataType;
        if (i == 0) {
            return ImageInfo.JPEG_MIME_TYPE;
        }
        if (i != 1) {
            return null;
        }
        return "image/jpeg2000";
    }

    public FeaturePoint[] getFeaturePoints() {
        return this.featurePoints;
    }

    public String toString() {
        StringBuilder stringBuffer = new StringBuilder();
        stringBuffer.append("Image size: ");
        stringBuffer.append(this.width).append(" x ").append(this.height);
        stringBuffer.append("Gender: ");
        stringBuffer.append(this.gender);
        stringBuffer.append("Eye color: ");
        stringBuffer.append(this.eyeColor);
        stringBuffer.append("Hair color: ");
        stringBuffer.append(hairColorToString());
        stringBuffer.append("Feature mask: ");
        stringBuffer.append(featureMaskToString());
        stringBuffer.append("Expression: ");
        stringBuffer.append(expressionToString());
        stringBuffer.append("Pose angle: ");
        stringBuffer.append(poseAngleToString());
        stringBuffer.append("Face image type: ");
        stringBuffer.append(faceImageTypeToString());
        stringBuffer.append("Source type: ");
        stringBuffer.append(sourceTypeToString());
        stringBuffer.append("Feature points: ");
        FeaturePoint[] featurePointArr = this.featurePoints;
        if (featurePointArr == null || featurePointArr.length == 0) {
            stringBuffer.append("   (none)\n");
        } else {
            for (FeaturePoint featurePoint : this.featurePoints) {
                stringBuffer.append("   ");
                stringBuffer.append(featurePoint.toString());
            }
        }
        return stringBuffer.toString();
    }

    private String hairColorToString() {
        return switch (this.hairColor) {
            case 0 -> "";
            case 1 -> "bald";
            case 2 -> "black";
            case 3 -> "blonde";
            case 4 -> "brown";
            case 5 -> "gray";
            case 6 -> "white";
            case 7 -> "red";
            case 8 -> "green";
            case 9 -> "blue";
            default -> "";
        };
    }

    private String featureMaskToString() {
        if ((0L) == 0) {
            return "";
        }
        ArrayList arrayList = new ArrayList();
        if ((this.featureMask & 2) != 0) {
            arrayList.add("glasses");
        }
        if ((this.featureMask & 4) != 0) {
            arrayList.add("moustache");
        }
        if ((this.featureMask & 8) != 0) {
            arrayList.add("beard");
        }
        if ((this.featureMask & 16) != 0) {
            arrayList.add("teeth visible");
        }
        if ((this.featureMask & 32) != 0) {
            arrayList.add("blink");
        }
        if ((this.featureMask & 64) != 0) {
            arrayList.add("mouth open");
        }
        if ((this.featureMask & 128) != 0) {
            arrayList.add("left eye patch");
        }
        if ((this.featureMask & 256) != 0) {
            arrayList.add("right eye patch");
        }
        if ((this.featureMask & 512) != 0) {
            arrayList.add("dark glasses");
        }
        if ((this.featureMask & 1024) != 0) {
            arrayList.add("distorting medical condition (which could impact feature point detection)");
        }
        StringBuilder stringBuffer = new StringBuilder();
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            stringBuffer.append(((String) it.next()).toString());
            if (it.hasNext()) {
                stringBuffer.append(", ");
            }
        }
        return stringBuffer.toString();
    }

    private String expressionToString() {
        return switch (this.expression) {
            case 1 -> "neutral (non-smiling) with both eyes open and mouth closed";
            case 2 -> "a smile where the inside of the mouth and/or teeth is not exposed (closed jaw)";
            case 3 -> "a smile where the inside of the mouth and/or teeth is exposed";
            case 4 -> "raised eyebrows";
            case 5 -> "eyes looking away from the camera";
            case 6 -> "squinting";
            case 7 -> "frowning";
            default -> "";
        };
    }

    private String poseAngleToString() {
        StringBuilder stringBuffer = new StringBuilder();
        stringBuffer.append("(");
        stringBuffer.append("y: ");
        stringBuffer.append(this.poseAngle[0]);
        if (this.poseAngleUncertainty[0] != 0) {
            stringBuffer.append(" (");
            stringBuffer.append(this.poseAngleUncertainty[0]);
            stringBuffer.append(")");
        }
        stringBuffer.append(", ");
        stringBuffer.append("p:");
        stringBuffer.append(this.poseAngle[1]);
        if (this.poseAngleUncertainty[1] != 0) {
            stringBuffer.append(" (");
            stringBuffer.append(this.poseAngleUncertainty[1]);
            stringBuffer.append(")");
        }
        stringBuffer.append(", ");
        stringBuffer.append("r: ");
        stringBuffer.append(this.poseAngle[2]);
        if (this.poseAngleUncertainty[2] != 0) {
            stringBuffer.append(" (");
            stringBuffer.append(this.poseAngleUncertainty[2]);
            stringBuffer.append(")");
        }
        stringBuffer.append(")");
        return stringBuffer.toString();
    }

    private String faceImageTypeToString() {
        int i = this.faceImageType;
        if (i == 0) {
            return "unspecified (basic)";
        }
        if (i == 1) {
            return "basic";
        }
        if (i == 2) {
            return "full frontal";
        }
        if (i != 3) {
            return i != 4 ? "" : "other";
        }
        return "token frontal";
    }

    private String sourceTypeToString() {
        return switch (this.sourceType) {
            case 1 -> "static photograph from an unknown source";
            case 2 -> "static photograph from a digital still-image camera";
            case 3 -> "static photograph fram a scanner";
            case 4 -> "single video frame from an unknown source";
            case 5 -> "single video frame from an analogue camera";
            case 6 -> "single video frame from a digital camera";
            default -> "";
        };
    }

    public int getWidth() {
        return this.width;
    }

    public int getHeight() {
        return this.height;
    }

    public short getExpression() {
        return this.expression;
    }

    public EyeColor getEyeColor() {
        return this.eyeColor;
    }

    public Gender getGender() {
        return this.gender;
    }

    public int getHairColor() {
        return this.hairColor;
    }

    public int getFaceImageType() {
        return this.faceImageType;
    }

    public int getQuality() {
        return this.quality;
    }

    public int getSourceType() {
        return this.sourceType;
    }

    public int getImageColorSpace() {
        return this.imageColorSpace;
    }

    public int getDeviceType() {
        return this.deviceType;
    }

    public int[] getPoseAngle() {
        int[] iArr = new int[3];
        System.arraycopy(this.poseAngle, 0, iArr, 0, 3);
        return iArr;
    }

    public int[] getPoseAngleUncertainty() {
        int[] iArr = new int[3];
        System.arraycopy(this.poseAngleUncertainty, 0, iArr, 0, 3);
        return iArr;
    }

    public static class FeaturePoint {
        private final int majorCode;
        private final int minorCode;
        private final int type;
        private final int x;
        private final int y;

        public FeaturePoint(int i, int i2, int i3, int i4, int i5) {
            this.type = i;
            this.majorCode = i2;
            this.minorCode = i3;
            this.x = i4;
            this.y = i5;
        }

        FeaturePoint(FaceInfo faceInfo, int i, byte b, int i2, int i3) {
            this(i, (b & 240) >> 4, b & 15, i2, i3);
        }

        public int getMajorCode() {
            return this.majorCode;
        }

        public int getMinorCode() {
            return this.minorCode;
        }

        public int getType() {
            return this.type;
        }

        public int getX() {
            return this.x;
        }

        public int getY() {
            return this.y;
        }

        public String toString() {
            String stringBuffer = "( point: " +
                    getMajorCode() +
                    "." +
                    getMinorCode() +
                    ", " +
                    "type: " +
                    Integer.toHexString(this.type) +
                    ", " +
                    "(" +
                    this.x +
                    ", " +
                    this.y +
                    ")" +
                    ")";
            return stringBuffer;
        }
    }
}
