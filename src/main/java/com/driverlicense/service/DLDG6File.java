package com.driverlicense.service;

import net.sf.scuba.smartcards.ISO7816;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DLDG6File extends DLDG6789File {
    private static final byte[] FORMAT_IDENTIFIER = {70, 65, 67, 0};
    private static final byte[] VERSION_NUMBER = {ISO7816.INS_DECREASE, 49, ISO7816.INS_DECREASE, 0};
    private List<FaceInfo> faces;

    public byte[] getEncoded() {
        return new byte[0];
    }

    public DLDG6File() {
        this.dataGroupTag = 117;
        if (this.faces == null) {
            this.faces = new ArrayList();
        }
        this.isSourceConsistent = false;
    }

    public DLDG6File(InputStream inputStream) throws IOException {
        super(inputStream, 117);
        if (this.faces == null) {
            this.faces = new ArrayList();
        }
    }

    /* access modifiers changed from: protected */
    public void readBiometricData(InputStream inputStream, int i) throws IOException {
        if (!inputStream.markSupported()) {
            inputStream = new BufferedInputStream(inputStream, i + 1);
        }
        DataInputStream dataInputStream = inputStream instanceof DataInputStream ? (DataInputStream) inputStream : new DataInputStream(inputStream);
        dataInputStream.readInt();
        dataInputStream.readInt();
        dataInputStream.readInt();
        int readUnsignedShort = dataInputStream.readUnsignedShort();
        for (int i2 = 0; i2 < readUnsignedShort; i2++) {
            addFaceInfo(new FaceInfo(dataInputStream));
        }
    }

    public void addFaceInfo(FaceInfo faceInfo) {
        if (this.faces == null) {
            this.faces = new ArrayList();
        }
        this.faces.add(faceInfo);
        this.isSourceConsistent = false;
    }

    public void removeFaceInfo(int i) {
        this.faces.remove(i);
        this.isSourceConsistent = false;
    }

    public String toString() {
        StringBuilder stringBuffer = new StringBuilder();
        stringBuffer.append("DG6File");
        stringBuffer.append(" [");
        int size = this.faces.size();
        int i = 0;
        for (FaceInfo next : this.faces) {
            stringBuffer.append(next.getWidth()).append("x").append(next.getHeight());
            if (i < size - 1) {
                stringBuffer.append(", ");
            }
            i++;
        }
        stringBuffer.append("]");
        return stringBuffer.toString();
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj.getClass() != DLDG6File.class) {
            return false;
        }
        DLDG6File dG6File = (DLDG6File) obj;
        if (this.faces != null) {
            return Arrays.equals(getEncoded(), dG6File.getEncoded());
        }
        return dG6File.faces == null;
    }

    public int hashCode() {
        List<FaceInfo> list = this.faces;
        if (list == null) {
            return 7191124;
        }
        return (list.hashCode() * 7) + 17;
    }

    public List<FaceInfo> getFaces() {
        return this.faces;
    }
}
