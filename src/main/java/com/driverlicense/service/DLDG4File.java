package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

public class DLDG4File extends DLDataGroup {
    private final Vector<FacePortrait> faces;

    public int getTag() {
        return 101;
    }

    public DLDG4File(List<FacePortrait> list) {
        Vector<FacePortrait> vector = new Vector<>();
        this.faces = vector;
        vector.addAll(list);
    }

    public DLDG4File(InputStream inputStream) throws IOException {
        this.faces = new Vector<>();
        TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
        int readTag = tLVInputStream.readTag();
        if (readTag == 101) {
            int i = 0;
            this.isSourceConsistent = false;
            tLVInputStream.readLength();
            BERTLVObject bERTLVObject = new BERTLVObject(readTag, tLVInputStream.readValue());
            byte b = ((byte[]) bERTLVObject.getSubObject(2).getValue())[0];
            while (i < b) {
                i++;
                this.faces.add(new FacePortrait(new ByteArrayInputStream(bERTLVObject.getChildByIndex(i).getEncoded())));
            }
            return;
        }
        throw new IllegalArgumentException("Expected EF_DG4_TAG");
    }

    public FacePortrait[] getFaces() {
        FacePortrait[] facePortraitArr = new FacePortrait[this.faces.size()];
        Iterator<FacePortrait> it = this.faces.iterator();
        int i = 0;
        while (it.hasNext()) {
            facePortraitArr[i] = it.next();
            i++;
        }
        return facePortraitArr;
    }

    public String toString() {
        return "DG4File: " + this.faces.size() + " portraits ";
    }

    public byte[] getEncoded() {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }
        try {
            BERTLVObject bERTLVObject = new BERTLVObject(101, new BERTLVObject(2, new byte[]{(byte) this.faces.size()}));
            for (int i = 0; i < this.faces.size(); i++) {
                bERTLVObject.addSubObject(this.faces.elementAt(i).getTLVObject());
            }
            bERTLVObject.reconstructLength();
            this.sourceObject = bERTLVObject;
            this.isSourceConsistent = true;
            return bERTLVObject.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
