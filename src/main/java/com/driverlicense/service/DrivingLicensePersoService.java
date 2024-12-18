package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.smartcards.*;
import org.ejbca.cvc.CVCertificate;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;

import java.io.*;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldFp;

public class DrivingLicensePersoService extends CardService implements Serializable {
    private static final byte CVCERTIFICATE_TAG = 100;
    public static final boolean ECFP = true;
    private static final byte ECPRIVATE_TAG = 99;
    public static final String EC_CURVE_NAME = "prime192v1";
    private static final byte INS_PUT_DATA = -38;
    private static final byte KEYDOC_TAG = 98;
    private static final byte PRIVEXPONENT_TAG = 97;
    private static final byte PRIVMODULUS_TAG = 96;
    private static final byte SICID_TAG = 101;
    @Serial
    private static final long serialVersionUID = -2054600604861470052L;
    private final DrivingLicenseService service;

    public byte[] getATR() throws CardServiceException {
        return new byte[0];
    }

    public boolean isConnectionLost(Exception exc) {
        return false;
    }

    public DrivingLicensePersoService(CardService cardService) throws CardServiceException {
        DrivingLicenseService drivingLicenseService;
        if (cardService instanceof DrivingLicenseService) {
            drivingLicenseService = (DrivingLicenseService) cardService;
        } else {
            drivingLicenseService = new DrivingLicenseService(cardService);
        }
        this.service = drivingLicenseService;
    }

    private void putData(byte b, byte b2, byte[] bArr) throws CardServiceException {
        CommandAPDU commandAPDU = new CommandAPDU(0, -38, (int) b, (int) b2, bArr);
        DESedeSecureMessagingWrapper wrapper = this.service.getWrapper();
        if (wrapper != null) {
            commandAPDU = wrapper.wrap(commandAPDU);
        }
        ResponseAPDU transmit = this.service.transmit(commandAPDU);
        if (wrapper != null) {
            transmit = wrapper.unwrap(transmit);
        }
    }

    public void putPrivateKey(PrivateKey privateKey) throws CardServiceException {
        try {
            BERTLVObject instance = BERTLVObject.getInstance(new ByteArrayInputStream((byte[]) BERTLVObject.getInstance(new ByteArrayInputStream(privateKey.getEncoded())).getChildByIndex(2).getValue()));
            putPrivateKey((byte[]) instance.getChildByIndex(1).getValue(), (byte[]) instance.getChildByIndex(3).getValue());
        } catch (Exception e2) {
            throw new CardServiceException(e2.toString());
        }
    }

    private void putPrivateKey(byte[] bArr, byte[] bArr2) throws CardServiceException {
        try {
            putData((byte) 0, PRIVMODULUS_TAG, new BERTLVObject(96, new BERTLVObject(4, bArr)).getEncoded());
            putData((byte) 0, PRIVEXPONENT_TAG, new BERTLVObject(97, new BERTLVObject(4, bArr2)).getEncoded());
        } catch (Exception e) {
            throw new CardServiceException(e.toString());
        }
    }

    public void putPrivateEAPKey(ECPrivateKey eCPrivateKey) throws CardServiceException {
        byte[] byteArray = eCPrivateKey.getParams().getCurve().getA().toByteArray();
        byte[] byteArray2 = eCPrivateKey.getParams().getCurve().getB().toByteArray();
        byte[] byteArray3 = eCPrivateKey.getParams().getOrder().toByteArray();
        short cofactor = (short) eCPrivateKey.getParams().getCofactor();
        byte[] bArr = {(byte) ((65280 & cofactor) >> 8), (byte) (cofactor & 255)};
        ECFieldFp eCFieldFp = (ECFieldFp) eCPrivateKey.getParams().getCurve().getField();
        byte[] bArr2 = new byte[eCFieldFp.getFieldSize()];
        byte[] byteArray4 = eCFieldFp.getP().toByteArray();
        byte[] encoded = ((org.bouncycastle.jce.interfaces.ECPrivateKey) eCPrivateKey).getParameters().getG().getEncoded(false);
        byte[] byteArray5 = eCPrivateKey.getS().toByteArray();
        byte[] tagData = DrivingLicenseService.tagData(ISOFileInfo.DATA_BYTES2, byteArray4);
        byte[] tagData2 = DrivingLicenseService.tagData((byte) -126, byteArray);
        byte[] tagData3 = DrivingLicenseService.tagData(ISOFileInfo.FILE_IDENTIFIER, byteArray2);
        byte[] tagData4 = DrivingLicenseService.tagData((byte) -124, encoded);
        byte[] tagData5 = DrivingLicenseService.tagData(ISOFileInfo.PROP_INFO, byteArray3);
        byte[] tagData6 = DrivingLicenseService.tagData((byte) -122, byteArray5);
        byte[] tagData7 = DrivingLicenseService.tagData(ISOFileInfo.FCI_EXT, bArr);
        byte[] bArr3 = new byte[(tagData.length + tagData2.length + tagData3.length + tagData4.length + tagData5.length + tagData6.length + tagData7.length)];
        System.arraycopy(tagData, 0, bArr3, 0, tagData.length);
        int length = tagData.length;
        System.arraycopy(tagData2, 0, bArr3, length, tagData2.length);
        int length2 = length + tagData2.length;
        System.arraycopy(tagData3, 0, bArr3, length2, tagData3.length);
        int length3 = length2 + tagData3.length;
        System.arraycopy(tagData4, 0, bArr3, length3, tagData4.length);
        int length4 = length3 + tagData4.length;
        System.arraycopy(tagData5, 0, bArr3, length4, tagData5.length);
        int length5 = length4 + tagData5.length;
        System.arraycopy(tagData6, 0, bArr3, length5, tagData6.length);
        System.arraycopy(tagData7, 0, bArr3, length5 + tagData6.length, tagData7.length);
        int length6 = tagData7.length;
        putData((byte) 0, ECPRIVATE_TAG, bArr3);
    }

    public void putCVCertificate(CVCertificate cVCertificate) throws CardServiceException {
        try {
            putData((byte) 0, (byte) 100, cVCertificate.getCertificateBody().getDEREncoded());
        } catch (Exception e) {
            throw new CardServiceException(e.toString());
        }
    }

    public void setSicId(String str) throws CardServiceException {
        try {
            putData((byte) 0, SICID_TAG, str.getBytes());
        } catch (Exception e) {
            throw new CardServiceException(e.toString());
        }
    }

    public void createFile(short s, short s2) throws CardServiceException {
        sendCreateFile(this.service.getWrapper(), s, s2, false);
    }

    public void createFile(short s, short s2, boolean z) throws CardServiceException {
        sendCreateFile(this.service.getWrapper(), s, s2, z);
    }

    private CommandAPDU createCreateFileAPDU(short s, short s2, boolean z) {
        return new CommandAPDU(0, -32, z ? 1 : 0, 0, new byte[]{ECPRIVATE_TAG, 4, (byte) ((s2 >>> 8) & 255), (byte) (s2 & 255), (byte) ((s >>> 8) & 255), (byte) (s & 255)}, 0);
    }

    private void sendCreateFile(DESedeSecureMessagingWrapper dESedeDESedeSecureMessagingWrapper, short s, short s2, boolean z) throws CardServiceException {
        CommandAPDU createCreateFileAPDU = createCreateFileAPDU(s, s2, z);
        if (dESedeDESedeSecureMessagingWrapper != null) {
            createCreateFileAPDU = dESedeDESedeSecureMessagingWrapper.wrap(createCreateFileAPDU);
        }
        ResponseAPDU transmit = this.service.transmit(createCreateFileAPDU);
        if (dESedeDESedeSecureMessagingWrapper != null) {
            transmit = dESedeDESedeSecureMessagingWrapper.unwrap(transmit);
        }
    }

    private CommandAPDU createUpdateBinaryAPDU(short s, int i, byte[] bArr) {
        byte[] bArr2 = new byte[i];
        System.arraycopy(bArr, 0, bArr2, 0, i);
        return new CommandAPDU(0, -42, (int) (byte) ((s >>> 8) & 255), (int) (byte) (s & 255), bArr2);
    }

    private void sendUpdateBinary(DESedeSecureMessagingWrapper dESedeDESedeSecureMessagingWrapper, short s, int i, byte[] bArr) throws CardServiceException {
        CommandAPDU createUpdateBinaryAPDU = createUpdateBinaryAPDU(s, i, bArr);
        if (dESedeDESedeSecureMessagingWrapper != null) {
            createUpdateBinaryAPDU = dESedeDESedeSecureMessagingWrapper.wrap(createUpdateBinaryAPDU);
        }
        ResponseAPDU transmit = this.service.transmit(createUpdateBinaryAPDU);
        if (dESedeDESedeSecureMessagingWrapper != null) {
            transmit = dESedeDESedeSecureMessagingWrapper.unwrap(transmit);
        }
    }

    public void writeFile(short s, InputStream inputStream) throws CardServiceException {
        DESedeSecureMessagingWrapper wrapper = this.service.getWrapper();
        int i = 255;
        if (wrapper != null) {
            i = 223;
        }
        try {
            byte[] bArr = new byte[i];
            short s2 = 0;
            while (true) {
                int read = inputStream.read(bArr, 0, i);
                if (read != -1) {
                    sendUpdateBinary(wrapper, s2, read, bArr);
                    s2 = (short) (s2 + read);
                } else {
                    return;
                }
            }
        } catch (IOException e) {
            throw new CardServiceException(e.toString());
        }
    }

    public void setBAP(byte[] bArr) throws CardServiceException {
        if (bArr.length >= 16) {
            try {
                putData((byte) 0, (byte) 98, bArr);
            } catch (Exception e) {
                throw new CardServiceException(e.toString());
            }
        } else {
            throw new IllegalStateException("Key seed too short");
        }
    }

    public void lockApplet() throws CardServiceException {
        putData((byte) -34, (byte) -83, (byte[]) null);
    }

    public void selectFile(short s) throws CardServiceException {
        DrivingLicenseService drivingLicenseService = this.service;
        drivingLicenseService.sendSelectFile(drivingLicenseService.getWrapper(), s);
    }

    public void close() {
        this.service.close();
    }

    public boolean isOpen() {
        return this.service.isOpen();
    }

    public void open() throws CardServiceException {
        this.service.open();
    }

    public ResponseAPDU transmit(CommandAPDU commandAPDU) throws CardServiceException {
        return this.service.transmit(commandAPDU);
    }
}
