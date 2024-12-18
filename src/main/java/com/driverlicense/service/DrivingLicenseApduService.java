package com.driverlicense.service;


import net.sf.scuba.smartcards.*;
import net.sf.scuba.util.Hex;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;


public class DrivingLicenseApduService
        extends CardService {
    private static final long serialVersionUID = -7938380948364076484L;
    private static final byte[] APPLET_AID = {ISOFileInfo.A0, 0, 0, 2, 72, 2, 0};


    private static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(
            new byte[8]);

    private CardService service;

    private Cipher cipher;

    private Mac mac;

    public DrivingLicenseApduService(CardService service) throws CardServiceException {
        this.service = service;
        try {
            this.cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            this.mac = Mac.getInstance("ISO9797Alg3Mac");
        } catch (GeneralSecurityException gse) {
            throw new CardServiceException(gse.toString());
        }
    }


    public void open() throws CardServiceException {
        if (!this.service.isOpen()) {
            this.service.open();
        }
        sendSelectApplet();
    }

    public synchronized boolean isOpen() {
        return this.service.isOpen();
    }

    private void sendSelectApplet() throws CardServiceException {
        int sw = sendSelectApplet(APPLET_AID);
        if (sw != 36864) {
            throw new CardServiceException("Could not select driving license");
        }
    }


    public synchronized ResponseAPDU transmit(CommandAPDU capdu) throws CardServiceException {
        return this.service.transmit(capdu);
    }

    @Override
    public byte[] getATR() throws CardServiceException {
        return new byte[0];
    }

    public void close() {
        if (this.service != null) {
            this.service.close();
        }
    }

    @Override
    public boolean isConnectionLost(Exception e) {
        return false;
    }

    public void setService(CardService service) {
        this.service = service;
    }

    public void addAPDUListener(APDUListener l) {
        this.service.addAPDUListener(l);
    }

    public void removeAPDUListener(APDUListener l) {
        this.service.removeAPDUListener(l);
    }

    CommandAPDU createSelectAppletAPDU(byte[] aid) {
        return new CommandAPDU(0,
                -92, 4, 0, aid,
                1);
    }

    CommandAPDU createSelectFileAPDU(short fid) {
        byte[] fiddle = {(byte) (fid >> 8 & 0xFF),
                (byte) (fid & 0xFF)};
        return createSelectFileAPDU(fiddle);
    }

    private CommandAPDU createSelectFileAPDU(byte[] fid) {
        return new CommandAPDU(0,
                -92, 2, 12, fid, 256);
    }

    CommandAPDU createReadBinaryAPDU(short offset, int le) {
        byte p1 = (byte) ((offset & 0xFF00) >> 8);
        byte p2 = (byte) (offset & 0xFF);
        return new CommandAPDU(0,
                -80, p1, p2, le);
    }

    CommandAPDU createGetChallengeAPDU(int le) {
        byte p1 = 0;
        byte p2 = 0;
        return new CommandAPDU(0,
                -124, p1, p2, le);
    }

    CommandAPDU createInternalAuthenticateAPDU(byte[] rndIFD) {
        if (rndIFD == null || rndIFD.length != 8) {
            throw new IllegalArgumentException("rndIFD wrong length");
        }
        byte p1 = 0;
        byte p2 = 0;
        int le = 255;
        return new CommandAPDU(0,
                -120, p1, p2, rndIFD, le);
    }


    CommandAPDU createMutualAuthAPDU(byte[] rndIFD, byte[] rndICC, byte[] kIFD, SecretKey kEnc, SecretKey kMac) throws GeneralSecurityException {
        if (rndIFD == null || rndIFD.length != 8) {
            throw new IllegalArgumentException("rndIFD wrong length");
        }
        if (rndICC == null || rndICC.length != 8) {
            rndICC = new byte[8];
        }
        if (kIFD == null || kIFD.length != 16) {
            throw new IllegalArgumentException("kIFD wrong length");
        }
        if (kEnc == null) {
            throw new IllegalArgumentException("kEnc == null");
        }
        if (kMac == null) {
            throw new IllegalArgumentException("kMac == null");
        }

        this.cipher.init(1, kEnc, ZERO_IV_PARAM_SPEC);


        byte[] plaintext = new byte[32];
        System.arraycopy(rndIFD, 0, plaintext, 0, 8);
        System.arraycopy(rndICC, 0, plaintext, 8, 8);
        System.arraycopy(kIFD, 0, plaintext, 16, 16);
        byte[] ciphertext = this.cipher.doFinal(plaintext);
        if (ciphertext.length != 32) {
            throw new IllegalStateException("Cryptogram wrong length " +
                    ciphertext.length);
        }

        this.mac.init(kMac);
        byte[] mactext = this.mac.doFinal(Util.pad(ciphertext));
        if (mactext.length != 8) {
            throw new IllegalStateException("MAC wrong length");
        }

        byte p1 = 0;
        byte p2 = 0;

        byte[] data = new byte[40];
        System.arraycopy(ciphertext, 0, data, 0, 32);
        System.arraycopy(mactext, 0, data, 32, 8);
        int le = 40;
        return new CommandAPDU(0,
                -126, p1, p2, data, le);
    }


    CommandAPDU createMutualAuthAPDU(byte[] signature) {
        return new CommandAPDU(0,
                -126, 0, 0, signature);
    }


    CommandAPDU createPSOAPDU(byte[] certData, int offset, int length, boolean last) {
        byte p1 = 0;
        byte p2 = -66;
        byte[] data = new byte[length];
        System.arraycopy(certData, offset, data, 0, length);
        return new CommandAPDU((last ? 0 : 16), 42, p1, p2, data);
    }


    public synchronized void sendPSO(DESedeSecureMessagingWrapper wrapper, byte[] certData) throws CardServiceException {
        int maxBlock = 223;
        int blockSize = 223;
        int offset = 0;
        int length = certData.length;
        if (certData.length > maxBlock) {
            int numBlock = certData.length / blockSize;
            if (numBlock * blockSize < certData.length)
                numBlock++;
            int i = 0;
            while (i < numBlock - 1) {
                CommandAPDU commandAPDU = createPSOAPDU(certData, offset, blockSize,
                        false);
                if (wrapper != null) {
                    commandAPDU = wrapper.wrap(commandAPDU);
                }
                ResponseAPDU responseAPDU = transmit(commandAPDU);
                if (wrapper != null) {
                    responseAPDU = wrapper.unwrap(responseAPDU);
                }
                int j = responseAPDU.getSW();
                if ((short) j != -28672) {
                    throw new CardServiceException("Sending PSO failed.");
                }
                length -= blockSize;
                offset += blockSize;
                i++;
            }
        }
        CommandAPDU c = createPSOAPDU(certData, offset, length, true);
        if (wrapper != null) {
            c = wrapper.wrap(c);
        }
        ResponseAPDU r = transmit(c);
        if (wrapper != null) {
            r = wrapper.unwrap(r);
        }
        int sw = r.getSW();
        if ((short) sw != -28672) {
            throw new CardServiceException("Sending PSO failed.");
        }
    }


    public synchronized void sendMSE(DESedeSecureMessagingWrapper wrapper, int p1, int p2, byte[] data) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, 34,
                p1, p2, data);
        if (wrapper != null) {
            c = wrapper.wrap(c);
        }
        ResponseAPDU r = transmit(c);
        if (wrapper != null) {
            r = wrapper.unwrap(r);
        }
        int sw = r.getSW();
        if ((short) sw != -28672) {
            throw new CardServiceException("Sending MSE failed.");
        }
    }


    public synchronized void sendMutualAuthenticate(DESedeSecureMessagingWrapper wrapper, byte[] signature) throws CardServiceException {
        CommandAPDU c = createMutualAuthAPDU(signature);
        if (wrapper != null) {
            c = wrapper.wrap(c);
        }
        ResponseAPDU r = transmit(c);
        if (wrapper != null) {
            r = wrapper.unwrap(r);
        }
        int sw = r.getSW();
        if ((short) sw != -28672) {
            throw new CardServiceException(
                    "Sending External Authenticate failed.");
        }
    }


    public synchronized int sendSelectApplet(byte[] aid) throws CardServiceException {
        return transmit(createSelectAppletAPDU(aid)).getSW();
    }


    public synchronized void sendSelectFile(DESedeSecureMessagingWrapper wrapper, short fid) throws CardServiceException {
        CommandAPDU capdu = createSelectFileAPDU(fid);
        if (wrapper != null) {
            capdu = wrapper.wrap(capdu);
        }
        ResponseAPDU rapdu = transmit(capdu);
        if (wrapper != null) {
            rapdu = wrapper.unwrap(rapdu);
        }
        short sw = (short) rapdu.getSW();
        if (sw == 27266) {
            throw new CardServiceException("File not found.");
        }
        if (sw != -28672) {
            throw new CardServiceException("Error occured.");
        }
    }


    public synchronized byte[] sendReadBinary(short offset, int le) throws CardServiceException {
        return sendReadBinary(null, offset, le);
    }


    public synchronized byte[] sendReadBinary(DESedeSecureMessagingWrapper wrapper, short offset, int le) throws CardServiceException {
        boolean repeatOnEOF = false;
        ResponseAPDU rapdu = null;
        do {
            repeatOnEOF = false;

            if (le == 0) {
                return null;
            }
            CommandAPDU capdu = createReadBinaryAPDU(offset, le);
            if (wrapper != null) {
                capdu = wrapper.wrap(capdu);
            }
            rapdu = transmit(capdu);
            if (wrapper != null) {
                rapdu = wrapper.unwrap(rapdu);
            }
            if (rapdu.getSW() != 25218)
                continue;
            le--;
            repeatOnEOF = true;
        }
        while (repeatOnEOF);
        return rapdu.getData();
    }


    public synchronized byte[] sendGetChallenge(DESedeSecureMessagingWrapper wrapper) throws CardServiceException {
        CommandAPDU capdu = createGetChallengeAPDU(8);
        if (wrapper != null) {
            capdu = wrapper.wrap(capdu);
        }
        ResponseAPDU rapdu = transmit(capdu);
        if (wrapper != null) {
            rapdu = wrapper.unwrap(rapdu);
        }
        return rapdu.getData();
    }


    public synchronized byte[] sendInternalAuthenticate(DESedeSecureMessagingWrapper wrapper, byte[] rndIFD) throws CardServiceException {
        CommandAPDU capdu = createInternalAuthenticateAPDU(rndIFD);
        if (wrapper != null) {
            capdu = wrapper.wrap(capdu);
        }
        ResponseAPDU rapdu = transmit(capdu);
        if (wrapper != null) {
            rapdu = wrapper.unwrap(rapdu);
        }
        return rapdu.getData();
    }


    public synchronized byte[] sendMutualAuth(byte[] rndIFD, byte[] rndICC, byte[] kIFD, SecretKey kEnc, SecretKey kMac) throws CardServiceException {
        try {
            ResponseAPDU rapdu = transmit(
                    createMutualAuthAPDU(rndIFD, rndICC, kIFD, kEnc, kMac));
            byte[] rapduBytes = rapdu.getBytes();
            String errorCode = Hex.shortToHexString((short) rapdu.getSW());
            if (rapduBytes.length == 2) {
                throw new CardServiceException(
                        "Mutual authentication failed: error code:  " +
                                errorCode);
            }

            if (rapduBytes.length != 42) {
                throw new CardServiceException(
                        "Mutual authentication failed: expected length: 42, actual length: " +
                                rapduBytes.length + ", error code: " +
                                errorCode);
            }


            this.cipher.init(2, kEnc, ZERO_IV_PARAM_SPEC);
            byte[] result = this.cipher.doFinal(rapduBytes, 0,
                    rapduBytes.length - 8 - 2);
            if (result.length != 32) {
                throw new IllegalStateException("Cryptogram wrong length " +
                        result.length);
            }
            return result;
        } catch (GeneralSecurityException gse) {
            throw new CardServiceException(gse.toString());
        }
    }

    public CardService getService() {
        return this.service;
    }
}


/* Location:              /Users/elhadjhocine/Downloads/isodl-20110215/lib/drivinglicense.jar!/org/isodl/service/DrivingLicenseApduService.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */