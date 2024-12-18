package com.driverlicense.service;


import net.sf.scuba.smartcards.*;
import net.sf.scuba.tlv.TLVInputStream;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CVCertificate;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import java.io.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;


public class DrivingLicenseService
        extends DrivingLicenseApduService implements Serializable {
    @Serial
    private static final long serialVersionUID = 1251224366317059401L;
    public static final short EF_DG1 = 1;
    public static final byte SF_DG1 = 1;
    public static final short EF_DG2 = 2;
    public static final byte SF_DG2 = 2;
    public static final short EF_DG3 = 3;
    public static final byte SF_DG3 = 3;
    public static final short EF_DG4 = 4;
    public static final byte SF_DG4 = 4;
    public static final short EF_DG5 = 5;
    public static final byte SF_DG5 = 5;
    public static final short EF_DG6 = 6;
    public static final byte SF_DG6 = 6;
    public static final short EF_DG7 = 7;
    public static final byte SF_DG7 = 7;
    public static final short EF_DG8 = 8;
    public static final byte SF_DG8 = 8;
    public static final short EF_DG9 = 9;
    public static final byte SF_DG9 = 9;
    public static final short EF_DG10 = 10;
    public static final byte SF_DG10 = 10;
    public static final short EF_DG11 = 11;
    public static final byte SF_DG11 = 11;
    public static final short EF_DG12 = 12;
    public static final byte SF_DG12 = 12;
    public static final short EF_DG13 = 13;
    public static final byte SF_DG13 = 13;
    public static final short EF_DG14 = 14;
    public static final byte SF_DG14 = 14;
    public static final short EF_SOD = 29;
    public static final byte SF_SOD = 29;
    public static final short EF_COM = 30;
    public static final byte SF_COM = 30;
    public static int maxBlockSize = 255;


    private static final int SESSION_STOPPED_STATE = 0;


    private static final int SESSION_STARTED_STATE = 1;


    private static final int BAP_AUTHENTICATED_STATE = 2;


    private static final int AA_AUTHENTICATED_STATE = 3;


    private static final int CA_AUTHENTICATED_STATE = 5;


    private static final int TA_AUTHENTICATED_STATE = 6;


    private static final int EAP_AUTHENTICATED_STATE = 7;


    private int state;


    private final Collection<AuthListener> authListeners;


    private DESedeSecureMessagingWrapper wrapper;


    private final Signature aaSignature;

    private final MessageDigest aaDigest;

    private final Cipher aaCipher;

    private final Random random;

    private final DrivingLicenseFileSystem fs;


    public DrivingLicenseService(CardService service) throws CardServiceException {
        super(service);
        try {
            this.aaSignature = Signature.getInstance("SHA1WithRSA/ISO9796-2");
            this.aaDigest = MessageDigest.getInstance("SHA1");
            this.aaCipher = Cipher.getInstance("RSA/NONE/NoPadding");
            this.random = new SecureRandom();
            this.authListeners = new ArrayList<AuthListener>();
            this.fs = new DrivingLicenseFileSystem(null);
        } catch (GeneralSecurityException gse) {
            throw new CardServiceException(gse.toString());
        }
        this.state = 0;
    }


    public void open() throws CardServiceException {
        if (isOpen()) {
            return;
        }
        super.open();
        this.state = 1;
    }

    public boolean isOpen() {
        return (this.state != 0);
    }


    public synchronized void doBAP(byte[] keySeed) throws CardServiceException {
        try {
            if (keySeed == null) {
                return;
            }
            if (keySeed.length < 16) {
                throw new IllegalStateException("Key seed too short");
            }
            SecretKey kEnc = Util.deriveKey(keySeed, 1);
            SecretKey kMac = Util.deriveKey(keySeed, 2);
            byte[] rndICC = sendGetChallenge(this.wrapper);
            byte[] rndIFD = new byte[8];
            this.random.nextBytes(rndIFD);
            byte[] kIFD = new byte[16];
            this.random.nextBytes(kIFD);
            byte[] response = sendMutualAuth(rndIFD, rndICC, kIFD, kEnc, kMac);
            byte[] kICC = new byte[16];
            System.arraycopy(response, 16, kICC, 0, 16);
            keySeed = new byte[16];
            for (int i = 0; i < 16; i++) {
                keySeed[i] = (byte) (kIFD[i] & 0xFF ^ kICC[i] & 0xFF);
            }
            SecretKey ksEnc = Util.deriveKey(keySeed, 1);
            SecretKey ksMac = Util.deriveKey(keySeed, 2);
            long ssc = Util.computeSendSequenceCounter(rndICC, rndIFD);
            this.wrapper = new DESedeSecureMessagingWrapper(ksEnc, ksMac, ssc);
            BAPEvent event = new BAPEvent(this, rndICC, rndIFD, kICC, kIFD,
                    true);
            notifyBAPPerformed(event);
            this.state = 2;
        } catch (GeneralSecurityException gse) {
            throw new CardServiceException(gse.toString());
        }
    }


    public void addAuthenticationListener(AuthListener l) {
        this.authListeners.add(l);
    }


    public void removeAuthenticationListener(AuthListener l) {
        this.authListeners.remove(l);
    }


    protected void notifyBAPPerformed(BAPEvent event) {
        for (AuthListener l : this.authListeners) {
            l.performedBAP(event);
        }
    }


    public boolean doAA(PublicKey publicKey) throws CardServiceException {
        try {
            byte[] m2 = new byte[8];
            this.random.nextBytes(m2);
            byte[] response = sendAA(publicKey, m2);
            this.aaCipher.init(2, publicKey);
            this.aaSignature.initVerify(publicKey);
            int digestLength = this.aaDigest.getDigestLength();
            byte[] plaintext = this.aaCipher.doFinal(response);
            byte[] m1 = Util.recoverMessage(digestLength, plaintext);
            this.aaSignature.update(m1);
            this.aaSignature.update(m2);
            boolean success = this.aaSignature.verify(response);
            AAEvent event = new AAEvent(this, publicKey, m1, m2, success);
            notifyAAPerformed(event);
            if (success) {
                this.state = 3;
            }
            return success;
        } catch (IllegalArgumentException | GeneralSecurityException iae) {
            throw new CardServiceException(iae.toString());
        }
    }


    public synchronized KeyPair doCA(int keyId, PublicKey key) throws CardServiceException {
        try {
            String algName = (key instanceof ECPublicKey) ? "ECDH" : "DH";
            KeyPairGenerator genKey = KeyPairGenerator.getInstance(algName);
            AlgorithmParameterSpec spec = null;
            if ("DH".equals(algName)) {
                DHPublicKey k = (DHPublicKey) key;
                spec = k.getParams();
            } else {
                ECPublicKey k = (ECPublicKey) key;
                spec = k.getParams();
            }

            genKey.initialize(spec);
            KeyPair keyPair = genKey.generateKeyPair();

            KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");
            agreement.init(keyPair.getPrivate());
            agreement.doPhase(key, true);


            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] secret = md.digest(agreement.generateSecret());

            byte[] keyData = (byte[]) null;
            if ("DH".equals(algName)) {
                DHPublicKey k = (DHPublicKey) keyPair.getPublic();
                keyData = k.getY().toByteArray();
            } else {
                ECPublicKey k = (ECPublicKey) keyPair
                        .getPublic();
                //                keyData = k.getQ().getEncoded();
                keyData = k.getEncoded();
            }
            keyData = tagData((byte) -111, keyData);

            sendMSE(this.wrapper, 65, 166, keyData);
            SecretKey ksEnc = Util.deriveKey(secret, 1);
            SecretKey ksMac = Util.deriveKey(secret, 2);
            this.wrapper = new DESedeSecureMessagingWrapper(ksEnc, ksMac, 0L);
            this.state = 5;
            return keyPair;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new CardServiceException(
                    "Problem occured during Chip Authentication: " +
                            ex.getMessage());
        }
    }


    public synchronized byte[] doTA(List<CVCertificate> terminalCertificates, PrivateKey terminalKey, String sicId) throws CardServiceException {
        try {
            String sigAlg = null;


            for (CVCertificate cert : terminalCertificates) {
                byte[] body = cert.getCertificateBody().getDEREncoded();
                byte[] arrayOfByte1 = cert.getSignature();
                byte[] certData = new byte[body.length + arrayOfByte1.length];
                System.arraycopy(body, 0, certData, 0, body.length);
                System.arraycopy(arrayOfByte1, 0, certData, body.length, arrayOfByte1.length);
                sendPSO(this.wrapper, certData);
                sigAlg = AlgorithmUtil.getAlgorithmName(cert
                        .getCertificateBody().getPublicKey()
                        .getObjectIdentifier());
            }


            byte[] challenge = sendGetChallenge(this.wrapper);

            Signature sig = Signature.getInstance(sigAlg);
            sig.initSign(terminalKey);

            ByteArrayOutputStream dtbs = new ByteArrayOutputStream();
            dtbs.write(sicId.getBytes());
            dtbs.write(challenge);

            sig.update(dtbs.toByteArray());


            sendMutualAuthenticate(this.wrapper, sig.sign());
            this.state = 6;
            return challenge;
        } catch (CardServiceException cse) {
            throw cse;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new CardServiceException("Problem occured during TA: " +
                    ex.getMessage());
        }
    }


    public synchronized void doEAP(int keyId, PublicKey key, List<CVCertificate> terminalCertificates, PrivateKey terminalKey, String sicId) throws CardServiceException {
        KeyPair keyPair = doCA(keyId, key);
        byte[] challenge = doTA(terminalCertificates, terminalKey, sicId);
        EAPEvent event = new EAPEvent(this, keyId, keyPair,
                terminalCertificates, terminalKey, sicId, challenge, true);
        notifyEAPPerformed(event);
        this.state = 7;
    }


    static byte[] tagData(byte tag, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(tag);
            out.write(data.length);
            out.write(data);
        } catch (IOException _) {
        }

        return out.toByteArray();
    }


    public byte[] sendAA(PublicKey publicKey, byte[] challenge) throws CardServiceException {
        if (publicKey == null) {
            throw new IllegalArgumentException("AA failed: bad key");
        }
        if (challenge == null || challenge.length != 8) {
            throw new IllegalArgumentException("AA failed: bad challenge");
        }
        return sendInternalAuthenticate(this.wrapper, challenge);
    }


    protected void notifyAAPerformed(AAEvent event) {
        for (AuthListener l : this.authListeners) {
            l.performedAA(event);
        }
    }


    protected void notifyEAPPerformed(EAPEvent event) {
        for (AuthListener l : this.authListeners) {
            l.performedEAP(event);
        }
    }

    public void close() {
        try {
            this.wrapper = null;
            super.close();
        } finally {
            this.state = 0;
        }
    }


    public DESedeSecureMessagingWrapper getWrapper() {
        return this.wrapper;
    }

    public FileSystemStructured getFileSystem() {
        return this.fs;
    }


    public CardFileInputStream readFile() throws CardServiceException {
        return new CardFileInputStream(maxBlockSize, this.fs);
    }


    public CardFileInputStream readDataGroup(int tag) throws CardServiceException {
        short fid = DrivingLicenseFile.lookupFIDByTag(tag);
        this.fs.selectFile(fid);
        return readFile();
    }

    private class DrivingLicenseFileSystem implements FileSystemStructured {
        private DrivingLicenseFileInfo selectedFile;

        private DrivingLicenseFileSystem(Object o) {
        }

        public synchronized byte[] readBinary(int offset, int length) throws CardServiceException {
            return DrivingLicenseService.this.sendReadBinary(DrivingLicenseService.this.wrapper, (short) offset, length);
        }


        public synchronized void selectFile(short fid) throws CardServiceException {
            DrivingLicenseService.this.sendSelectFile(DrivingLicenseService.this.wrapper, fid);
            this.selectedFile = new DrivingLicenseFileInfo(fid, getFileLength());
        }

        public synchronized int getFileLength() throws CardServiceException {
            try {
                byte[] prefix = readBinary(0, 8);
                ByteArrayInputStream baIn = new ByteArrayInputStream(prefix);
                TLVInputStream tlvIn = new TLVInputStream(baIn);
                tlvIn.readTag();
                int vLength = tlvIn.readLength();
                int tlLength = prefix.length - baIn.available();
                return tlLength + vLength;
            } catch (IOException ioe) {
                throw new CardServiceException(ioe.toString());
            }
        }

        public FileInfo[] getSelectedPath() {
            return (FileInfo[]) new DrivingLicenseFileInfo[]{this.selectedFile};
        }
    }

    private static class DrivingLicenseFileInfo
            extends FileInfo {
        private final short fid;
        private final int length;

        public DrivingLicenseFileInfo(short fid, int length) {
            this.fid = fid;
            this.length = length;
        }

        public short getFID() {
            return this.fid;
        }

        public int getFileLength() {
            return this.length;
        }
    }
}


/* Location:              /Users/elhadjhocine/Downloads/isodl-20110215/lib/drivinglicense.jar!/org/isodl/service/DrivingLicenseService.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */