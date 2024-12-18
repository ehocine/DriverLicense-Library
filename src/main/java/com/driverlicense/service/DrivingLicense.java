package com.driverlicense.service;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardServiceException;
import org.ejbca.cvc.CVCertificate;

import java.io.*;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.*;


public class DrivingLicense {
    private static final int BUFFER_SIZE = 243;
    private Map<Short, InputStream> rawStreams = new HashMap<Short, InputStream>();

    private Map<Short, InputStream> bufferedStreams = new HashMap<Short, InputStream>();

    private Map<Short, byte[]> filesBytes = (Map) new HashMap<Short, Byte>();

    private Map<Short, Integer> fileLengths = new TreeMap<Short, Integer>();

    private Map<Short, Boolean> eapFlags = new TreeMap<Short, Boolean>();

    private int bytesRead = 0;

    private int totalLength = 0;


    private DLCOMFile DLCOMFile = null;

    private SODFile sodFile = null;

    private boolean eapSupport = false;

    private boolean eapSuccess = false;

    private CVCertificate cvcaCertificate = null;

    private PrivateKey eapPrivateKey = null;

    private PrivateKey aaPrivateKey = null;

    private DocumentSigner signer = null;

    private List<Short> eapFids = new ArrayList<Short>();

    private byte[] keySeed = null;

    private boolean updateCOMSODfiles = true;


    public DrivingLicense(DrivingLicenseService service) throws IOException, CardServiceException {
        this(service, null);
    }

    public DrivingLicense(DrivingLicenseService drivingLicenseService, String str) throws IOException, CardServiceException {
        this.rawStreams = new HashMap<>();
        this.bufferedStreams = new HashMap<>();
        this.filesBytes = new HashMap<>();
        this.fileLengths = new TreeMap<>();
        this.eapFlags = new TreeMap<>();
        this.bytesRead = 0;
        this.totalLength = 0;
        this.DLCOMFile = null;
        this.sodFile = null;
        this.eapSupport = false;
        this.eapSuccess = false;
        this.cvcaCertificate = null;
        this.eapPrivateKey = null;
        this.aaPrivateKey = null;
        this.signer = null;
        this.eapFids = new ArrayList<>();
        this.keySeed = null;
        BufferedInputStream preReadFile = preReadFile(drivingLicenseService, (short) 30);
        this.DLCOMFile = new DLCOMFile(preReadFile);
        preReadFile.reset();
        processSecurityObjectIndicators();
        processTagList(drivingLicenseService);

        BufferedInputStream sodStream = preReadFile(drivingLicenseService, (short) 29);
        this.sodFile = new SODFile(sodStream);
        sodStream.reset();
    }

    private void processSecurityObjectIndicators() {
        for (SecurityObjectIndicator securityObjectIndicator : this.DLCOMFile.getSOIArray()) {
            if (securityObjectIndicator instanceof SecurityObjectIndicatorDG14 soiDG14) {
                this.eapSupport = true;

                for (Integer dataGroup : soiDG14.getDataGroups()) {
                    short fid = DrivingLicenseFile.lookupFIDByTag(DrivingLicenseFile.lookupTagByDataGroupNumber(dataGroup));
                    this.eapFids.add(fid);
                    this.eapFlags.put(fid, true);
                }
            }
        }
    }

    private void processTagList(DrivingLicenseService drivingLicenseService) throws CardServiceException, IOException {
        for (Integer tag : this.DLCOMFile.getTagList()) {
            short fid = DrivingLicenseFile.lookupFIDByTag(tag);

            if (fid == 14) {
                BufferedInputStream dg14Stream = preReadFile(drivingLicenseService, (short) 14);
                new DLDG14File(dg14Stream);
                dg14Stream.reset();
            } else if (!this.eapFids.contains(fid)) {
                setupFile(drivingLicenseService, fid);
            }
        }
    }

    private BufferedInputStream preReadFile(DrivingLicenseService service, short fid) throws CardServiceException {
        BufferedInputStream bufferedIn;

        if (this.rawStreams.containsKey(fid)) {
            int length = this.fileLengths.get(fid);
            bufferedIn = new BufferedInputStream(this.rawStreams.get(fid), length + 1);
            bufferedIn.mark(length + 1);
            return bufferedIn;
        }

        service.getFileSystem().selectFile(fid);
        CardFileInputStream cardIn = service.readFile();
        int length = cardIn.getLength();

        bufferedIn = new BufferedInputStream(cardIn, length + 1);
        this.totalLength += length;
        this.fileLengths.put(fid, length);
        bufferedIn.mark(length + 1);
        this.rawStreams.put(fid, bufferedIn);

        return bufferedIn;
    }

    private void setupFile(DrivingLicenseService service, short fid) throws CardServiceException {
        service.getFileSystem().selectFile(fid);
        CardFileInputStream in = service.readFile();
        int fileLength = in.getLength();
        in.mark(fileLength + 1);
        this.rawStreams.put(fid, in);
        this.totalLength += fileLength;
        this.fileLengths.put(fid, fileLength);
    }

    public synchronized InputStream getInputStream(short fid) {
        try {
            // Check if the file is already cached in memory
            byte[] file = this.filesBytes.get(fid);
            if (file != null) {
                ByteArrayInputStream in = new ByteArrayInputStream(file);
                in.mark(file.length + 1);
                return in;
            }

            // Check if a buffered stream exists
            InputStream in = this.bufferedStreams.get(fid);
            if (in != null) {
                if (in.markSupported()) {
                    in.reset();
                }
                return in;
            }

            // If no stream is available, start copying the raw input stream
            startCopyingRawInputStream(fid);
            return this.bufferedStreams.get(fid); // Return the newly created buffered stream
        } catch (IOException ioe) {
            throw new IllegalStateException("ERROR: Failed to get input stream for FID: " + fid, ioe);
        }
    }

    private synchronized void startCopyingRawInputStream(final short fid) throws IOException {
        // Retrieve the raw input stream for the given FID
        InputStream unBufferedIn = this.rawStreams.get(fid);
        if (unBufferedIn == null) {
            throw new IOException("No raw input stream to copy for FID: " + Integer.toHexString(fid));
        }

        // Get the file length and prepare streams
        int fileLength = this.fileLengths.get(fid);
        unBufferedIn.reset();
        PipedInputStream pipedIn = new PipedInputStream(fileLength + 1);
        PipedOutputStream out = new PipedOutputStream(pipedIn);
        ByteArrayOutputStream copyOut = new ByteArrayOutputStream(fileLength);

        // Wrap the piped input stream in a buffered input stream and cache it
        BufferedInputStream bufferedIn = new BufferedInputStream(pipedIn, fileLength + 1);
        bufferedIn.mark(fileLength + 1);
        this.bufferedStreams.put(fid, bufferedIn);

        // Start a new thread to handle the copying process
        new Thread(() -> {
            byte[] buffer = new byte[256]; // Use a larger buffer size for faster reads
            try {
                int bytesRead;
                while ((bytesRead = unBufferedIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    copyOut.write(buffer, 0, bytesRead);
                    synchronized (this) {
                        this.bytesRead += bytesRead;
                    }
                }
                out.flush();
                out.close();

                // Cache the full file contents in memory
                this.filesBytes.put(fid, copyOut.toByteArray());
                copyOut.close();
            } catch (IOException e) {
                try {
                    out.close();
                } catch (IOException ignored) {
                    // Suppress secondary exception
                }
                e.printStackTrace();
            }
        }).start();
    }

    public void putFile(short fid, byte[] bytes) {
        putFile(fid, bytes, false);
    }


    public void putFile(short fid, byte[] bytes, boolean eapProtection) {
        if (bytes == null) {
            return;
        }
        this.updateCOMSODfiles = true;
        this.filesBytes.put(fid, bytes);
        this.eapFlags.put(fid, eapProtection);
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        int fileLength = bytes.length;
        in.mark(fileLength + 1);
        this.bufferedStreams.put(fid, in);
        this.fileLengths.put(fid, fileLength);

        this.totalLength += fileLength;
        if (fid != 30 &&
                fid != 29) {
            updateCOMSODFile(null);
        }
    }


    public void removeFile(short fid) {
        this.filesBytes.remove(fid);
        this.eapFlags.remove(fid);
        int fileLength = (Integer) this.fileLengths.get(fid);
        this.bufferedStreams.remove(fid);
        this.fileLengths.remove(fid);
        this.totalLength -= fileLength;
        if (fid != 30 &&
                fid != 29) {
            updateCOMSODFile(null);
        }
    }

    private void updateCOMSODFile(X509Certificate newCertificate) {
        if (!this.updateCOMSODfiles || this.sodFile == null || this.DLCOMFile == null) {
            return;
        }
        try {
            String digestAlg = this.sodFile.getDigestAlgorithm();
            X509Certificate cert = (newCertificate != null) ? newCertificate :
                    this.sodFile.getDocSigningCertificate();

            String signatureAlg = cert.getSigAlgName();

            byte[] signature = this.sodFile.getEncryptedDigest();
            Map<Integer, byte[]> dgHashes = (Map) new TreeMap<Integer, Byte>();
            List<Short> dgFids = getFileList();
            if (dgFids.size() < 4) {
                return;
            }


            this.DLCOMFile.getTagList().clear();
            Collections.sort(dgFids);
            MessageDigest digest = MessageDigest.getInstance(digestAlg);
            for (Short fid : dgFids) {
                if (fid != 30 && fid != 29) {
                    byte[] data = getFileBytes(fid);
                    byte tag = data[0];
                    dgHashes.put(DrivingLicenseFile.lookupDataGroupNumberByTag(tag), digest.digest(data));
                    this.DLCOMFile.insertTag((int) tag);
                }
            }
            if (this.signer != null) {
                this.signer.setCertificate(cert);
                this.sodFile = new SODFile(digestAlg, signatureAlg, dgHashes, this.signer, cert);
            } else {
                this.sodFile = new SODFile(digestAlg, signatureAlg, dgHashes, signature, cert);
            }
            updateSOIS();
            putFile((short) 29, this.sodFile.getEncoded());
            putFile((short) 30, this.DLCOMFile.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public byte[] getFileBytes(short fid) {
        byte[] result = this.filesBytes.get(Short.valueOf(fid));
        if (result != null) {
            return result;
        }
        InputStream in = getInputStream(fid);
        if (in == null) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[256];
        while (true) {
            try {
                int bytesRead = in.read(buf);
                if (bytesRead < 0) {
                    break;
                }
                out.write(buf, 0, bytesRead);
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
        return out.toByteArray();
    }


    public void setSigner(DocumentSigner signer) {
        this.updateCOMSODfiles = true;
        this.signer = signer;
        updateCOMSODFile(null);
    }


    public void setDocSigningCertificate(X509Certificate newCertificate) {
        this.updateCOMSODfiles = true;
        updateCOMSODFile(newCertificate);
    }


    private void updateSOIS() {
        if (!this.updateCOMSODfiles || this.DLCOMFile == null) {
            return;
        }
        SecurityObjectIndicatorDG13 soi13 = null;
        SecurityObjectIndicatorDG14 soi14 = null;
        if (getFileList().contains((short) 13) && this.aaPrivateKey != null) {
            soi13 = new SecurityObjectIndicatorDG13(new ArrayList<Integer>());
        }
        if (getFileList().contains((short) 14) && this.eapPrivateKey != null && this.cvcaCertificate != null) {
            List<Integer> dgs = new ArrayList<Integer>();
            for (short fid : getFileList()) {
                if (this.eapFlags.get(fid)) {
                    dgs.add(DrivingLicenseFile.lookupDataGroupNumberByFID(fid));
                }
            }
            Collections.sort(dgs);
            soi14 = new SecurityObjectIndicatorDG14(this.cvcaCertificate, dgs);
        }
        int length = ((soi13 != null) ? 1 : 0) + ((soi14 != null) ? 1 : 0);
        SecurityObjectIndicator[] sois = new SecurityObjectIndicator[length];
        int index = 0;
        if (soi13 != null) {
            sois[index++] = soi13;
        }
        if (soi14 != null) {
            sois[index] = soi14;
        }
        this.DLCOMFile.setSOIArray(sois);
    }

    public void setCVCertificate(CVCertificate cert) {
        this.cvcaCertificate = cert;
        this.updateCOMSODfiles = true;
        updateSOIS();
    }


    public CVCertificate getCVCertificate() {
        return this.cvcaCertificate;
    }

    public DocumentSigner getSigner() {
        return this.signer;
    }


    public void setEAPKeys(KeyPair keyPair) {
        this.eapPrivateKey = keyPair.getPrivate();
        Map<Integer, PublicKey> key = new TreeMap<Integer, PublicKey>();
        key.put(-1, keyPair.getPublic());
        DLDG14File dg14file = new DLDG14File(key);
        putFile((short) 14, dg14file.getEncoded());
    }

    public void setAAKeys(KeyPair keyPair) {
        this.aaPrivateKey = keyPair.getPrivate();
        DLDG13File DLDG13File = new DLDG13File(keyPair.getPublic());
        putFile((short) 13, DLDG13File.getEncoded());
    }

    public PrivateKey getAAPrivateKey() {
        return this.aaPrivateKey;
    }

    public void setAAPrivateKey(PrivateKey key) {
        this.aaPrivateKey = key;
        updateSOIS();
    }

    public void setAAPublicKey(PublicKey key) {
        DLDG13File DLDG13File = new DLDG13File(key);
        putFile((short) 13, DLDG13File.getEncoded());
    }

    public PrivateKey getEAPPrivateKey() {
        return this.eapPrivateKey;
    }

    public boolean hasEAP() {
        return this.eapSupport;
    }

    public boolean wasEAPPerformed() {
        return this.eapSuccess;
    }


    public List<Short> getEAPFiles() {
        return this.eapFids;
    }


    public int getTotalLength() {
        return this.totalLength;
    }


    public int getBytesRead() {
        return this.bytesRead;
    }


    public List<Short> getFileList() {
        return new ArrayList<Short>(this.fileLengths.keySet());
    }


    public byte[] getKeySeed() {
        return this.keySeed;
    }


    public void setKeySeed(byte[] keySeed) {
        this.keySeed = keySeed;
    }


    public void upload(DrivingLicensePersoService persoService) throws CardServiceException {
        upload(persoService, null);
    }


    public void upload(DrivingLicensePersoService persoService, byte[] keySeed) throws CardServiceException {
        if (keySeed == null && this.keySeed != null) {
            keySeed = this.keySeed;
            if (keySeed.length != 16) {
                throw new CardServiceException("Wrong key seed length.");
            }
        }
        List<Short> fileList = getFileList();
        String sicId = null;
        boolean enableAASupport = (this.aaPrivateKey != null);
        if (fileList.contains((short) 13) != enableAASupport) {
            throw new CardServiceException("DG13 present, but no AA private key found, or vice versa.");
        }

        boolean enableCASupport = (this.eapPrivateKey != null);
        if (fileList.contains((short) 14) != enableCASupport) {
            throw new CardServiceException("DG14 present, but no CA private key found, or vice versa.");
        }
        boolean enableTASupport = (enableCASupport && this.cvcaCertificate != null);
        List<Integer> eapDGS = new ArrayList<Integer>();
        byte b;
        int i;
        SecurityObjectIndicator[] arrayOfSecurityObjectIndicator;
        for (i = (arrayOfSecurityObjectIndicator = this.DLCOMFile.getSOIArray()).length, b = 0; b < i; ) {
            SecurityObjectIndicator soi = arrayOfSecurityObjectIndicator[b];
            if (soi instanceof SecurityObjectIndicatorDG13) {
                if (!enableAASupport) {
                    throw new CardServiceException("AA support declared in COM, but no required AA data present.");
                }
            } else if (soi instanceof SecurityObjectIndicatorDG14) {
                if (!enableTASupport) {
                    throw new CardServiceException("EAP support declared in COM, but no required CA/TA data present.");
                }
                eapDGS.addAll(((SecurityObjectIndicatorDG14) soi).getDataGroups());
            }
            b++;
        }

        for (short fid : fileList) {
            byte[] fileBytes = getFileBytes(fid);
            boolean eapProtection = eapDGS.contains(DrivingLicenseFile.lookupDataGroupNumberByFID(fid));
            persoService.createFile(fid, (short) fileBytes.length, eapProtection);
            persoService.selectFile(fid);
            ByteArrayInputStream in = new ByteArrayInputStream(fileBytes);
            persoService.writeFile(fid, in);
            if (enableTASupport && fid == 1) {
                try {
                    DLDG1File dg1 = new DLDG1File(new ByteArrayInputStream(fileBytes));
                    sicId = (dg1.getDriverInfo()).number;
                } catch (IOException _) {
                }
            }
        }
        if (enableAASupport) {
            persoService.putPrivateKey(this.aaPrivateKey);
        }
        if (enableCASupport) {
            persoService.putPrivateEAPKey((ECPrivateKey) this.eapPrivateKey);
        }
        if (enableTASupport) {
            persoService.putCVCertificate(this.cvcaCertificate);
            persoService.setSicId(sicId);
        }
        if (keySeed != null) {
            persoService.setBAP(keySeed);
        }
        persoService.lockApplet();
    }
}