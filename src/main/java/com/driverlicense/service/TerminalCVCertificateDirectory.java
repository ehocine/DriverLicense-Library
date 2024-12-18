package com.driverlicense.service;

import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;


public class TerminalCVCertificateDirectory {
    private static TerminalCVCertificateDirectory instance = null;


    private final Map<String, List<CVCertificate>> certificateListsMap;


    private final Map<String, PrivateKey> keysMap;


    private TerminalCVCertificateDirectory() {
        this.certificateListsMap = new HashMap<String, List<CVCertificate>>();

        this.keysMap = new HashMap<String, PrivateKey>();
    }

    public void addEntry(String caReference, List<CVCertificate> terminalCertificates, PrivateKey terminalKey) {
        if (caReference == null || this.certificateListsMap.containsKey(caReference)) {
            throw new IllegalArgumentException(
                    "Bad key (already present or null).");
        }
        if (terminalCertificates == null || terminalKey == null ||
                terminalCertificates.isEmpty()) {
            throw new IllegalArgumentException();
        }
        List<CVCertificate> list = new ArrayList<>(terminalCertificates);
        this.certificateListsMap.put(caReference, list);
        this.keysMap.put(caReference, terminalKey);
    }

    public static TerminalCVCertificateDirectory getInstance() {
        if (instance == null)
            instance = new TerminalCVCertificateDirectory();
        return instance;
    }

    public void scanOneDirectory(File f) throws IOException {
        if (!f.isDirectory()) {
            throw new IllegalArgumentException("File " + f.getAbsolutePath() +
                    " is not a directory.");
        }
        File[] certFiles = f.listFiles(new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.isFile() &&
                        pathname.getName().startsWith("terminalcert") &&
                        pathname.getName().endsWith(".cvcert");
            }
        });
        File[] keyFiles = f.listFiles(new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.isFile() &&
                        pathname.getName().equals("terminalkey.der");
            }
        });
        certFiles = sortFiles(certFiles);
        List<CVCertificate> terminalCertificates = new ArrayList<CVCertificate>();
        String keyAlgName = "RSA";
        byte b;
        int i;
        File[] arrayOfFile1;
        for (i = (arrayOfFile1 = certFiles).length, b = 0; b < i; ) {
            File file = arrayOfFile1[b];
            System.out.println("Found certificate file: " + file);
            CVCertificate c = readCVCertificateFromFile(file);
            if (c == null) {
                throw new IOException();
            }
            terminalCertificates.add(c);
            try {
                keyAlgName = c.getCertificateBody().getPublicKey()
                        .getAlgorithm();
            } catch (NoSuchFieldException _) {
            }
            b++;
        }

        assert keyFiles != null;
        if (keyFiles.length != 1) {
            throw new IOException();
        }
        System.out.println("Found key file: " + keyFiles[0]);
        PrivateKey k = readKeyFromFile(keyFiles[0], keyAlgName);
        if (k == null) {
            throw new IOException();
        }
        try {
            String ref = ((CVCertificate) terminalCertificates.getFirst()).getCertificateBody()
                    .getAuthorityReference().getConcatenated();
            addEntry(ref, terminalCertificates, k);
        } catch (Exception e) {
            throw new IOException();
        }
    }

    public void scanDirectory(File dir) throws IOException {
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException("File " + dir.getAbsolutePath() +
                    " is not a directory.");
        }
        File[] dirs = dir.listFiles(new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.isDirectory();
            }
        });
        try {
            byte b;
            int i;
            File[] arrayOfFile;
            for (i = (Objects.requireNonNull(arrayOfFile = dirs)).length, b = 0; b < i; ) {
                File f = arrayOfFile[b];
                scanOneDirectory(f);
                b++;
            }

        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    public List<CVCertificate> getCertificates(String key) {
        return this.certificateListsMap.get(key);
    }

    public PrivateKey getPrivateKey(String key) {
        return this.keysMap.get(key);
    }

    public Set<String> getKeys() {
        return this.certificateListsMap.keySet();
    }

    private static File[] sortFiles(File[] files) {
        List<File> l = new ArrayList<File>();
        byte b;
        int i;
        File[] arrayOfFile;
        for (i = (arrayOfFile = files).length, b = 0; b < i; ) {
            File f = arrayOfFile[b];
            l.add(f);
            b++;
        }

        Comparator<File> c = new Comparator<File>() {
            public int compare(File o1, File o2) {
                return o1.getName().compareTo(o2.getName());
            }
        };
        l.sort(c);
        l.toArray(files);
        return files;
    }

    private static byte[] loadFile(File file) throws IOException {
        byte[] dataBuffer = (byte[]) null;
        FileInputStream inStream = null;

        try {
            int length = (int) file.length();
            dataBuffer = new byte[length];
            inStream = new FileInputStream(file);

            int offset = 0;
            int readBytes = 0;
            boolean readMore = true;
            while (readMore) {
                readBytes = inStream.read(dataBuffer, offset, length - offset);
                offset += readBytes;
                readMore = (readBytes > 0 && offset != length);
            }
        } finally {
            try {
                if (inStream != null)
                    inStream.close();
            } catch (IOException e1) {
                System.out.println("loadFile - error when closing: " + e1);
            }
        }
        return dataBuffer;
    }

    private static CVCertificate readCVCertificateFromFile(File f) {
        try {
            byte[] data = loadFile(f);
            return CertificateParser.parseCertificate(data);
        } catch (Exception e) {
            return null;
        }
    }


    private static PrivateKey readKeyFromFile(File f, String algName) {
        try {
            byte[] data = loadFile(f);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
            KeyFactory gen = KeyFactory.getInstance(algName);
            return gen.generatePrivate(spec);
        } catch (Exception e) {
            return null;
        }
    }
}