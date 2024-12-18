package com.driverlicense.service;

import com.driverlicense.tlv.BERTLVObject;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.util.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;


public class SODFile
        extends DrivingLicenseFile {
    private static final ASN1ObjectIdentifier ICAO_SOD_OID = new ASN1ObjectIdentifier(
            "2.23.136.1.1.1");

    private static final ASN1ObjectIdentifier SIGNED_DATA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.7.2");

    private static final ASN1ObjectIdentifier RFC_3369_CONTENT_TYPE_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.9.3");

    private static final ASN1ObjectIdentifier RFC_3369_MESSAGE_DIGEST_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.9.4");

    private static final ASN1ObjectIdentifier RSA_SA_PSS_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.10");

    private static final ASN1ObjectIdentifier PKCS1_SHA1_WITH_RSA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.5");

    private static final ASN1ObjectIdentifier PKCS1_SHA256_WITH_RSA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.11");

    private static final ASN1ObjectIdentifier PKCS1_SHA384_WITH_RSA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.12");

    private static final ASN1ObjectIdentifier PKCS1_SHA512_WITH_RSA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.13");

    private static final ASN1ObjectIdentifier PKCS1_SHA224_WITH_RSA_OID = new ASN1ObjectIdentifier(
            "1.2.840.113549.1.1.14");


    private final SignedData signedData;


    public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm, Map<Integer, byte[]> dataGroupHashes, byte[] encryptedDigest, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException, IOException {
        this.signedData = createSignedData(digestAlgorithm, digestEncryptionAlgorithm, dataGroupHashes, encryptedDigest, docSigningCertificate);
    }


    public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm, Map<Integer, byte[]> dataGroupHashes, DocumentSigner signer, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException, IOException {
        this.signedData = createSignedData(digestAlgorithm, digestEncryptionAlgorithm, dataGroupHashes, signer, docSigningCertificate);
    }

    public SODFile(InputStream inputStream) throws IOException {
        TLVInputStream tLVInputStream = new TLVInputStream(inputStream);
        if (tLVInputStream.readTag() == 119) {
            tLVInputStream.readLength();
            ASN1Sequence aSN1Sequence = (ASN1Sequence) new ASN1InputStream(inputStream).readObject();
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence.getObjectAt(0);
            if (aSN1ObjectIdentifier.equals(SIGNED_DATA_OID)) {
                this.signedData = SignedData.getInstance(((DLTaggedObject) aSN1Sequence.getObjectAt(1)).getBaseObject());
                return;
            }
            throw new IOException("Wrong OID: " + aSN1ObjectIdentifier.getId());
        }
        throw new IOException("Wrong tag");
    }

    public int getTag() {
        return 119;
    }


    public byte[] getEncoded() throws IOException {
        if (this.isSourceConsistent) {
            return this.sourceObject.getEncoded();
        }


        ASN1Encodable[] fileContents = {SIGNED_DATA_OID,
                new DERTaggedObject(0, (ASN1Encodable) this.signedData)};
        DERSequence dERSequence = new DERSequence(fileContents);
        BERTLVObject sodFile = new BERTLVObject(119,
                dERSequence.getEncoded(), false);
        return sodFile.getEncoded();
    }

    public String toString() {
        try {
            X509Certificate cert = getDocSigningCertificate();
            return "SODFile " + cert.getIssuerX500Principal();
        } catch (Exception e) {
            return "SODFile";
        }
    }


    public Map<Integer, byte[]> getDataGroupHashes() {
        DataGroupHash[] hashObjects = getSecurityObject(this.signedData)
                .getDatagroupHash();
        Map<Integer, byte[]> hashMap = (Map) new TreeMap<Integer, Byte>();


        for (DataGroupHash hashObject : hashObjects) {
            int number = hashObject.getDataGroupNumber();
            byte[] hashValue = hashObject.getDataGroupHashValue().getOctets();
            hashMap.put(number, hashValue);
        }
        return hashMap;
    }


    public byte[] getEncryptedDigest() {
        return getEncryptedDigest(this.signedData);
    }


    public String getDigestAlgorithm() {
        try {
            return lookupMnemonicByOID(getSecurityObject(this.signedData).getDigestAlgorithmIdentifier().getAlgorithm());
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            throw new IllegalStateException(nsae.toString());
        }
    }


    public String getDigestEncryptionAlgorithm() {
        try {
            return lookupMnemonicByOID(Objects.requireNonNull(getSignerInfo(this.signedData)).getDigestEncryptionAlgorithm().getAlgorithm());
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            throw new IllegalStateException(nsae.toString());
        }
    }


    public X509Certificate getDocSigningCertificate() throws IOException, CertificateException {
        byte[] certSpec = (byte[]) null;
        ASN1Set certs = this.signedData.getCertificates();
        if (certs.size() != 1) {
            System.err.println("WARNING: found " + certs.size() +
                    " certificates");
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(certSpec));
    }


    public boolean checkDocSignature(Certificate docSigningCert) throws GeneralSecurityException, IOException {
        byte[] eContent = getEContent();
        byte[] signature = getEncryptedDigest(this.signedData);

        String encAlg = Objects.requireNonNull(getSignerInfo(this.signedData)).getDigestEncryptionAlgorithm().getAlgorithm().getId();


        if (encAlg == null) {
            String digestAlg = Objects.requireNonNull(getSignerInfo(this.signedData)).getDigestAlgorithm().getAlgorithm().getId();
            MessageDigest digest = MessageDigest.getInstance(digestAlg);
            digest.update(eContent);
            byte[] digestBytes = digest.digest();
            return Arrays.equals(digestBytes, signature);
        }


        if (encAlg.equals(RSA_SA_PSS_OID.toString())) {
            encAlg =
                    String.valueOf(lookupMnemonicByOID(getSignerInfo(this.signedData).getDigestAlgorithm().getAlgorithm())) +
                            "withRSA/PSS";
        }

        Signature sig = Signature.getInstance(encAlg);
        sig.initVerify(docSigningCert);
        sig.update(eContent);
        return sig.verify(signature);
    }


    private static SignerInfo getSignerInfo(SignedData signedData) {
        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() > 1) {
            System.err.println("WARNING: found " + signerInfos.size() +
                    " signerInfos");
        }
        int i = 0;
        if (i < signerInfos.size()) {
            return SignerInfo.getInstance((ASN1Sequence) signerInfos.getObjectAt(i));
        }
        return null;
    }


    private static LDSSecurityObject getSecurityObject(SignedData signedData) {
        try {
            ContentInfo contentInfo = signedData.getEncapContentInfo();
            byte[] content = ((DEROctetString) contentInfo.getContent())
                    .getOctets();
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(
                    content));

            //            LDSSecurityObject sod = new LDSSecurityObject((ASN1Sequence) in.readObject());
            LDSSecurityObject sod = LDSSecurityObject.getInstance((ASN1Sequence) in.readObject());
            Object nextObject = in.readObject();

            if (nextObject != null) {
                System.err
                        .println("WARNING: extra object found after LDSSecurityObject...");
            }
            return sod;
        } catch (IOException ioe) {
            throw new IllegalStateException(
                    "Could not read security object in signedData");
        }
    }


    public byte[] getEContent() throws IOException {
        SignerInfo signerInfo = getSignerInfo(this.signedData);
        assert signerInfo != null;
        ASN1Set signedAttributesSet = signerInfo.getAuthenticatedAttributes();

        ContentInfo contentInfo = this.signedData.getEncapContentInfo();
        byte[] contentBytes = ((DEROctetString) contentInfo.getContent())
                .getOctets();

        if (signedAttributesSet.size() == 0) {
            return contentBytes;
        }

        byte[] attributesBytes = signedAttributesSet.getEncoded();
        String digAlg = signerInfo.getDigestAlgorithm().getAlgorithm().getId();


        try {
            Enumeration<?> attributes = signedAttributesSet.getObjects();
            byte[] storedDigestedContent = (byte[]) null;
            while (attributes.hasMoreElements()) {
                Attribute attribute = Attribute.getInstance(attributes.nextElement());
                ASN1ObjectIdentifier attrType = attribute.getAttrType();
                if (attrType.equals(RFC_3369_MESSAGE_DIGEST_OID)) {
                    ASN1Set attrValuesSet = attribute.getAttrValues();
                    if (attrValuesSet.size() != 1) {
                        System.err
                                .println("WARNING: expected only one attribute value in signedAttribute message digest in eContent!");
                    }
                    storedDigestedContent = ((DEROctetString) attrValuesSet
                            .getObjectAt(0)).getOctets();
                }
            }
            if (storedDigestedContent == null) {
                System.err
                        .println("WARNING: error extracting signedAttribute message digest in eContent!");
            }
            MessageDigest dig = MessageDigest.getInstance(digAlg);
            byte[] computedDigestedContent = dig.digest(contentBytes);
            if (!Arrays.equals(storedDigestedContent,
                    computedDigestedContent)) {
                System.err
                        .println("WARNING: error checking signedAttribute message digest in eContent!");
            }
        } catch (NoSuchAlgorithmException nsae) {
            System.err
                    .println("WARNING: error checking signedAttribute in eContent! No such algorithm " +
                            digAlg);
        }
        return attributesBytes;
    }


    private static byte[] getEncryptedDigest(SignedData signedData) {
        SignerInfo signerInfo = getSignerInfo(signedData);
        assert signerInfo != null;
        return signerInfo.getEncryptedDigest().getOctets();
    }


    private static SignedData createSignedData(String digestAlgorithm, String digestEncryptionAlgorithm, Map<Integer, byte[]> dataGroupHashes, byte[] encryptedDigest, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException, IOException {
        ASN1Set digestAlgorithmsSet = createSingletonSet((ASN1Encodable) createDigestAlgorithms(digestAlgorithm));
        ContentInfo contentInfo = createContentInfo(digestAlgorithm,
                dataGroupHashes);
        byte[] content = ((DEROctetString) contentInfo.getContent())
                .getOctets();
        ASN1Set certificates = createSingletonSet((ASN1Encodable) createCertificate(docSigningCertificate));
        ASN1Set crls = null;
        ASN1Set signerInfos = createSingletonSet((ASN1Encodable) createSignerInfo(
                digestAlgorithm, digestEncryptionAlgorithm, content,
                encryptedDigest, docSigningCertificate).toASN1Primitive());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates,
                crls, signerInfos);
    }


    private static SignedData createSignedData(String digestAlgorithm, String digestEncryptionAlgorithm, Map<Integer, byte[]> dataGroupHashes, DocumentSigner signer, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException, CertificateException, IOException {
        ASN1Set digestAlgorithmsSet = createSingletonSet((ASN1Encodable) createDigestAlgorithms(digestAlgorithm));
        ContentInfo contentInfo = createContentInfo(digestAlgorithm,
                dataGroupHashes);
        byte[] content = ((DEROctetString) contentInfo.getContent())
                .getOctets();

        byte[] encryptedDigest = (byte[]) null;
        byte[] dataToBeSigned = createAuthenticatedAttributes(
                digestAlgorithm, content).getEncoded();

        signer.setCertificate(docSigningCertificate);
        encryptedDigest = signer.signData(dataToBeSigned);
        if (encryptedDigest == null)
            return null;
        ASN1Set certificates = createSingletonSet((ASN1Encodable) createCertificate(docSigningCertificate));
        ASN1Set crls = null;
        ASN1Set signerInfos = createSingletonSet((ASN1Encodable) createSignerInfo(
                digestAlgorithm, digestEncryptionAlgorithm, content,
                encryptedDigest, docSigningCertificate).toASN1Primitive());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates,
                crls, signerInfos);
    }


    private static ASN1Sequence createDigestAlgorithms(String digestAlgorithm) throws NoSuchAlgorithmException {
        ASN1ObjectIdentifier algorithmIdentifier = lookupOIDByMnemonic(digestAlgorithm);
        ASN1Encodable[] result = {algorithmIdentifier, DERNull.INSTANCE};
        return (ASN1Sequence) new DERSequence(result);
    }


    private static ASN1Sequence createCertificate(X509Certificate cert) throws CertificateException {
        try {
            byte[] certSpec = cert.getEncoded();
            return (ASN1Sequence) (new ASN1InputStream(certSpec))
                    .readObject();
        } catch (IOException ioe) {
            throw new CertificateException(
                    "Could not construct certificate byte stream");
        }
    }


    private static ContentInfo createContentInfo(String digestAlgorithm, Map<Integer, byte[]> dataGroupHashes) throws NoSuchAlgorithmException, IOException {
        DataGroupHash[] dataGroupHashesArray = new DataGroupHash[dataGroupHashes
                .size()];
        int i = 0;
        for (int dataGroupNumber : dataGroupHashes.keySet()) {
            byte[] hashBytes = dataGroupHashes.get(dataGroupNumber);
            DataGroupHash hash = new DataGroupHash(dataGroupNumber,
                    (ASN1OctetString) new DEROctetString(hashBytes));
            dataGroupHashesArray[i++] = hash;
        }

        AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestAlgorithm), DERNull.INSTANCE);
        LDSSecurityObject sObject2 = new LDSSecurityObject(
                digestAlgorithmIdentifier, dataGroupHashesArray);
        return new ContentInfo(ICAO_SOD_OID, (ASN1Encodable) new DEROctetString((ASN1Encodable) sObject2));
    }


    private static SignerInfo createSignerInfo(String digestAlgorithm, String digestEncryptionAlgorithm, byte[] content, byte[] encryptedDigest, X509Certificate docSigningCertificate) throws NoSuchAlgorithmException {
        X500Principal docSignerPrincipal = docSigningCertificate
                .getIssuerX500Principal();
        X509Name docSignerName = new X509Name(true,
                docSignerPrincipal.getName());
        BigInteger serial = docSigningCertificate
                .getSerialNumber();
        SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(
                docSignerName, serial));

        AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestAlgorithm), DERNull.INSTANCE);
        AlgorithmIdentifier digestEncryptionAlgorithmObject = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestEncryptionAlgorithm), DERNull.INSTANCE);

        ASN1Set authenticatedAttributes = createAuthenticatedAttributes(
                digestAlgorithm, content);

        DEROctetString dEROctetString = new DEROctetString(
                encryptedDigest);
        ASN1Set unAuthenticatedAttributes = null;
        return new SignerInfo(sid, digestAlgorithmObject,
                authenticatedAttributes, digestEncryptionAlgorithmObject,
                (ASN1OctetString) dEROctetString, unAuthenticatedAttributes);
    }


    private static ASN1Set createAuthenticatedAttributes(String digestAlgorithm, byte[] contentBytes) throws NoSuchAlgorithmException {
        MessageDigest dig = MessageDigest.getInstance(digestAlgorithm);
        byte[] digestedContentBytes = dig.digest(contentBytes);
        DEROctetString dEROctetString = new DEROctetString(
                digestedContentBytes);
        Attribute contentTypeAttribute = new Attribute(
                RFC_3369_CONTENT_TYPE_OID, createSingletonSet((ASN1Encodable) ICAO_SOD_OID));
        Attribute messageDigestAttribute = new Attribute(
                RFC_3369_MESSAGE_DIGEST_OID,
                createSingletonSet((ASN1Encodable) dEROctetString));
        ASN1Encodable[] result = {(ASN1Encodable) contentTypeAttribute.toASN1Primitive(),
                (ASN1Encodable) messageDigestAttribute.toASN1Primitive()};
        return (ASN1Set) new DERSet(result);
    }

    private static ASN1Set createSingletonSet(ASN1Encodable e) {
        ASN1Encodable[] result = {e};
        return (ASN1Set) new DERSet(result);
    }


    static String lookupMnemonicByOID(ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException {
        if (oid.equals(X509ObjectIdentifiers.organization)) {
            return "O";
        }
        if (oid.equals(X509ObjectIdentifiers.organizationalUnitName)) {
            return "OU";
        }
        if (oid.equals(X509ObjectIdentifiers.commonName)) {
            return "CN";
        }
        if (oid.equals(X509ObjectIdentifiers.countryName)) {
            return "C";
        }
        if (oid.equals(X509ObjectIdentifiers.stateOrProvinceName)) {
            return "ST";
        }
        if (oid.equals(X509ObjectIdentifiers.localityName)) {
            return "L";
        }
        if (oid.equals(X509ObjectIdentifiers.id_SHA1)) {
            return "SHA1";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha224)) {
            return "SHA224";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha256)) {
            return "SHA256";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha384)) {
            return "SHA384";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512)) {
            return "SHA512";
        }
        if (oid.equals(PKCS1_SHA1_WITH_RSA_OID)) {
            return "SHA1withRSA";
        }
        if (oid.equals(PKCS1_SHA256_WITH_RSA_OID)) {
            return "SHA256withRSA";
        }
        if (oid.equals(PKCS1_SHA384_WITH_RSA_OID)) {
            return "SHA384withRSA";
        }
        if (oid.equals(PKCS1_SHA512_WITH_RSA_OID)) {
            return "SHA512withRSA";
        }
        if (oid.equals(PKCS1_SHA224_WITH_RSA_OID)) {
            return "SHA224withRSA";
        }
        throw new NoSuchAlgorithmException("Unknown OID " + oid);
    }


    static ASN1ObjectIdentifier lookupOIDByMnemonic(String name) throws NoSuchAlgorithmException {
        return switch (name) {
            case "O" -> X509ObjectIdentifiers.organization;
            case "OU" -> X509ObjectIdentifiers.organizationalUnitName;
            case "CN" -> X509ObjectIdentifiers.commonName;
            case "C" -> X509ObjectIdentifiers.countryName;
            case "ST" -> X509ObjectIdentifiers.stateOrProvinceName;
            case "L" -> X509ObjectIdentifiers.localityName;
            case "SHA1" -> X509ObjectIdentifiers.id_SHA1;
            case "SHA224" -> NISTObjectIdentifiers.id_sha224;
            case "SHA256" -> NISTObjectIdentifiers.id_sha256;
            case "SHA384" -> NISTObjectIdentifiers.id_sha384;
            case "SHA512" -> NISTObjectIdentifiers.id_sha512;
            case "SHA1withRSA" -> PKCS1_SHA1_WITH_RSA_OID;
            case "SHA256withRSA" -> PKCS1_SHA256_WITH_RSA_OID;
            case "SHA384withRSA" -> PKCS1_SHA384_WITH_RSA_OID;
            case "SHA512withRSA" -> PKCS1_SHA512_WITH_RSA_OID;
            case "SHA224withRSA" -> PKCS1_SHA224_WITH_RSA_OID;
            default -> throw new NoSuchAlgorithmException("Unknown OID " + name);
        };
    }


    public static void main(String[] args) {
        try {
            Security.addProvider((Provider) new BouncyCastleProvider());
            String fileName = "/home/sos/woj/examplesod.bin";
            InputStream in = new FileInputStream(new File(fileName));
            byte[] orig = new byte[in.available()];
            in.read(orig);
            System.out.println("ori0: " + Hex.bytesToHexString(orig));
            SODFile file = new SODFile(new ByteArrayInputStream(orig));
            byte[] orig1 = file.getEncoded();
            System.out.println("ori1: " + Hex.bytesToHexString(orig1));
            System.out.println("com o0 o1: " + Arrays.equals(orig, orig1));

            String digestAlgorithm = file.getDigestAlgorithm();
            String digestEncryptionAlgorithm = file
                    .getDigestEncryptionAlgorithm();
            Map<Integer, byte[]> dataGroupHashes = file.getDataGroupHashes();
            byte[] encryptedDigest = file.getEncryptedDigest();
            X509Certificate certificate = file.getDocSigningCertificate();

            SODFile file2 = new SODFile(digestAlgorithm,
                    digestEncryptionAlgorithm, dataGroupHashes,
                    encryptedDigest, certificate);
            byte[] enc = file2.getEncoded();
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("compare0: " + Arrays.equals(orig, enc));
            System.out.println("compare1: " + Arrays.equals(orig1, enc));

            SODFile file3 = new SODFile(new ByteArrayInputStream(enc));
            byte[] enc2 = file3.getEncoded();
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            System.out.println("compare: " + Arrays.equals(enc, enc2));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}