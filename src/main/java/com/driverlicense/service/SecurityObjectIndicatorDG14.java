package com.driverlicense.service;

import org.bouncycastle.asn1.*;
import org.ejbca.cvc.CVCertificate;

import java.util.ArrayList;
import java.util.List;


public class SecurityObjectIndicatorDG14
        extends SecurityObjectIndicator {
    public static final ASN1ObjectIdentifier id_bap_conf1 = new ASN1ObjectIdentifier(
            "1.0.18013.3.2.1.1");

    public static final ASN1ObjectIdentifier id_eap = new ASN1ObjectIdentifier(
            "1.0.18013.3.2.2");

    private final List<Integer> dataGroups = new ArrayList<Integer>();


    private final byte[] certificateSubjectId;


    public SecurityObjectIndicatorDG14(CVCertificate cvCertificate, List<Integer> dataGroups) {
        try {
            this.dataGroups.addAll(dataGroups);
            this.certificateSubjectId = new byte[17];
            byte[] t = cvCertificate.getCertificateBody().getHolderReference()
                    .getConcatenated().getBytes();
            System.arraycopy(t, 0, this.certificateSubjectId, 1, t.length);
            this.certificateSubjectId[0] = (byte) t.length;

            DERSequence paramEAP = new DERSequence(new ASN1Encodable[]{
                    (ASN1Encodable) new ASN1Integer(0), (ASN1Encodable) new ASN1Integer(14), (ASN1Encodable) id_bap_conf1,
                    (ASN1Encodable) new DEROctetString(this.certificateSubjectId),
                    (ASN1Encodable) new DEROctetString(new byte[17])});
            DERSequence eapId = new DERSequence(new ASN1Encodable[]{(ASN1Encodable) id_eap,
                    (ASN1Encodable) paramEAP});
            ASN1Integer[] dgs = new ASN1Integer[dataGroups.size()];
            for (int i = 0; i < dgs.length; i++) {
                dgs[i] = new ASN1Integer((Integer) dataGroups.get(i));
            }
            this.sequence = new DERSequence(new ASN1Encodable[]{(ASN1Encodable) eapId,
                    (ASN1Encodable) new DERSet((ASN1Encodable[]) dgs)});
        } catch (Exception e) {
            throw new IllegalArgumentException();
        }
    }


    public SecurityObjectIndicatorDG14(DERSequence seq) {
        this.sequence = seq;
        ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(0);
        ASN1Integer ver = (ASN1Integer) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(0);
        ASN1Integer dg = (ASN1Integer) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
        ASN1ObjectIdentifier bap = (ASN1ObjectIdentifier) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(2);
        DEROctetString sub = (DEROctetString) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(3);
        DERSet dgs = (DERSet) this.sequence.getObjectAt(1);
        if (!id.equals(id_eap) || ver.getValue().intValue() != 0 ||
                dg.getValue().intValue() != 14 || !bap.equals(id_bap_conf1)) {
            throw new IllegalArgumentException();
        }
        this.certificateSubjectId = sub.getOctets();
        for (int i = 0; i < dgs.size(); i++) {
            this.dataGroups.add(((ASN1Integer) dgs.getObjectAt(i)).getValue().intValue());
        }
    }

    public byte[] getCertificateSubjectId() {
        return this.certificateSubjectId;
    }


    public List<Integer> getDataGroups() {
        return this.dataGroups;
    }

    public String toString() {
        String subject = "subject: " +
                new String(this.certificateSubjectId, 1, this.certificateSubjectId[0]);
        String result = "SOI DG14, " + id_eap.getId() + ", " + subject;
        if (!this.dataGroups.isEmpty()) {
            result = result + ", DGs:";
            for (Integer i : this.dataGroups) {
                result = String.valueOf(result) + " DG" + i.toString();
            }
        }
        return result;
    }
}