package com.driverlicense.service;

import org.bouncycastle.asn1.*;

import java.util.ArrayList;
import java.util.List;


public class SecurityObjectIndicatorDG13
        extends SecurityObjectIndicator {
    public static final ASN1ObjectIdentifier id_aa = new ASN1ObjectIdentifier(
            "1.0.18013.3.2.3");

    private final List<Integer> dataGroups = new ArrayList<Integer>();


    public SecurityObjectIndicatorDG13(List<Integer> dataGroups) {
        this.dataGroups.addAll(dataGroups);
        DERSequence paramAA = new DERSequence(new ASN1Encodable[]{
                (ASN1Encodable) new ASN1Integer(0), (ASN1Encodable) new ASN1Integer(13)});
        DERSequence aaId = new DERSequence(
                new ASN1Encodable[]{(ASN1Encodable) id_aa, (ASN1Encodable) paramAA});
        ASN1Integer[] dgs = new ASN1Integer[this.dataGroups.size()];
        for (int i = 0; i < dgs.length; i++) {
            dgs[i] = new ASN1Integer((Integer) this.dataGroups.get(i));
        }
        this.sequence = new DERSequence(
                new ASN1Encodable[]{(ASN1Encodable) aaId, (ASN1Encodable) new DERSet((ASN1Encodable[]) dgs)});
    }


    public SecurityObjectIndicatorDG13(DERSequence seq) {
        this.sequence = seq;
        ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(0);
        ASN1Integer ver = (ASN1Integer) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(0);
        ASN1Integer dg = (ASN1Integer) ((DERSequence) ((DERSequence) this.sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
        DERSet dgs = (DERSet) this.sequence.getObjectAt(1);
        if (!id.equals(id_aa) || ver.getValue().intValue() != 0 ||
                dg.getValue().intValue() != 13) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < dgs.size(); i++) {
            this.dataGroups.add(((ASN1Integer) dgs.getObjectAt(i)).getValue().intValue());
        }
    }

    public List<Integer> getDataGroups() {
        return this.dataGroups;
    }

    public String toString() {
        StringBuilder result = new StringBuilder("SOI DG13, " + id_aa.getId());
        if (!this.dataGroups.isEmpty()) {
            result.append(", DGs:");
            for (Integer i : this.dataGroups) {
                result.append(" DG").append(i.toString());
            }
        }
        return result.toString();
    }
}