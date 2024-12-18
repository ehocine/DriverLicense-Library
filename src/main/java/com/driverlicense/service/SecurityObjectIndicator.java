package com.driverlicense.service;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;


public class SecurityObjectIndicator {
    protected DERSequence sequence;

    public SecurityObjectIndicator() {
    }

    public SecurityObjectIndicator(DERSequence sequence) {
        this.sequence = sequence;
    }

    public DERSequence getDERSequence() {
        return this.sequence;
    }

    public int getDGNumber() {
        try {
            ASN1Integer dg = (ASN1Integer) ((DERSequence) ((DERSequence) this.sequence
                    .getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
            return dg.getValue().intValue();
        } catch (Exception e) {
            return -1;
        }
    }

    public ASN1ObjectIdentifier getIdentifier() {
        try {
            return (ASN1ObjectIdentifier) ((DERSequence) this.sequence
                    .getObjectAt(0)).getObjectAt(0);
        } catch (Exception e) {
            return null;
        }
    }

    public String toString() {
        return "SOI DG" + getDGNumber() + ", id: " + getIdentifier().getId();
    }
}