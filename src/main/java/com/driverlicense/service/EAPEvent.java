package com.driverlicense.service;

import org.ejbca.cvc.CVCertificate;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;

import java.io.Serial;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;


public class EAPEvent
        extends EventObject {
    @Serial
    private static final long serialVersionUID = 9152021138227662926L;
    private final DrivingLicenseService service;
    private final KeyPair keyPair;
    private final List<CVCertificate> terminalCertificates = new ArrayList<>();


    private final PrivateKey terminalKey;


    private final boolean success;


    private final String sicId;


    private final int keyId;


    private final byte[] cardChallenge;


    public EAPEvent(DrivingLicenseService service, int keyId, KeyPair keyPair, List<CVCertificate> terminalCertificates, PrivateKey terminalKey, String sicId, byte[] cardChallenge, boolean success) {
        super(service);
        this.service = service;
        this.keyId = keyId;
        this.keyPair = keyPair;
        this.success = success;
        this.terminalCertificates.addAll(terminalCertificates);
        this.terminalKey = terminalKey;
        this.sicId = sicId;
        this.cardChallenge = cardChallenge;
    }

    public DESedeSecureMessagingWrapper getWrapper() {
        return this.service.getWrapper();
    }


    public boolean isSuccess() {
        return this.success;
    }


    public KeyPair getKeyPair() {
        return this.keyPair;
    }


    public List<CVCertificate> getCVCertificates() {
        return this.terminalCertificates;
    }


    public PrivateKey getTerminalKey() {
        return this.terminalKey;
    }


    public String getSicId() {
        return this.sicId;
    }


    public int getKeyId() {
        return this.keyId;
    }


    public byte[] getCardChallenge() {
        return this.cardChallenge;
    }

    public DrivingLicenseService getService() {
        return this.service;
    }
}


/* Location:              /Users/elhadjhocine/Downloads/isodl-20110215/lib/drivinglicense.jar!/org/isodl/service/EAPEvent.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */