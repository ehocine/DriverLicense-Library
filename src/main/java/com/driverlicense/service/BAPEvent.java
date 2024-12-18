package com.driverlicense.service;

import org.jmrtd.protocol.DESedeSecureMessagingWrapper;

import java.io.Serial;
import java.util.EventObject;


public class BAPEvent
        extends EventObject {
    @Serial
    private static final long serialVersionUID = -5177594173285843844L;
    private final DrivingLicenseService service;
    private final boolean success;
    private final byte[] rndICC;
    private final byte[] rndIFD;
    private final byte[] kICC;
    private final byte[] kIFD;

    public BAPEvent(DrivingLicenseService service, byte[] rndICC, byte[] rndIFD, byte[] kICC, byte[] kIFD, boolean success) {
        super(service);
        this.service = service;
        this.rndICC = rndICC;
        this.rndIFD = rndIFD;
        this.kICC = kICC;
        this.kIFD = kIFD;
        this.success = success;
    }


    public DESedeSecureMessagingWrapper getWrapper() {
        return this.service.getWrapper();
    }


    public boolean isSuccess() {
        return this.success;
    }


    public byte[] getKICC() {
        return this.kICC;
    }


    public byte[] getKIFD() {
        return this.kIFD;
    }


    public byte[] getRndICC() {
        return this.rndICC;
    }


    public byte[] getRndIFD() {
        return this.rndIFD;
    }

    public DrivingLicenseService getService() {
        return this.service;
    }
}