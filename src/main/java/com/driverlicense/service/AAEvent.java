package com.driverlicense.service;

import java.io.Serial;
import java.security.PublicKey;
import java.util.EventObject;


public class AAEvent
        extends EventObject {
    @Serial
    private static final long serialVersionUID = 7704093568464620557L;
    private final PublicKey pubkey;
    private final byte[] m1;
    private final byte[] m2;
    private final boolean success;

    public AAEvent(Object src, PublicKey pubkey, byte[] m1, byte[] m2, boolean success) {
                super(src);
                this.pubkey = pubkey;
                this.m1 = m1;
                this.m2 = m2;
                this.success = success;
    }


    public PublicKey getPubkey() {
                return this.pubkey;
    }


    public byte[] getM1() {
                return this.m1;
    }


    public byte[] getM2() {
                return this.m2;
    }


    public boolean isSuccess() {
                return this.success;
    }
}