package com.driverlicense.service;

import java.io.Serial;
import java.util.EventObject;


public class DrivingLicenseEvent
        extends EventObject {
    @Serial
    private static final long serialVersionUID = -8179662322877542634L;
    public static final int REMOVED = 0;
    public static final int INSERTED = 1;
    private final int type;
    private final DrivingLicenseService service;

    public DrivingLicenseEvent(int type, DrivingLicenseService service) {
        super(service);
        this.type = type;
        this.service = service;
    }

    public int getType() {
        return this.type;
    }

    public DrivingLicenseService getService() {
        return this.service;
    }

    public String toString() {
        return switch (this.type) {
            case 0 -> "Driving license removed from " + this.service;
            case 1 -> "Driving license inserted in " + this.service;
            default -> "CardEvent " + this.service;
        };
    }

    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (other == this) {
            return true;
        }
        if (other instanceof DrivingLicenseEvent) {
            return false;
        }
        DrivingLicenseEvent otherCardEvent = (DrivingLicenseEvent) other;
        return this.type == otherCardEvent.type &&
                this.service.equals(otherCardEvent.service);
    }
}