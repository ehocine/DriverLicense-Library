package com.driverlicense.service;


import net.sf.scuba.smartcards.CardTerminalListener;

public interface DrivingLicenseListener extends CardTerminalListener {
    void licenseInserted(DrivingLicenseEvent paramDrivingLicenseEvent);

    void licenseRemoved(DrivingLicenseEvent paramDrivingLicenseEvent);
}