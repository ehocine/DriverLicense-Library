package com.driverlicense.service;

public interface AuthListener {
  void performedBAP(BAPEvent paramBAPEvent);
  
  void performedAA(AAEvent paramAAEvent);
  
  void performedEAP(EAPEvent paramEAPEvent);
}