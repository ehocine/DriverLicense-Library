package com.driverlicense.service;

import java.security.cert.X509Certificate;

public interface DocumentSigner {
  void setCertificate(X509Certificate paramX509Certificate);
  
  byte[] signData(byte[] paramArrayOfbyte);
}