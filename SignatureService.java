package com.aliuken.pki.service;

import com.aliuken.pki.model.CertificateData;

public interface SignatureService {
    void sign(CertificateData certificateData);
    byte[] sign(byte[] documentContent, CertificateData certificateData);
}
