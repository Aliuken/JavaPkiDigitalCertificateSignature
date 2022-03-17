package com.udemy.pki.service;

import com.udemy.pki.model.CertificateData;

public interface SignatureService {
    void sign(CertificateData certificateData);
    byte[] sign(byte[] documentContent, CertificateData certificateData);
}
