package com.aliuken.pki.service;

import com.aliuken.pki.model.CertificateData;

public interface SignatureService {
    boolean sign(CertificateData certificateData, String originFile, String destinationFile) throws Exception;
}
