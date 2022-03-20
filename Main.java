package com.aliuken.pki;

import com.aliuken.pki.model.CertificateData;
import com.aliuken.pki.service.KeyStoreService;
import com.aliuken.pki.service.PdfSignatureService;
import com.aliuken.pki.service.SignatureService;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        KeyStoreService keyStoreService = new KeyStoreService();
        List<CertificateData> certificateDataList = keyStoreService.getCertificateDataListFromWindowsKeyStore();
        if(certificateDataList != null && !certificateDataList.isEmpty()) {
            CertificateData dertificateData = certificateDataList.get(0);
            SignatureService signatureService = new PdfSignatureService();
            signatureService.sign(dertificateData);
        }
    }
}
